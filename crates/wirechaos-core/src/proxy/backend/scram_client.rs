use crate::proxy::auth::verifier::{hmac_sha256, pbkdf2_sha256, sha256};
use crate::proxy::backend::error::PgError;
use base64::Engine;
use rand::RngCore;
use std::collections::HashMap;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// The SCRAM mechanism the proxy uses toward the backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScramMechanism {
    Sha256,
    Sha256Plus,
}

impl ScramMechanism {
    fn gs2_header(self) -> &'static str {
        match self {
            Self::Sha256 => "n,,",
            Self::Sha256Plus => "p=tls-server-end-point,,",
        }
    }
}

/// The client half of a SCRAM-SHA-256(-PLUS) exchange with PostgreSQL.
///
/// Two credential shapes are supported:
///
/// * **plaintext password** — every key is derived from the backend's salt, so
///   the proxy can answer any iteration count/salt the backend chooses;
/// * **SCRAM secret + captured `ClientKey`** — the salt-bound keys from the
///   frontend exchange are reused. This only works when the backend's salt and
///   iteration count match, and a mismatch is reported as
///   [`PgError::SaltMismatch`] *before* a wrong proof can be sent.
pub struct ScramClient {
    client_nonce: String,
    auth_message: String,
    client_key: Option<Zeroizing<Vec<u8>>>,
    server_key: Option<Zeroizing<Vec<u8>>>,
    stored_key: Option<Zeroizing<Vec<u8>>>,
    password: Option<Zeroizing<Vec<u8>>>,
    mechanism: ScramMechanism,
    /// Raw `cbind-input` (GS2 header ‖ certificate hash), present only for
    /// `-PLUS`.
    channel_binding: Option<Vec<u8>>,
}

impl ScramClient {
    pub fn new(
        client_key: Option<Vec<u8>>,
        server_key: Option<Vec<u8>>,
        stored_key: Option<Vec<u8>>,
        password: Option<Vec<u8>>,
    ) -> Self {
        let mut rng = rand::thread_rng();
        let mut bytes = [0u8; 18];
        rng.fill_bytes(&mut bytes);

        let client_nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);

        Self {
            client_nonce,
            auth_message: String::new(),
            client_key: client_key.map(Zeroizing::new),
            server_key: server_key.map(Zeroizing::new),
            stored_key: stored_key.map(Zeroizing::new),
            password: password.map(Zeroizing::new),
            mechanism: ScramMechanism::Sha256,
            channel_binding: None,
        }
    }

    /// Select `SCRAM-SHA-256-PLUS` and bind the proof to the backend
    /// certificate. `cbind_input` is the raw GS2-header ‖ digest value.
    pub fn use_channel_binding(&mut self, cbind_input: Vec<u8>) {
        self.mechanism = ScramMechanism::Sha256Plus;
        self.channel_binding = Some(cbind_input);
    }

    #[cfg(test)]
    #[must_use]
    pub fn mechanism(&self) -> ScramMechanism {
        self.mechanism
    }

    pub fn client_first_message(&self) -> String {
        format!("{}n=,r={}", self.mechanism.gs2_header(), self.client_nonce)
    }

    pub fn client_final_message(
        &mut self,
        server_first: &str,
        stored_salt: &[u8],
        stored_iteration_count: u32,
    ) -> Result<String, PgError> {
        let params = parse_scram_kv(server_first);

        let combined_nonce = params
            .get(&'r')
            .ok_or_else(|| PgError::Auth("Missing nonce ('r') in SCRAM response".into()))?;

        let salt_b64 = params
            .get(&'s')
            .ok_or_else(|| PgError::Auth("Missing salt ('s') in SCRAM response".into()))?;

        let iterations: u32 = params
            .get(&'i')
            .ok_or_else(|| PgError::Auth("Missing iterations ('i') in SCRAM response".into()))?
            .parse()
            .map_err(|_| PgError::Auth("invalid iterations count".into()))?;

        if !combined_nonce.starts_with(&self.client_nonce)
            || combined_nonce.len() <= self.client_nonce.len()
        {
            return Err(PgError::Auth("Server nonce mismatch".into()));
        }

        let salt = base64::engine::general_purpose::STANDARD
            .decode(salt_b64)
            .map_err(|_| PgError::Auth("invalid salt encoding".into()))?;

        // A plaintext credential can derive the backend's keys for any salt.
        // A captured ClientKey cannot: it is bound to the frontend exchange's
        // salt, so a different salt is an explicit, operator-actionable error.
        let (client_key, stored_key, server_key) = match &self.password {
            Some(password) => {
                let salted = pbkdf2_sha256(password, &salt, iterations);
                let client_key = hmac_sha256(&salted, b"Client Key");
                let server_key = hmac_sha256(&salted, b"Server Key");
                let stored_key = sha256(&client_key);

                (
                    client_key.to_vec(),
                    stored_key.to_vec(),
                    Some(server_key.to_vec()),
                )
            }
            None => {
                if salt != stored_salt {
                    return Err(PgError::SaltMismatch);
                }

                if stored_iteration_count != iterations {
                    return Err(PgError::Auth("Invalid iteration count".into()));
                }

                let client_key = self
                    .client_key
                    .as_ref()
                    .map(|key| key.to_vec())
                    .ok_or_else(|| {
                        PgError::UnsupportedAuth(
                            "backend requested SCRAM, but no ClientKey was captured from the client"
                                .into(),
                        )
                    })?;
                let stored_key = self
                    .stored_key
                    .as_ref()
                    .map(|key| key.to_vec())
                    .ok_or_else(|| PgError::Auth("stored SCRAM secret is unavailable".into()))?;

                (
                    client_key,
                    stored_key,
                    self.server_key.as_ref().map(|key| key.to_vec()),
                )
            }
        };

        let client_final_without_proof = format!(
            "c={},r={}",
            base64::engine::general_purpose::STANDARD.encode(self.cbind_input()),
            combined_nonce
        );
        let client_first_bare = format!("n=,r={}", self.client_nonce);
        self.auth_message = format!(
            "{},{},{}",
            client_first_bare, server_first, client_final_without_proof
        );

        let client_signature = hmac_sha256(&stored_key, self.auth_message.as_bytes());

        if client_key.len() != client_signature.len() {
            return Err(PgError::Auth("invalid client key length".into()));
        }

        let client_proof: Vec<u8> = client_key
            .iter()
            .zip(client_signature.iter())
            .map(|(a, b)| a ^ b)
            .collect();

        self.server_key = server_key.map(Zeroizing::new);

        let proof_b64 = base64::engine::general_purpose::STANDARD.encode(&client_proof);
        Ok(format!("{},p={}", client_final_without_proof, proof_b64))
    }

    /// Verify the backend's `v=` signature.
    ///
    /// `Ok(false)` means no `ServerKey` was available, so the session must
    /// record `server_signature_verified = false` and log a warning. A present
    /// but wrong signature is an error.
    pub fn verify_server_final(&self, server_final: &str) -> Result<bool, PgError> {
        let params = parse_scram_kv(server_final);

        if let Some(err) = params.get(&'e') {
            return Err(PgError::Auth(format!("SCRAM error: {}", err)));
        }

        let Some(server_key) = self.server_key.as_ref() else {
            return Ok(false);
        };
        let server_key: &[u8] = server_key;

        let server_sig_b64 = params
            .get(&'v')
            .ok_or_else(|| PgError::Auth("invalid server signature".into()))?;

        let server_signature = base64::engine::general_purpose::STANDARD
            .decode(server_sig_b64)
            .map_err(|_| PgError::Auth("invalid server signature".into()))?;

        let expected_server_sig = hmac_sha256(server_key, self.auth_message.as_bytes());

        if expected_server_sig
            .as_slice()
            .ct_eq(server_signature.as_slice())
            .unwrap_u8()
            != 1
        {
            return Err(PgError::Auth("invalid server signature".into()));
        }

        Ok(true)
    }

    fn cbind_input(&self) -> Vec<u8> {
        self.channel_binding
            .clone()
            .unwrap_or_else(|| self.mechanism.gs2_header().as_bytes().to_vec())
    }
}

fn parse_scram_kv(msg: &str) -> HashMap<char, &str> {
    msg.split(',')
        .filter_map(|pair| {
            let mut parts = pair.splitn(2, '=');
            let key = parts.next()?.chars().next()?;
            let value = parts.next()?;
            Some((key, value))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::auth::verifier::{pbkdf2_sha256, sha256};
    use base64::engine::general_purpose::STANDARD as B64;

    const PASSWORD: &[u8] = b"pencil";
    const SALT: &[u8] = &[
        0x5b, 0x6d, 0x99, 0x68, 0x9d, 0x12, 0x35, 0x8e, 0xec, 0xa0, 0x4b, 0x14, 0x12, 0x36, 0xfa,
        0x81,
    ];
    const ITERATIONS: u32 = 4096;
    const CLIENT_NONCE: &str = "rOprNGfwEbeRWgbNEkqO";
    const SERVER_NONCE_SUFFIX: &str = "%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0";

    fn keys(password: &[u8], salt: &[u8], iterations: u32) -> ([u8; 32], [u8; 32], [u8; 32]) {
        let salted = pbkdf2_sha256(password, salt, iterations);
        let client_key = hmac_sha256(&salted, b"Client Key");
        let server_key = hmac_sha256(&salted, b"Server Key");
        let stored_key = sha256(&client_key);
        (client_key, server_key, stored_key)
    }

    fn secret_client_with_nonce(salt: &[u8], iterations: u32, nonce: &str) -> ScramClient {
        let (client_key, server_key, stored_key) = keys(PASSWORD, salt, iterations);
        let mut client = ScramClient::new(
            Some(client_key.to_vec()),
            Some(server_key.to_vec()),
            Some(stored_key.to_vec()),
            None,
        );
        client.client_nonce = nonce.to_owned();
        client
    }

    fn password_client_with_nonce(password: &[u8], nonce: &str) -> ScramClient {
        let mut client = ScramClient::new(None, None, None, Some(password.to_vec()));
        client.client_nonce = nonce.to_owned();
        client
    }

    fn salt_b64() -> String {
        B64.encode(SALT)
    }

    fn server_first(client_nonce: &str, salt_b64: &str, iterations: u32) -> String {
        format!("r={client_nonce}{SERVER_NONCE_SUFFIX},s={salt_b64},i={iterations}")
    }

    fn expected_client_final(
        client_nonce: &str,
        server_first: &str,
        client_key: &[u8],
        stored_key: &[u8],
        gs2_header: &str,
    ) -> String {
        let combined_nonce = format!("{client_nonce}{SERVER_NONCE_SUFFIX}");
        let client_final_without_proof =
            format!("c={},r={combined_nonce}", B64.encode(gs2_header.as_bytes()));
        let auth_message =
            format!("n=,r={client_nonce},{server_first},{client_final_without_proof}");

        let client_signature = hmac_sha256(stored_key, auth_message.as_bytes());
        let proof: Vec<u8> = client_key
            .iter()
            .zip(client_signature.iter())
            .map(|(a, b)| a ^ b)
            .collect();

        format!("{client_final_without_proof},p={}", B64.encode(&proof))
    }

    #[test]
    fn client_first_has_gs2_header_and_a_fresh_nonce() {
        let first = ScramClient::new(None, None, None, Some(PASSWORD.to_vec()));
        let second = ScramClient::new(None, None, None, Some(PASSWORD.to_vec()));

        assert!(first.client_first_message().starts_with("n,,n=,r="));
        assert!(!first.client_nonce.is_empty());
        assert_ne!(first.client_nonce, second.client_nonce);
        assert!(
            first
                .client_nonce
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "the nonce must be URL-safe base64 without padding"
        );
    }

    #[test]
    fn client_final_matches_an_independent_computation() {
        let (client_key, server_key, stored_key) = keys(PASSWORD, SALT, ITERATIONS);
        let mut client = secret_client_with_nonce(SALT, ITERATIONS, CLIENT_NONCE);
        let server_first = server_first(CLIENT_NONCE, &salt_b64(), ITERATIONS);

        let actual = client
            .client_final_message(&server_first, SALT, ITERATIONS)
            .expect("valid server-first must produce a client-final");

        assert_eq!(
            actual,
            expected_client_final(CLIENT_NONCE, &server_first, &client_key, &stored_key, "n,,")
        );

        let combined_nonce = format!("{CLIENT_NONCE}{SERVER_NONCE_SUFFIX}");
        let auth_message = format!("n=,r={CLIENT_NONCE},{server_first},c=biws,r={combined_nonce}");
        let server_signature = hmac_sha256(&server_key, auth_message.as_bytes());

        assert!(client
            .verify_server_final(&format!("v={}", B64.encode(server_signature)))
            .expect("signature check"));
    }

    #[test]
    fn a_plaintext_password_derives_keys_for_the_backends_salt() {
        let other_salt = [0x99u8; 16];
        let mut client = password_client_with_nonce(PASSWORD, CLIENT_NONCE);
        let server_first = server_first(CLIENT_NONCE, &B64.encode(other_salt), ITERATIONS);

        let actual = client
            .client_final_message(&server_first, SALT, ITERATIONS)
            .expect("a password can derive the backend's keys");

        let (client_key, _, stored_key) = keys(PASSWORD, &other_salt, ITERATIONS);
        assert_eq!(
            actual,
            expected_client_final(CLIENT_NONCE, &server_first, &client_key, &stored_key, "n,,",)
        );
    }

    #[test]
    fn rejects_a_salt_that_differs_from_the_stored_verifier() {
        let mut client = secret_client_with_nonce(SALT, ITERATIONS, CLIENT_NONCE);
        let server_first = server_first(CLIENT_NONCE, &salt_b64(), ITERATIONS);

        let result = client.client_final_message(&server_first, b"a-different-salt", ITERATIONS);

        assert!(matches!(result, Err(PgError::SaltMismatch)));
    }

    #[test]
    fn rejects_an_iteration_count_that_differs_from_the_stored_verifier() {
        let mut client = secret_client_with_nonce(SALT, ITERATIONS, CLIENT_NONCE);
        let server_first = server_first(CLIENT_NONCE, &salt_b64(), ITERATIONS + 1);

        let result = client.client_final_message(&server_first, SALT, ITERATIONS);

        assert!(
            matches!(result, Err(PgError::Auth(message)) if message == "Invalid iteration count")
        );
    }

    #[test]
    fn rejects_a_server_nonce_that_does_not_extend_the_client_nonce() {
        let mut client = secret_client_with_nonce(SALT, ITERATIONS, CLIENT_NONCE);
        let server_first = format!("r=an-attacker-chosen-nonce,s={},i={ITERATIONS}", salt_b64());

        let result = client.client_final_message(&server_first, SALT, ITERATIONS);

        assert!(
            matches!(result, Err(PgError::Auth(message)) if message == "Server nonce mismatch")
        );
    }

    #[test]
    fn rejects_a_server_nonce_that_is_exactly_the_client_nonce() {
        let mut client = secret_client_with_nonce(SALT, ITERATIONS, CLIENT_NONCE);
        let server_first = format!("r={CLIENT_NONCE},s={},i={ITERATIONS}", salt_b64());

        let result = client.client_final_message(&server_first, SALT, ITERATIONS);

        assert!(
            matches!(result, Err(PgError::Auth(message)) if message == "Server nonce mismatch")
        );
    }

    #[test]
    fn rejects_missing_or_invalid_server_first_attributes() {
        let base = server_first(CLIENT_NONCE, &salt_b64(), ITERATIONS);

        let without_nonce = base
            .split(',')
            .filter(|pair| !pair.starts_with("r="))
            .collect::<Vec<_>>()
            .join(",");
        let without_salt = base
            .split(',')
            .filter(|pair| !pair.starts_with("s="))
            .collect::<Vec<_>>()
            .join(",");
        let without_iterations = base
            .split(',')
            .filter(|pair| !pair.starts_with("i="))
            .collect::<Vec<_>>()
            .join(",");
        let invalid_iterations = base.replace("i=4096", "i=not-a-number");
        let invalid_salt = base.replace(&salt_b64(), "!!!");

        for message in [
            without_nonce,
            without_salt,
            without_iterations,
            invalid_iterations,
            invalid_salt,
        ] {
            let mut client = secret_client_with_nonce(SALT, ITERATIONS, CLIENT_NONCE);
            assert!(
                client
                    .client_final_message(&message, SALT, ITERATIONS)
                    .is_err(),
                "malformed server-first must be rejected: {message}"
            );
        }
    }

    #[test]
    fn channel_binding_uses_the_tls_server_end_point_gs2_header() {
        let cbind = {
            let mut value = b"p=tls-server-end-point,,".to_vec();
            value.extend_from_slice(&[0x33u8; 32]);
            value
        };
        let mut client = password_client_with_nonce(PASSWORD, CLIENT_NONCE);
        client.use_channel_binding(cbind.clone());

        assert_eq!(client.mechanism(), ScramMechanism::Sha256Plus);
        assert!(client
            .client_first_message()
            .starts_with("p=tls-server-end-point,,n=,r="));

        let server_first = server_first(CLIENT_NONCE, &salt_b64(), ITERATIONS);
        let final_message = client
            .client_final_message(&server_first, SALT, ITERATIONS)
            .expect("plus proof");

        assert!(
            final_message.starts_with(&format!("c={},r=", B64.encode(&cbind))),
            "the c= value must bind the backend certificate: {final_message}"
        );
    }

    #[test]
    fn verify_server_final_reports_when_no_server_key_is_available() {
        let mut client = ScramClient::new(None, None, None, Some(PASSWORD.to_vec()));
        let server_first = server_first(&client.client_nonce.clone(), &salt_b64(), ITERATIONS);
        client
            .client_final_message(&server_first, SALT, ITERATIONS)
            .expect("password-derived keys always include a ServerKey");

        let mut without_key = ScramClient::new(None, None, None, None);
        without_key.client_nonce = CLIENT_NONCE.to_owned();
        assert!(!without_key.verify_server_final("v=AAAA").expect("no key"));
    }

    #[test]
    fn verify_server_final_rejects_a_bad_signature_or_an_error_message() {
        let mut client = secret_client_with_nonce(SALT, ITERATIONS, CLIENT_NONCE);
        let server_first = server_first(CLIENT_NONCE, &salt_b64(), ITERATIONS);
        client
            .client_final_message(&server_first, SALT, ITERATIONS)
            .expect("client-final");

        assert!(matches!(
            client.verify_server_final(&format!("v={}", B64.encode([0u8; 32]))),
            Err(PgError::Auth(message)) if message == "invalid server signature"
        ));
        assert!(matches!(
            client.verify_server_final("v=not-base64!"),
            Err(PgError::Auth(message)) if message == "invalid server signature"
        ));
        assert!(matches!(
            client.verify_server_final("nope"),
            Err(PgError::Auth(message)) if message == "invalid server signature"
        ));
        assert!(matches!(
            client.verify_server_final("e=other-error"),
            Err(PgError::Auth(message)) if message == "SCRAM error: other-error"
        ));
    }
}
