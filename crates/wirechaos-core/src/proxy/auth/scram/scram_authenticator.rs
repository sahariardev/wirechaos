use crate::proxy::auth::scram::error::ScramError;
use crate::proxy::auth::verifier::{hmac_sha256, sha256, Verifier};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand::RngCore;
use subtle::ConstantTimeEq;

#[derive(Debug, PartialEq)]
enum State {
    Started,
    ClientFirstReceived,
    Done,
}

/// The message every malformed SCRAM message is rejected with.
///
/// Security: the text is deliberately uniform and says nothing about which
/// attribute was missing, which check failed, or how far the parser got.
/// Naming the failing check would let a probe map the parser just by reading
/// the error text it gets back, so the client only ever learns that its message
/// was rejected. The one message allowed to say more is the authentication
/// failure in `handle_client_final`, which must read the same for every bad
/// credential.
fn malformed() -> ScramError {
    ScramError::Protocol("malformed SCRAM message".to_string())
}

pub const SCRAM_SHA_256: &str = "SCRAM-SHA-256";
pub const SERVER_NONCE_LENGTH: usize = 32;
pub struct ScramAuthenticator<'a> {
    verifier: &'a Verifier,
    state: State,
    client_nonce: String,
    combined_nonce: String,
    client_first_bare: String,
    server_first: String,
    gs2_header: String,
    extracted_client_key: Option<Vec<u8>>,
}

impl<'a> ScramAuthenticator<'a> {
    pub fn new(verifier: &'a Verifier) -> Self {
        ScramAuthenticator {
            verifier,
            state: State::Started,
            client_nonce: String::new(),
            combined_nonce: String::new(),
            client_first_bare: String::new(),
            server_first: String::new(),
            gs2_header: String::new(),
            extracted_client_key: None,
        }
    }

    pub fn mechanisms(&self) -> Vec<&'static str> {
        vec![SCRAM_SHA_256]
    }

    pub fn handle_client_first(
        &mut self,
        mechanism: &str,
        client_first: &str,
        startup_user: &str,
    ) -> Result<String, ScramError> {
        self.validate_params(mechanism, startup_user)?;

        let (flag, authzid_part, bare) = self.extract_data_from_client_first(client_first)?;

        self.validate_gs2_flag(flag)?;
        self.validate_authzid_part(authzid_part)?;

        self.gs2_header = format!("{flag},{authzid_part},");

        let mut client_nonce = String::new();

        for attr in bare.split(',') {
            if let Some(v) = attr.strip_prefix("r=") {
                client_nonce = v.to_string();
            }
        }

        if client_nonce.is_empty() {
            return Err(malformed());
        }

        let mut server_nonce_bytes = [0u8; SERVER_NONCE_LENGTH];
        rand::thread_rng().fill_bytes(&mut server_nonce_bytes);
        let server_nonce = B64.encode(server_nonce_bytes);

        self.client_nonce = client_nonce.clone();
        self.combined_nonce = format!("{client_nonce}-{server_nonce}");
        self.client_first_bare = bare.to_string();

        let server_first = format!(
            "r={},s={},i={}",
            self.combined_nonce,
            B64.encode(&self.verifier.salt),
            self.verifier.iterations
        );

        self.server_first = server_first.clone();
        self.state = State::ClientFirstReceived;
        Ok(server_first)
    }

    pub fn handle_client_final(
        &mut self,
        client_final: &str,
        user: &str,
    ) -> Result<String, ScramError> {
        if self.state != State::ClientFirstReceived {
            return Err(malformed());
        }

        self.state = State::Done;

        let (mut cbind, mut nonce, mut proof_b64) = (None, None, None);

        for attr in client_final.split(',') {
            if let Some(v) = attr.strip_prefix("c=") {
                if cbind.is_some() {
                    return Err(malformed());
                }
                cbind = Some(v);
            }

            if let Some(v) = attr.strip_prefix("r=") {
                if nonce.is_some() {
                    return Err(malformed());
                }
                nonce = Some(v);
            }

            if let Some(v) = attr.strip_prefix("p=") {
                if proof_b64.is_some() {
                    return Err(malformed());
                }
                proof_b64 = Some(v);
            }
        }

        let cbind = cbind.ok_or_else(malformed)?;
        let nonce = nonce.ok_or_else(malformed)?;
        let proof_b64 = proof_b64.ok_or_else(malformed)?;

        let expected_cbind = B64.encode(self.gs2_header.as_bytes());

        if cbind
            .as_bytes()
            .ct_eq(expected_cbind.as_bytes())
            .unwrap_u8()
            != 1
        {
            return Err(malformed());
        }

        if nonce != self.combined_nonce {
            return Err(malformed());
        }

        if !nonce.starts_with(&self.client_nonce) {
            return Err(malformed());
        }

        // The proof is the last attribute of the message (RFC 5802), so the
        // auth message is everything before it. A client-final that puts the
        // proof anywhere else is malformed, not a reason to panic.
        let proof_start = client_final.rfind(",p=").ok_or_else(malformed)?;

        let without_proof = &client_final[..proof_start];
        let auth_message = format!(
            "{},{},{}",
            self.client_first_bare, self.server_first, without_proof
        );

        let proof = B64.decode(proof_b64).map_err(|_| malformed())?;

        if proof.len() != 32 {
            return Err(malformed());
        }

        let client_sig = hmac_sha256(&self.verifier.stored_key, auth_message.as_bytes());
        let recovered_client_key: Vec<u8> = proof
            .iter()
            .zip(client_sig.iter())
            .map(|(a, b)| a ^ b)
            .collect();

        let recovered_stored_key = sha256(&recovered_client_key);

        if recovered_stored_key
            .ct_eq(&self.verifier.stored_key[..])
            .unwrap_u8()
            != 1
        {
            return Err(ScramError::AuthenticationFailed(format!(
                "password authentication failed for user {}",
                user
            )));
        }

        // if user does not exist we continue the scram auth with dummy verifier
        // to make sure to execute all the hashing so that it prevents attacker to
        // identify user does not exist, once all kind of hasing operation done we are sending
        // auth failed
        if self.verifier.dummy {
            return Err(ScramError::AuthenticationFailed(format!(
                "password authentication failed for user {}",
                user
            )));
        }

        self.extracted_client_key = Some(recovered_client_key);

        let server_sig = hmac_sha256(&self.verifier.server_key, auth_message.as_bytes());
        Ok(format!("v={}", B64.encode(server_sig)))
    }

    pub fn extracted_client_key(&self) -> Option<Vec<u8>> {
        self.extracted_client_key.clone()
    }

    fn validate_authzid_part(&self, authzid_part: &str) -> Result<(), ScramError> {
        if authzid_part.starts_with("a=") && authzid_part.len() > 2 {
            return Err(ScramError::Protocol(
                "client uses authorization identity, but it is not supported ".into(),
            ));
        } else if !authzid_part.is_empty() && !authzid_part.starts_with("a=") {
            return Err(malformed());
        }

        Ok(())
    }

    fn validate_params(&self, mechanism: &str, startup_user: &str) -> Result<(), ScramError> {
        if self.state != State::Started {
            return Err(malformed());
        }

        if startup_user.is_empty() {
            return Err(ScramError::Protocol(
                "startup user must not be empty".into(),
            ));
        }

        if mechanism != SCRAM_SHA_256 {
            return Err(ScramError::Protocol(format!(
                "unsupported SASL mechanism: {}",
                mechanism
            )));
        }

        Ok(())
    }
    fn extract_data_from_client_first<'b>(
        &self,
        client_first: &'b str,
    ) -> Result<(&'b str, &'b str, &'b str), ScramError> {
        let parts: Vec<&str> = client_first.splitn(3, ',').collect();

        if parts.len() < 3 {
            return Err(malformed());
        }

        Ok((parts[0], parts[1], parts[2]))
    }
    fn validate_gs2_flag(&self, flag: &str) -> Result<(), ScramError> {
        match flag {
            "n" | "y" => {}
            _ if flag.starts_with("p=") => {
                return Err(ScramError::Protocol(
                    "client requested channel binding, but SCRAM-SHA-256 was not offered".into(),
                ))
            }

            _ => return Err(malformed()),
        };

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::auth::verifier::{hmac_sha256, pbkdf2_sha256, sha256, Verifier};
    use base64::{engine::general_purpose::STANDARD as B64, Engine};

    const USER: &str = "user";
    const CLIENT_NONCE: &str = "fyko+d2lbbTB1mTN";

    /// Build a Verifier with a fixed, deterministic salt so the server-first
    /// message is reconstructable in assertions.
    fn verifier() -> Verifier {
        Verifier::from_password("pencil", vec![0u8; 16], 4096)
    }

    /// Unwrap a successful result, formatting the error via `Display`
    /// (`ScramError` implements `Display` but not `Debug`, so `.expect` won't compile).
    fn expect_ok<T, E: std::fmt::Display>(result: Result<T, E>) -> T {
        match result {
            Ok(value) => value,
            Err(error) => panic!("expected Ok, got {error}"),
        }
    }

    /// The client-visible text for a rejected SCRAM message. Written out as a
    /// literal on purpose: this is the wire contract, so the test must fail if
    /// the message ever starts describing the failure instead of merely naming
    /// it.
    const OPAQUE: &str = "malformed SCRAM message";

    /// Pull the message out of a Protocol error, panicking otherwise.
    fn protocol_err(result: Result<String, ScramError>) -> String {
        match result {
            Err(ScramError::Protocol(message)) => message,
            Err(ScramError::AuthenticationFailed(_)) => {
                panic!("expected Protocol error, got AuthenticationFailed")
            }
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    /// Assert that the client's message was rejected as malformed.
    ///
    /// Every malformed SCRAM message answers with the same opaque text, so a
    /// test can only pin that the input *is* rejected — which is the point: the
    /// text must never tell a prober which check it reached. The input differs
    /// from test to test; the answer may not. The few messages that are still
    /// specific (an unoffered mechanism, an unsupported authorization identity,
    /// channel binding the server never offered, an empty startup user) say
    /// what the client asked for, not how far its parser input got, and keep
    /// their own assertions.
    fn assert_malformed(result: Result<String, ScramError>) {
        assert_eq!(protocol_err(result), OPAQUE);
    }

    /// Parse the `r=...` combined nonce out of a server-first message.
    fn combined_nonce_of(server_first: &str) -> String {
        server_first
            .split(',')
            .next()
            .expect("server-first must carry an r= attribute")
            .strip_prefix("r=")
            .expect("server-first must begin with r=")
            .to_string()
    }

    /// Run the server to the point where it has issued server-first and is
    /// waiting for client-final. `verifier()` must be built from "pencil".
    fn begin_exchange(auth: &mut ScramAuthenticator<'_>) -> String {
        let client_first = format!("n,,n={USER},r={CLIENT_NONCE}");
        expect_ok(auth.handle_client_first(SCRAM_SHA_256, &client_first, USER))
    }

    /// Play the SCRAM client role for `password`: compute a genuine proof from
    /// the server-first message and return (client-final, expected server-final).
    ///
    /// Everything here is derived independently from the password + the public
    /// server-first attributes (RFC 5802), so it exercises the server against a
    /// faithful client rather than against code that shares its bugs.
    fn simulate_client(
        password: &str,
        client_first_bare: &str,
        server_first: &str,
        gs2_header: &str,
    ) -> (String, String) {
        let mut combined = "";
        let mut salt_b64 = "";
        let mut iterations = 0u32;
        for attr in server_first.split(',') {
            if let Some(v) = attr.strip_prefix("r=") {
                combined = v;
            } else if let Some(v) = attr.strip_prefix("s=") {
                salt_b64 = v;
            } else if let Some(v) = attr.strip_prefix("i=") {
                iterations = v.parse().expect("server-first iterations must be a number");
            }
        }

        let cbind = B64.encode(gs2_header.as_bytes());
        let client_final_no_proof = format!("c={cbind},r={combined}");
        let auth_message = format!("{client_first_bare},{server_first},{client_final_no_proof}");

        let salt = B64
            .decode(salt_b64)
            .expect("server-first salt must be base64");
        let salted = pbkdf2_sha256(password.as_bytes(), &salt, iterations);

        let client_key = hmac_sha256(&salted, b"Client Key");
        let stored_key = sha256(&client_key);
        let client_sig = hmac_sha256(&stored_key, auth_message.as_bytes());
        let proof: Vec<u8> = client_key
            .iter()
            .zip(client_sig.iter())
            .map(|(a, b)| a ^ b)
            .collect();

        // The client independently checks the server's signature against
        // ServerKey = HMAC(SaltedPassword, "Server Key"), not StoredKey.
        let server_key = hmac_sha256(&salted, b"Server Key");
        let expected_server_final = format!(
            "v={}",
            B64.encode(hmac_sha256(&server_key, auth_message.as_bytes()))
        );

        let client_final = format!("c={cbind},r={combined},p={}", B64.encode(proof));
        (client_final, expected_server_final)
    }

    /// Drive a full exchange (server + simulated client) to completion.
    /// Returns (server-final actually returned, server-final the client expects).
    fn full_client_exchange(
        auth: &mut ScramAuthenticator<'_>,
        password: &str,
        gs2_header: &str,
        client_nonce: &str,
    ) -> (String, String) {
        let flag = &gs2_header[..1];
        let client_first = format!("{flag},,n={USER},r={client_nonce}");
        let server_first = expect_ok(auth.handle_client_first(SCRAM_SHA_256, &client_first, USER));
        let client_first_bare = format!("n={USER},r={client_nonce}");

        let (client_final, expected_server_final) =
            simulate_client(password, &client_first_bare, &server_first, gs2_header);
        let server_final = expect_ok(auth.handle_client_final(&client_final, ""));
        (server_final, expected_server_final)
    }

    #[test]
    fn mechanisms_offers_sha_256() {
        let v = verifier();
        let auth = ScramAuthenticator::new(&v);
        assert_eq!(auth.mechanisms(), vec![SCRAM_SHA_256]);
    }

    /// The worked example from RFC 7677, section 3: password "pencil", salt
    /// "W22ZaJ0SNY7soEsUEjb6gQ==", 4096 iterations, and the exact messages the
    /// RFC prints.
    ///
    /// This checks the primitives against a published vector instead of the
    /// crate agreeing with itself: key derivation, the ClientProof check and
    /// the ServerSignature must all land on the RFC's bytes.
    #[test]
    fn ok_rfc7677_vector_derives_the_published_proof_and_signature() {
        const RFC_PASSWORD: &str = "pencil";
        const RFC_SALT_B64: &str = "W22ZaJ0SNY7soEsUEjb6gQ==";
        const RFC_ITERATIONS: u32 = 4096;
        const RFC_CLIENT_FIRST_BARE: &str = "n=user,r=rOprNGfwEbeRWgbNEkqO";
        const RFC_SERVER_FIRST: &str = "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,\
                                        s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
        const RFC_CLIENT_FINAL_WITHOUT_PROOF: &str =
            "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0";
        const RFC_PROOF_B64: &str = "dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=";
        const RFC_SERVER_FINAL: &str = "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=";

        let salt = B64.decode(RFC_SALT_B64).expect("RFC salt is base64");
        let verifier = Verifier::from_password(RFC_PASSWORD, salt.clone(), RFC_ITERATIONS);

        // SaltedPassword = PBKDF2-HMAC-SHA256, then the two derived keys.
        let salted = pbkdf2_sha256(RFC_PASSWORD.as_bytes(), &salt, RFC_ITERATIONS);
        let client_key = hmac_sha256(&salted, b"Client Key");
        assert_eq!(verifier.stored_key, sha256(&client_key).to_vec());
        assert_eq!(
            verifier.server_key,
            hmac_sha256(&salted, b"Server Key").to_vec()
        );

        // AuthMessage = client-first-bare + server-first + client-final-without-proof.
        let auth_message =
            format!("{RFC_CLIENT_FIRST_BARE},{RFC_SERVER_FIRST},{RFC_CLIENT_FINAL_WITHOUT_PROOF}");

        // The published proof XOR ClientSignature must recover ClientKey, which
        // in turn must hash back to StoredKey.
        let client_signature = hmac_sha256(&verifier.stored_key, auth_message.as_bytes());
        let proof = B64.decode(RFC_PROOF_B64).expect("RFC proof is base64");
        let recovered: Vec<u8> = proof
            .iter()
            .zip(client_signature.iter())
            .map(|(a, b)| a ^ b)
            .collect();
        assert_eq!(
            recovered,
            client_key.to_vec(),
            "the RFC's proof must recover ClientKey"
        );
        assert_eq!(
            sha256(&recovered).to_vec(),
            verifier.stored_key,
            "the recovered ClientKey must hash to StoredKey"
        );

        // ServerSignature = HMAC(ServerKey, AuthMessage).
        let server_signature = hmac_sha256(&verifier.server_key, auth_message.as_bytes());
        assert_eq!(
            format!("v={}", B64.encode(server_signature)),
            RFC_SERVER_FINAL
        );
    }

    #[test]
    fn ok_returns_structured_server_first() {
        let v = verifier();
        let mut auth = ScramAuthenticator::new(&v);
        let client_first = format!("n,,n={USER},r={CLIENT_NONCE}");

        let server_first = expect_ok(auth.handle_client_first(SCRAM_SHA_256, &client_first, USER));

        // The client nonce is echoed verbatim, then '-' and a fresh server nonce.
        let prefix = format!("r={CLIENT_NONCE}-");
        assert!(
            server_first.starts_with(&prefix),
            "server-first must echo the client nonce: got {server_first}"
        );

        // 32 random bytes => 44 base64 chars (STANDARD, padded).
        let server_nonce = server_first[prefix.len()..].split(',').next().unwrap();
        assert_eq!(server_nonce.len(), 44, "server nonce must be 32 raw bytes");
        let decoded = B64
            .decode(server_nonce)
            .expect("server nonce must be valid base64");
        assert_eq!(decoded.len(), SERVER_NONCE_LENGTH);

        // salt + iteration count come straight from the verifier.
        let expected = format!(
            "r={}-{},s={},i={}",
            CLIENT_NONCE,
            server_nonce,
            B64.encode(&v.salt),
            v.iterations
        );
        assert_eq!(server_first, expected);
    }

    #[test]
    fn ok_accepts_n_and_y_gs2_flags() {
        for flag in ["n", "y"] {
            let v = verifier();
            let mut auth = ScramAuthenticator::new(&v);
            let client_first = format!("{flag},,n={USER},r={CLIENT_NONCE}");
            let server_first = auth
                .handle_client_first(SCRAM_SHA_256, &client_first, USER)
                .unwrap_or_else(|e| panic!("flag {flag:?} must be accepted, got {e}"));
            assert!(server_first.starts_with(&format!("r={CLIENT_NONCE}-")));
        }
    }

    #[test]
    fn ok_state_advances_and_rejects_replay() {
        let v = verifier();
        let mut auth = ScramAuthenticator::new(&v);
        let client_first = format!("n,,n={USER},r={CLIENT_NONCE}");

        expect_ok(auth.handle_client_first(SCRAM_SHA_256, &client_first, USER));

        // A second client-first is a protocol violation: we've already moved to
        // ClientFirstReceived.
        assert_malformed(auth.handle_client_first(SCRAM_SHA_256, &client_first, USER));
    }

    #[test]
    fn ok_can_retry_after_protocol_error() {
        let v = verifier();
        let mut auth = ScramAuthenticator::new(&v);

        // Parsing failure leaves state untouched (still Started), so a retry works.
        assert_malformed(auth.handle_client_first(SCRAM_SHA_256, "n,", USER));

        let ok = auth.handle_client_first(
            SCRAM_SHA_256,
            &format!("n,,n={USER},r={CLIENT_NONCE}"),
            USER,
        );
        assert!(ok.is_ok(), "retry after an error must succeed");
    }

    #[test]
    fn err_missing_client_nonce() {
        let v = verifier();
        let mut auth = ScramAuthenticator::new(&v);
        // Valid gs2 header, but the bare part carries no r= attribute.
        let client_first = format!("n,,n={USER}");
        assert_malformed(auth.handle_client_first(SCRAM_SHA_256, &client_first, USER));
    }

    #[test]
    fn err_fewer_than_three_comma_parts() {
        let v = verifier();
        let mut auth = ScramAuthenticator::new(&v);
        assert_malformed(auth.handle_client_first(SCRAM_SHA_256, "n,", USER));
    }

    #[test]
    fn err_empty_startup_user() {
        let v = verifier();
        let mut auth = ScramAuthenticator::new(&v);
        let client_first = format!("n,,n={USER},r={CLIENT_NONCE}");
        let err = protocol_err(auth.handle_client_first(SCRAM_SHA_256, &client_first, ""));
        assert_eq!(err, "startup user must not be empty");
    }

    #[test]
    fn err_unsupported_mechanism() {
        let v = verifier();
        let mut auth = ScramAuthenticator::new(&v);
        let client_first = format!("n,,n={USER},r={CLIENT_NONCE}");
        let err = protocol_err(auth.handle_client_first("SCRAM-SHA-256-PLUS", &client_first, USER));
        assert_eq!(err, "unsupported SASL mechanism: SCRAM-SHA-256-PLUS");
    }

    #[test]
    fn err_channel_binding_not_offered() {
        let v = verifier();
        let mut auth = ScramAuthenticator::new(&v);
        let client_first = format!("p=tls-unique,,n={USER},r={CLIENT_NONCE}");
        let err = protocol_err(auth.handle_client_first(SCRAM_SHA_256, &client_first, USER));
        assert_eq!(
            err,
            "client requested channel binding, but SCRAM-SHA-256 was not offered"
        );
    }

    #[test]
    fn err_invalid_gs2_flag() {
        let v = verifier();
        let mut auth = ScramAuthenticator::new(&v);
        let client_first = format!("x,,n={USER},r={CLIENT_NONCE}");
        assert_malformed(auth.handle_client_first(SCRAM_SHA_256, &client_first, USER));
    }

    #[test]
    fn err_authzid_not_supported() {
        let v = verifier();
        let mut auth = ScramAuthenticator::new(&v);
        // Non-empty authorization identity is rejected.
        let client_first = format!("n,a={USER},n={USER},r={CLIENT_NONCE}");
        let err = protocol_err(auth.handle_client_first(SCRAM_SHA_256, &client_first, USER));
        assert!(err.contains("authorization identity"));
    }

    #[test]
    fn err_malformed_authzid() {
        let v = verifier();
        let mut auth = ScramAuthenticator::new(&v);
        // Anything between the gs2 commas that isn't empty and doesn't start with "a=".
        let client_first = format!("n,zz,n={USER},r={CLIENT_NONCE}");
        assert_malformed(auth.handle_client_first(SCRAM_SHA_256, &client_first, USER));
    }

    #[test]
    fn extractor_splits_gs2_header_from_bare() {
        let v = verifier();
        let auth = ScramAuthenticator::new(&v);
        let client_first = format!("n,,n={USER},r={CLIENT_NONCE}");
        let (flag, authzid, bare) = expect_ok(auth.extract_data_from_client_first(&client_first));
        assert_eq!(flag, "n");
        assert_eq!(authzid, "");
        assert_eq!(bare, format!("n={USER},r={CLIENT_NONCE}"));

        let parts = auth.extract_data_from_client_first("n,");
        assert!(parts.is_err(), "two-part message must be rejected");
    }

    #[test]
    fn ok_full_exchange_returns_verifiable_server_signature() {
        let v = verifier();
        let mut auth = ScramAuthenticator::new(&v);

        let (server_final, expected) =
            full_client_exchange(&mut auth, "pencil", "n,,", CLIENT_NONCE);
        assert_eq!(
            server_final, expected,
            "server-final must be HMAC(ServerKey, auth message)"
        );
        assert!(
            server_final.starts_with("v="),
            "server-final must be a v= attribute, got {server_final}"
        );
        assert!(auth.extracted_client_key.is_some());
    }

    #[test]
    fn ok_full_exchange_accepts_y_gs2_flag() {
        let v = verifier();
        let mut auth = ScramAuthenticator::new(&v);

        let (server_final, expected) =
            full_client_exchange(&mut auth, "pencil", "y,,", CLIENT_NONCE);
        assert_eq!(server_final, expected);
    }

    #[test]
    fn ok_state_is_done_after_successful_exchange() {
        let v = verifier();
        let mut auth = ScramAuthenticator::new(&v);
        let (_, _) = full_client_exchange(&mut auth, "pencil", "n,,", CLIENT_NONCE);

        assert_malformed(auth.handle_client_final("c=biws,r=x,p=AAAA", ""));
    }

    #[test]
    fn err_wrong_password_fails_authentication() {
        let v = verifier();
        let mut auth = ScramAuthenticator::new(&v);
        let server_first = begin_exchange(&mut auth);

        let bare = format!("n={USER},r={CLIENT_NONCE}");
        let (client_final, _) = simulate_client("not-pencil", &bare, &server_first, "n,,");

        assert!(
            matches!(
                auth.handle_client_final(&client_final, ""),
                Err(ScramError::AuthenticationFailed(_))
            ),
            "a proof derived from the wrong password must be rejected"
        );
    }

    #[test]
    fn err_proof_attribute_is_not_last() {
        let v = verifier();
        let mut auth = ScramAuthenticator::new(&v);
        let server_first = begin_exchange(&mut auth);
        let nonce = combined_nonce_of(&server_first);

        // A proof in front of the other attributes must be a protocol error
        // rather than an out-of-bounds panic while the auth message is rebuilt.
        let message = format!("p=AAAA,c=biws,r={nonce}");
        assert_malformed(auth.handle_client_final(&message, ""));
    }

    #[test]
    fn err_client_final_out_of_order() {
        let v = verifier();
        let mut auth = ScramAuthenticator::new(&v);
        // handle_client_final before any client-first.
        assert_malformed(auth.handle_client_final("c=biws,r=x,p=AAAA", ""));
    }

    #[test]
    fn err_required_attributes_missing() {
        let v = verifier();

        // One case per required attribute. Which one is absent is never told to
        // the client, so each case only has to show the message is rejected.
        // The checks run before the nonce is validated, so the attribute values
        // here only need to be syntactically parseable.
        let cases = ["r=x,p=AAAA", "c=biws,p=AAAA", "c=biws,r=x"];
        for message in cases {
            let mut auth = ScramAuthenticator::new(&v);
            begin_exchange(&mut auth);
            assert_malformed(auth.handle_client_final(message, ""));
        }
    }

    #[test]
    fn err_duplicate_attributes() {
        let v = verifier();

        // One case per attribute that may appear at most once.
        let cases = [
            "c=biws,c=biws,r=x,p=AAAA",
            "c=biws,r=x,r=y,p=AAAA",
            "c=biws,r=x,p=AAAA,p=BBBB",
        ];
        for message in cases {
            let mut auth = ScramAuthenticator::new(&v);
            begin_exchange(&mut auth);
            assert_malformed(auth.handle_client_final(message, ""));
        }
    }

    #[test]
    fn err_channel_binding_mismatch() {
        let v = verifier();
        let mut auth = ScramAuthenticator::new(&v);
        begin_exchange(&mut auth); // server echoed GS2 header "n,,"

        // cbind is base64 of "y,," ("eSws") instead of the echoed "n,," ("biws").
        let client_final = "c=eSws,r=x,p=AAAA";
        assert_malformed(auth.handle_client_final(client_final, ""));
    }

    #[test]
    fn err_nonce_mismatch() {
        let v = verifier();
        let mut auth = ScramAuthenticator::new(&v);
        let server_first = begin_exchange(&mut auth);
        let combined = combined_nonce_of(&server_first);

        // Drop the last character of the real combined nonce.
        let truncated = format!("c=biws,r={},p=AAAA", &combined[..combined.len() - 1]);
        assert_malformed(auth.handle_client_final(&truncated, ""));

        // A completely different nonce.
        let mut auth = ScramAuthenticator::new(&v);
        begin_exchange(&mut auth);
        assert_malformed(auth.handle_client_final("c=biws,r=totally-different,p=AAAA", ""));
    }

    #[test]
    fn err_malformed_proof() {
        // A payload that is not base64 at all, and one that is valid base64 but
        // decodes to the wrong length (16 bytes, not 32). Both are only reached
        // after the nonce check, so each case runs its own exchange and derives
        // its own combined nonce.
        let cases = ["!!!not-base64!!!".to_string(), B64.encode(vec![0u8; 16])];

        for payload in cases {
            let v = verifier();
            let mut auth = ScramAuthenticator::new(&v);
            let server_first = begin_exchange(&mut auth);
            let nonce = combined_nonce_of(&server_first);
            let message = format!("c=biws,r={nonce},p={payload}");
            assert_malformed(auth.handle_client_final(&message, ""));
        }
    }
}
