use crate::auth::error::ScramError;
use crate::auth::verifier::Verifier;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand::RngCore;

#[derive(Debug, PartialEq)]
enum State {
    Started,
    ClientFirstReceived,
    Done,
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
            return Err(ScramError::Protocol("missing client nonce".to_string()));
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

    fn validate_authzid_part(&self, authzid_part: &str) -> Result<(), ScramError> {
        if authzid_part.starts_with("a=") && authzid_part.len() > 2 {
            return Err(ScramError::Protocol(
                "client uses authorization identity, but it is not supported ".into(),
            ));
        } else if !authzid_part.is_empty() && !authzid_part.starts_with("a=") {
            return Err(ScramError::Protocol("malformed authzid".into()));
        }

        Ok(())
    }

    fn validate_params(&self, mechanism: &str, startup_user: &str) -> Result<(), ScramError> {
        if self.state != State::Started {
            return Err(ScramError::Protocol("unexpected client first".into()));
        }

        if startup_user.is_empty() {
            return Err(ScramError::Protocol(
                "startup user must not be empty".into(),
            ));
        }

        if mechanism != SCRAM_SHA_256 {
            return Err(ScramError::Protocol(
                format!("unsupported SASL mechanism: {}", mechanism).into(),
            ));
        }

        Ok(())
    }
    fn extract_data_from_client_first<'b>(
        &self,
        client_first: &'b str,
    ) -> Result<(&'b str, &'b str, &'b str), ScramError> {
        let parts: Vec<&str> = client_first.splitn(3, ',').collect();

        if parts.len() < 3 {
            return Err(ScramError::Protocol(
                "client-first-message needs >= 3 comma parts".into(),
            ));
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

            _ => {
                return Err(ScramError::Protocol(
                    format!("invalid gs2 flag: {}", flag).into(),
                ))
            }
        };

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::verifier::Verifier;
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

    /// Pull the message out of a Protocol error (the only error `handle_client_first`
    /// currently returns), panicking otherwise.
    fn protocol_err(result: Result<String, ScramError>) -> String {
        match result {
            Err(ScramError::Protocol(message)) => message,
            Err(ScramError::AuthenticationFailed) => {
                panic!("expected Protocol error, got AuthenticationFailed")
            }
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    #[test]
    fn mechanisms_offers_sha_256() {
        let v = verifier();
        let auth = ScramAuthenticator::new(&v);
        assert_eq!(auth.mechanisms(), vec![SCRAM_SHA_256]);
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
        let decoded = B64.decode(server_nonce).expect("server nonce must be valid base64");
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
        let err = protocol_err(auth.handle_client_first(SCRAM_SHA_256, &client_first, USER));
        assert_eq!(err, "unexpected client first");
    }

    #[test]
    fn ok_can_retry_after_protocol_error() {
        let v = verifier();
        let mut auth = ScramAuthenticator::new(&v);

        // Parsing failure leaves state untouched (still Started), so a retry works.
        let err = protocol_err(auth.handle_client_first(SCRAM_SHA_256, "n,", USER));
        assert_eq!(err, "client-first-message needs >= 3 comma parts");

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
        let err = protocol_err(auth.handle_client_first(SCRAM_SHA_256, &client_first, USER));
        assert_eq!(err, "missing client nonce");
    }

    #[test]
    fn err_fewer_than_three_comma_parts() {
        let v = verifier();
        let mut auth = ScramAuthenticator::new(&v);
        let err = protocol_err(auth.handle_client_first(SCRAM_SHA_256, "n,", USER));
        assert_eq!(err, "client-first-message needs >= 3 comma parts");
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
        let err = protocol_err(auth.handle_client_first(SCRAM_SHA_256, &client_first, USER));
        assert_eq!(err, "invalid gs2 flag: x");
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
        let err = protocol_err(auth.handle_client_first(SCRAM_SHA_256, &client_first, USER));
        assert_eq!(err, "malformed authzid");
    }

    #[test]
    fn extractor_splits_gs2_header_from_bare() {
        let v = verifier();
        let auth = ScramAuthenticator::new(&v);
        let client_first = format!("n,,n={USER},r={CLIENT_NONCE}");
        let (flag, authzid, bare) =
            expect_ok(auth.extract_data_from_client_first(&client_first));
        assert_eq!(flag, "n");
        assert_eq!(authzid, "");
        assert_eq!(bare, format!("n={USER},r={CLIENT_NONCE}"));

        let parts = auth.extract_data_from_client_first("n,");
        assert!(parts.is_err(), "two-part message must be rejected");
    }
}
