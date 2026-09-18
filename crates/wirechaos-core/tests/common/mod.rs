//! Helpers shared by the integration tests.
//!
//! Cargo compiles every file in `tests/` as its own crate, so anything used by
//! more than one of them lives here and is pulled in with `mod common;`.

// Panicking is how a test reports a failed expectation, which is what clippy's
// `allow-*-in-tests` options encode. Integration test files are compiled as their
// own crate, so those settings do not reach the helper functions below; the allow is
// therefore stated once here, for test scaffolding only. Production code keeps the
// deny (see the [workspace.lints] table in Cargo.toml).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(dead_code)] // each test crate uses a different subset of these helpers

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rustls::{Certificate, PrivateKey, RootCertStore, ServerConfig, ServerName};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use wirechaos_core::proxy::auth::verifier::{
    hmac_sha256, pbkdf2_sha256, sha256, ProviderError, Verifier, VerifierProvider,
};
use wirechaos_core::proxy::buffer_pool::MultiBufferPool;

/// (1234 << 16) | 5679 — the SSLRequest startup-message code.
pub const SSL_REQUEST_CODE: u32 = 80877103;
/// (1234 << 16) | 5680 — the GSSENCRequest startup-message code.
pub const GSSENC_REQUEST_CODE: u32 = 80877104;
/// Protocol version 3.0 as a startup-message Int32.
pub const PROTOCOL_VERSION_3_0: u32 = 196608;

/// Authentication (`R`) sub-codes.
pub const AUTH_SASL: i32 = 10;
pub const AUTH_SASL_CONTINUE: i32 = 11;
pub const AUTH_SASL_FINAL: i32 = 12;

/// Message type bytes exchanged by the tests.
pub const MSG_AUTH: u8 = b'R';
pub const MSG_PASSWORD: u8 = b'p';
pub const MSG_ERROR: u8 = b'E';

/// Credentials the helpers and providers agree on.
pub const USER: &str = "peter";
pub const PASSWORD: &str = "pencil";
pub const SALT_ITERATIONS: u32 = 4096;
/// A fixed salt keeps derived keys reproducible across the assertions.
pub const SALT: [u8; 16] = [0x5a; 16];
pub const CLIENT_NONCE: &str = "fyko+d2lbbTB1mTN";

/// Every client read goes through this, so a server that never replies fails
/// the test instead of hanging it.
pub const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// A pool large enough for every message the tests exchange. `get` rounds a
/// request up to the smallest bucket that fits, so message bodies do not have
/// to land on an exact bucket size.
pub fn buffer_pool() -> Arc<MultiBufferPool> {
    MultiBufferPool::new(4, 1024, 4)
}

/// Generate a fresh self-signed certificate and build a matching server
/// acceptor and client connector from it.
pub fn tls_pair() -> (TlsAcceptor, TlsConnector) {
    let certified_key = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
        .expect("generate self-signed certificate");
    let cert_der = certified_key.cert.der().clone();
    let key_der = certified_key.key_pair.serialize_der();

    let server_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(
            vec![Certificate(cert_der.as_ref().to_vec())],
            PrivateKey(key_der),
        )
        .expect("build server config");

    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let mut roots = RootCertStore::empty();
    roots
        .add(&Certificate(cert_der.as_ref().to_vec()))
        .expect("add self-signed cert as root");

    let client_config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(client_config));

    (acceptor, connector)
}

/// The name the client uses to verify the test server's certificate.
pub fn server_name() -> ServerName {
    ServerName::try_from("localhost").expect("server name")
}

/// Build a StartupMessage wire payload carrying protocol 3.0 plus `params`.
pub fn startup_message(params: &[u8]) -> Vec<u8> {
    let body_len = 4 + params.len() as u32;
    let mut msg = Vec::with_capacity(4 + body_len as usize);
    msg.extend_from_slice(&(4 + body_len).to_be_bytes());
    msg.extend_from_slice(&PROTOCOL_VERSION_3_0.to_be_bytes());
    msg.extend_from_slice(params);
    msg
}

// ---- verifier provider ----

/// The verifier the tests authenticate against: `PASSWORD` with a fixed salt.
pub fn verifier(user_password: &str) -> Verifier {
    Verifier::from_password(user_password, SALT.to_vec(), SALT_ITERATIONS)
}

/// In-memory [`VerifierProvider`] covering the users one test needs.
pub struct TestVerifierProvider {
    users: HashMap<String, Verifier>,
}

impl TestVerifierProvider {
    /// A provider that knows `USER` with `PASSWORD`.
    pub fn new() -> Self {
        Self::with_user(USER, PASSWORD)
    }

    pub fn with_user(user: &str, password: &str) -> Self {
        let mut users = HashMap::new();
        users.insert(user.to_string(), verifier(password));

        Self { users }
    }

    /// A provider that knows nobody: every lookup misses.
    pub fn empty() -> Self {
        Self {
            users: HashMap::new(),
        }
    }
}

impl VerifierProvider for TestVerifierProvider {
    /// `Ok(None)` is the "no such user" answer; `Err` is reserved for a store
    /// that could not be consulted. `ProviderError` currently has no variants,
    /// so a store failure cannot be simulated from here yet.
    fn lookup(&self, username: &str) -> Result<Option<Verifier>, ProviderError> {
        Ok(self.users.get(username).cloned())
    }
}

// ---- message framing ----

/// Read one backend message: 1-byte type, Int32 length, then the body.
pub async fn read_message<S: AsyncRead + Unpin>(stream: &mut S) -> (u8, Vec<u8>) {
    let mut header = [0u8; 5];

    timeout(IO_TIMEOUT, stream.read_exact(&mut header))
        .await
        .expect("timed out waiting for a server message")
        .expect("read message header");

    let length = u32::from_be_bytes(header[1..5].try_into().unwrap()) as usize;
    assert!(
        length >= 4,
        "message length {length} leaves no room for the length field itself"
    );

    let mut body = vec![0u8; length - 4];

    timeout(IO_TIMEOUT, stream.read_exact(&mut body))
        .await
        .expect("timed out reading a message body")
        .expect("read message body");

    (header[0], body)
}

/// Write one frontend message: 1-byte type, Int32 length, then the body.
pub async fn write_message<S: AsyncWrite + Unpin>(stream: &mut S, message_type: u8, body: &[u8]) {
    let mut msg = Vec::with_capacity(5 + body.len());
    msg.push(message_type);
    msg.extend_from_slice(&((body.len() + 4) as u32).to_be_bytes());
    msg.extend_from_slice(body);

    timeout(IO_TIMEOUT, stream.write_all(&msg))
        .await
        .expect("timed out writing a message")
        .expect("write message");

    timeout(IO_TIMEOUT, stream.flush())
        .await
        .expect("timed out flushing a message")
        .expect("flush message");
}

/// Write a bare Int32 length prefix — the malformed-input tests need a header
/// without a body behind it.
pub async fn write_length_prefix<S: AsyncWrite + Unpin>(stream: &mut S, raw_length: u32) {
    stream
        .write_all(&raw_length.to_be_bytes())
        .await
        .expect("write length prefix");
    stream.flush().await.expect("flush length prefix");
}

/// Write a startup-phase message: bare Int32 length followed by the payload.
pub async fn write_startup_payload<S: AsyncWrite + Unpin>(stream: &mut S, msg: &[u8]) {
    stream.write_all(msg).await.expect("write startup message");
    stream.flush().await.expect("flush startup message");
}

/// The sub-code of an `R` (authentication) message body.
pub fn auth_sub_code(body: &[u8]) -> i32 {
    i32::from_be_bytes(body[..4].try_into().expect("auth body carries a sub-code"))
}

/// The SASL mechanism list carried by an AuthenticationSASL body.
pub fn sasl_mechanisms(body: &[u8]) -> Vec<String> {
    let mut mechanisms = Vec::new();
    let mut current = Vec::new();

    for byte in &body[4..] {
        if *byte == 0 {
            if current.is_empty() {
                break; // the terminating empty string
            }

            mechanisms.push(String::from_utf8(current.clone()).expect("mechanism is utf-8"));
            current.clear();
        } else {
            current.push(*byte);
        }
    }

    mechanisms
}

/// Parse the `Xvalue\0` fields of an ErrorResponse body into a map.
pub fn error_fields(body: &[u8]) -> HashMap<char, String> {
    let mut fields = HashMap::new();
    let mut i = 0;

    while i < body.len() && body[i] != 0 {
        let field_type = body[i] as char;
        i += 1;

        let start = i;
        while i < body.len() && body[i] != 0 {
            i += 1;
        }

        let value = String::from_utf8(body[start..i].to_vec()).expect("error field is utf-8");
        fields.insert(field_type, value);

        i += 1; // step over the NUL terminator
    }

    fields
}

// ---- SCRAM client ----

/// The body of a SASLInitialResponse: mechanism cstring, Int32 data length,
/// then the client-first-message.
pub fn sasl_initial_response_body(mechanism: &str, data: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(mechanism.len() + 5 + data.len());
    body.extend_from_slice(mechanism.as_bytes());
    body.push(0);
    body.extend_from_slice(&(data.len() as i32).to_be_bytes());
    body.extend_from_slice(data);

    body
}

/// Answer the server's AuthenticationSASL request with `client_first` and
/// return the mechanism the client claimed to use.
pub async fn begin_sasl<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    client_first: &str,
) -> String {
    let (message_type, body) = read_message(stream).await;
    assert_eq!(
        message_type, MSG_AUTH,
        "the server must open with an authentication request"
    );
    assert_eq!(
        auth_sub_code(&body),
        AUTH_SASL,
        "the server must request SASL authentication"
    );

    let mechanisms = sasl_mechanisms(&body);
    assert!(
        mechanisms.contains(&"SCRAM-SHA-256".to_string()),
        "SCRAM-SHA-256 must be offered: {mechanisms:?}"
    );

    let mechanism = mechanisms[0].clone();
    let body = sasl_initial_response_body(&mechanism, client_first.as_bytes());
    write_message(stream, MSG_PASSWORD, &body).await;

    mechanism
}

/// Read AuthenticationSASLContinue and return its server-first payload.
pub async fn read_server_first<S: AsyncRead + Unpin>(stream: &mut S) -> String {
    let (message_type, body) = read_message(stream).await;
    assert_eq!(message_type, MSG_AUTH);
    assert_eq!(auth_sub_code(&body), AUTH_SASL_CONTINUE);

    String::from_utf8(body[4..].to_vec()).expect("server-first is utf-8")
}

/// Read AuthenticationSASLFinal and return its server-final payload.
pub async fn read_server_final<S: AsyncRead + Unpin>(stream: &mut S) -> String {
    let (message_type, body) = read_message(stream).await;
    assert_eq!(message_type, MSG_AUTH);
    assert_eq!(auth_sub_code(&body), AUTH_SASL_FINAL);

    String::from_utf8(body[4..].to_vec()).expect("server-final is utf-8")
}

/// Read an ErrorResponse and return its fields.
pub async fn read_error<S: AsyncRead + Unpin>(stream: &mut S) -> HashMap<char, String> {
    let (message_type, body) = read_message(stream).await;
    assert_eq!(
        message_type, MSG_ERROR,
        "the server must report failures as framed ErrorResponse messages"
    );

    error_fields(&body)
}

/// A minimal SCRAM-SHA-256 client (RFC 5802).
///
/// Everything it produces is derived from the password and the server-first
/// message, so the server is checked against an independent implementation
/// instead of against its own helpers.
pub struct ScramClient {
    password: String,
    client_nonce: String,
    gs2_header: &'static str,
    client_first_bare: String,
    combined_nonce: String,
    server_first: String,
    client_final_without_proof: String,
    proof: Vec<u8>,
    client_key: Vec<u8>,
    expected_server_final: String,
}

impl ScramClient {
    pub fn new(user: &str, password: &str, client_nonce: &str) -> Self {
        Self {
            password: password.to_string(),
            client_nonce: client_nonce.to_string(),
            gs2_header: "n,,",
            client_first_bare: format!("n={user},r={client_nonce}"),
            combined_nonce: String::new(),
            server_first: String::new(),
            client_final_without_proof: String::new(),
            proof: Vec::new(),
            client_key: Vec::new(),
            expected_server_final: String::new(),
        }
    }

    /// The client-first-message, GS2 header included.
    pub fn client_first(&self) -> String {
        format!("{}{}", self.gs2_header, self.client_first_bare)
    }

    /// Consume server-first and derive the client-final values from it.
    pub fn handle_server_first(&mut self, server_first: &str) {
        self.server_first = server_first.to_string();

        let mut combined_nonce = String::new();
        let mut salt_b64 = String::new();
        let mut iterations = 0u32;

        for attr in server_first.split(',') {
            if let Some(value) = attr.strip_prefix("r=") {
                combined_nonce = value.to_string();
            } else if let Some(value) = attr.strip_prefix("s=") {
                salt_b64 = value.to_string();
            } else if let Some(value) = attr.strip_prefix("i=") {
                iterations = value
                    .parse()
                    .expect("server-first iterations must be a number");
            }
        }

        assert!(
            combined_nonce.starts_with(&self.client_nonce),
            "server-first must echo the client nonce: {server_first}"
        );

        let salt = B64
            .decode(salt_b64)
            .expect("server-first salt must be base64");
        let salted = pbkdf2_sha256(self.password.as_bytes(), &salt, iterations);
        let client_key = hmac_sha256(&salted, b"Client Key");

        self.client_final_without_proof = format!(
            "c={},r={combined_nonce}",
            B64.encode(self.gs2_header.as_bytes())
        );
        let auth_message = format!(
            "{},{},{}",
            self.client_first_bare, self.server_first, self.client_final_without_proof
        );

        let client_sig = hmac_sha256(&sha256(&client_key), auth_message.as_bytes());
        let proof: Vec<u8> = client_key
            .iter()
            .zip(client_sig.iter())
            .map(|(a, b)| a ^ b)
            .collect();

        // The client checks the server against ServerKey, not StoredKey.
        let server_key = hmac_sha256(&salted, b"Server Key");

        self.combined_nonce = combined_nonce;
        self.client_key = client_key.to_vec();
        self.proof = proof;
        self.expected_server_final = format!(
            "v={}",
            B64.encode(hmac_sha256(&server_key, auth_message.as_bytes()))
        );
    }

    /// The client-final-message, proof included.
    pub fn client_final(&self) -> String {
        format!(
            "{},p={}",
            self.client_final_without_proof,
            B64.encode(&self.proof)
        )
    }

    /// The combined nonce the server handed out.
    pub fn combined_nonce(&self) -> &str {
        &self.combined_nonce
    }

    /// The ClientKey the password derives, as the server should extract it.
    pub fn client_key(&self) -> &[u8] {
        &self.client_key
    }

    /// The server-final the client expects to be sent back.
    pub fn expected_server_final(&self) -> &str {
        &self.expected_server_final
    }
}
