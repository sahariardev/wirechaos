//! A scripted PostgreSQL backend for the integration tests.
//!
//! It is a *peer*, not a stub: it runs a real SCRAM server exchange, verifies
//! the proxy's proof against the stored `StoredKey`, checks channel binding
//! against its own certificate, records what it received, and can drop or hold
//! a connection on demand.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use base64::engine::general_purpose::STANDARD as B64;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::sync::Notify;
use wirechaos_core::proxy::auth::verifier::{hmac_sha256, sha256, Verifier};
use wirechaos_core::proxy::backend::md5_response;
use wirechaos_core::proxy::tls::CertHash;

const AUTH_OK: i32 = 0;
const AUTH_CLEARTEXT: i32 = 3;
const AUTH_MD5: i32 = 5;
const AUTH_SASL: i32 = 10;
const AUTH_SASL_CONTINUE: i32 = 11;
const AUTH_SASL_FINAL: i32 = 12;

const FAKE_SALT: [u8; 16] = [0x11; 16];
const FAKE_ITERATIONS: u32 = 4096;

#[derive(Clone)]
enum AuthMode {
    Trust,
    Cleartext {
        password: Option<String>,
    },
    Md5 {
        password: Option<String>,
    },
    Scram {
        verifier: Option<Arc<Verifier>>,
        require_plus: bool,
    },
    Unsupported(u32),
}

struct FakeConfig {
    auth: AuthMode,
    parameters: Vec<(String, String)>,
    backend_key: Option<(i32, i32)>,
    hang_after_startup: bool,
    hold_query_open: bool,
}

#[derive(Default)]
struct Recorded {
    saw_authentication_ok: bool,
    observed_mechanism: Option<String>,
    channel_binding_matched: bool,
    received_md5_response: Option<String>,
    received_password: Option<String>,
    startup_params: Vec<(String, String)>,
}

struct Inner {
    config: FakeConfig,
    recorded: Mutex<Recorded>,
    kill: Notify,
    tls_acceptor: Option<TlsAcceptor>,
    tls_cert_hash: Option<CertHash>,
}

#[derive(Clone)]
pub struct FakeBackend {
    inner: Arc<Inner>,
    addr: SocketAddr,
}

/// Builder returned by [`FakeBackend::start`].
pub struct FakeBackendBuilder {
    auth: AuthMode,
    parameters: Vec<(String, String)>,
    backend_key: Option<(i32, i32)>,
    hang_after_startup: bool,
    hold_query_open: bool,
    tls: bool,
}

impl FakeBackend {
    pub fn start() -> FakeBackendBuilder {
        FakeBackendBuilder {
            auth: AuthMode::Trust,
            parameters: vec![("server_version".to_owned(), "17.2".to_owned())],
            backend_key: Some((4242, 0x0BCD_1234)),
            hang_after_startup: false,
            hold_query_open: false,
            tls: false,
        }
    }

    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    #[must_use]
    pub fn real_key(&self) -> (i32, i32) {
        self.inner.config.backend_key.unwrap_or((0, 0))
    }

    #[must_use]
    pub fn saw_authentication_ok(&self) -> bool {
        lock(&self.inner.recorded).saw_authentication_ok
    }

    #[must_use]
    pub fn observed_mechanism(&self) -> Option<String> {
        lock(&self.inner.recorded).observed_mechanism.clone()
    }

    #[must_use]
    pub fn channel_binding_matched(&self) -> bool {
        lock(&self.inner.recorded).channel_binding_matched
    }

    #[must_use]
    pub fn received_md5_response(&self) -> Option<String> {
        lock(&self.inner.recorded).received_md5_response.clone()
    }

    #[must_use]
    pub fn received_password(&self) -> Option<String> {
        lock(&self.inner.recorded).received_password.clone()
    }

    #[must_use]
    pub fn startup_params(&self) -> Vec<(String, String)> {
        lock(&self.inner.recorded).startup_params.clone()
    }

    pub fn kill_connection(&self) {
        self.inner.kill.notify_waiters();
    }
}

impl FakeBackendBuilder {
    pub fn with_trust_auth(mut self) -> Self {
        self.auth = AuthMode::Trust;
        self
    }

    pub fn requiring_cleartext(mut self) -> Self {
        self.auth = AuthMode::Cleartext { password: None };
        self
    }

    pub fn requiring_md5(mut self) -> Self {
        self.auth = AuthMode::Md5 { password: None };
        self
    }

    pub fn requiring_scram(mut self) -> Self {
        self.auth = AuthMode::Scram {
            verifier: None,
            require_plus: false,
        };
        self
    }

    pub fn requiring_plus(mut self) -> Self {
        self.auth = AuthMode::Scram {
            verifier: None,
            require_plus: true,
        };
        self
    }

    pub fn requiring_unsupported(mut self, code: u32) -> Self {
        self.auth = AuthMode::Unsupported(code);
        self
    }

    pub fn with_secret(mut self, secret: &str) -> Self {
        let verifier =
            Arc::new(Verifier::from_pg_secret(secret).expect("valid fake-backend secret"));

        self.auth = match self.auth {
            AuthMode::Scram { require_plus, .. } => AuthMode::Scram {
                verifier: Some(verifier),
                require_plus,
            },
            other => other,
        };
        self
    }

    pub fn with_password_for(mut self, _user: &str, password: &str) -> Self {
        let verifier = Arc::new(Verifier::from_password(
            password,
            FAKE_SALT,
            FAKE_ITERATIONS,
        ));

        self.auth = match self.auth {
            AuthMode::Scram { require_plus, .. } => AuthMode::Scram {
                verifier: Some(verifier),
                require_plus,
            },
            AuthMode::Cleartext { .. } => AuthMode::Cleartext {
                password: Some(password.to_owned()),
            },
            AuthMode::Md5 { .. } => AuthMode::Md5 {
                password: Some(password.to_owned()),
            },
            other => other,
        };

        self
    }

    pub fn with_parameter(mut self, name: &str, value: &str) -> Self {
        self.parameters.push((name.to_owned(), value.to_owned()));
        self
    }

    pub fn with_backend_key(mut self, pid: i32, secret: i32) -> Self {
        self.backend_key = Some((pid, secret));
        self
    }

    pub fn hanging_after_startup(mut self) -> Self {
        self.hang_after_startup = true;
        self
    }

    pub fn holding_query_open(mut self) -> Self {
        self.hold_query_open = true;
        self
    }

    pub fn with_tls(mut self) -> Self {
        self.tls = true;
        self
    }

    pub async fn start(self) -> FakeBackend {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake backend");
        let addr = listener.local_addr().expect("fake backend addr");

        let (tls_acceptor, tls_cert_hash) = if self.tls {
            let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
                .expect("generate backend certificate");
            let cert_der = certified.cert.der().clone();
            let key_der = certified.key_pair.serialize_der();

            let server_config = ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![cert_der.clone()],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der)),
                )
                .expect("fake backend TLS config");

            (
                Some(TlsAcceptor::from(Arc::new(server_config))),
                CertHash::new(cert_der.as_ref()).expect("certificate parses"),
            )
        } else {
            (None, None)
        };

        let backend = FakeBackend {
            inner: Arc::new(Inner {
                config: FakeConfig {
                    auth: self.auth,
                    parameters: self.parameters,
                    backend_key: self.backend_key,
                    hang_after_startup: self.hang_after_startup,
                    hold_query_open: self.hold_query_open,
                },
                recorded: Mutex::new(Recorded::default()),
                kill: Notify::new(),
                tls_acceptor,
                tls_cert_hash,
            }),
            addr,
        };

        let accept_state = backend.clone();
        tokio::spawn(async move {
            loop {
                let (socket, _peer) = match listener.accept().await {
                    Ok(value) => value,
                    Err(_) => break,
                };

                let state = accept_state.clone();
                tokio::spawn(async move {
                    let _ = run_connection(socket, state).await;
                });
            }
        });

        backend
    }
}

/// The transport after the optional TLS upgrade. Generic helpers below keep the
/// raw and TLS paths on the same code.
trait FakeStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> FakeStream for T {}

async fn run_connection(mut socket: TcpStream, backend: FakeBackend) -> std::io::Result<()> {
    let first = read_startup_message(&mut socket).await?;

    let mut stream: Box<dyn FakeStream>;
    let startup: Vec<u8>;

    if is_ssl_request(&first) {
        if let Some(acceptor) = backend.inner.tls_acceptor.as_ref() {
            socket.write_all(b"S").await?;
            socket.flush().await?;
            stream = Box::new(acceptor.accept(socket).await?);
        } else {
            socket.write_all(b"N").await?;
            socket.flush().await?;
            stream = Box::new(socket);
        }

        startup = read_startup_message(&mut stream).await?;
    } else {
        stream = Box::new(socket);
        startup = first;
    }

    let params = parse_startup_params(&startup);
    lock(&backend.inner.recorded).startup_params = params.clone();
    let user = params
        .iter()
        .find(|(name, _)| name == "user")
        .map(|(_, value)| value.clone())
        .unwrap_or_default();

    match backend.inner.config.auth.clone() {
        AuthMode::Trust => {
            write_auth(&mut stream, AUTH_OK, &[]).await?;
        }
        AuthMode::Cleartext { password } => {
            write_auth(&mut stream, AUTH_CLEARTEXT, &[]).await?;
            let (tag, body) = read_message(&mut stream).await?;
            if tag != b'p' {
                return Err(std::io::Error::other("expected PasswordMessage"));
            }
            let received = cstr(&body);
            lock(&backend.inner.recorded).received_password = Some(received.clone());

            if password
                .as_deref()
                .is_some_and(|expected| expected != received)
            {
                write_error(&mut stream, "28P01", "password authentication failed").await?;
                return Ok(());
            }
            write_auth(&mut stream, AUTH_OK, &[]).await?;
        }
        AuthMode::Md5 { password } => {
            let salt = [0x01u8, 0x02, 0x03, 0x04];
            let mut body = AUTH_MD5.to_be_bytes().to_vec();
            body.extend_from_slice(&salt);
            write_message(&mut stream, b'R', &body).await?;

            let (tag, body) = read_message(&mut stream).await?;
            if tag != b'p' {
                return Err(std::io::Error::other("expected PasswordMessage"));
            }
            let received = cstr(&body);
            lock(&backend.inner.recorded).received_md5_response = Some(received.clone());

            if let Some(password) = password {
                if md5_response(&user, password.as_bytes(), &salt) != received {
                    write_error(&mut stream, "28P01", "password authentication failed").await?;
                    return Ok(());
                }
            }
            write_auth(&mut stream, AUTH_OK, &[]).await?;
        }
        AuthMode::Scram {
            verifier,
            require_plus,
        } => {
            let verifier = verifier.expect("fake backend needs a SCRAM secret/password");
            if !run_scram(&mut stream, &backend, &verifier, require_plus).await? {
                return Ok(());
            }
        }
        AuthMode::Unsupported(code) => {
            write_auth(&mut stream, code as i32, &[]).await?;
            return Ok(());
        }
    }

    lock(&backend.inner.recorded).saw_authentication_ok = true;

    if backend.inner.config.hang_after_startup {
        backend.inner.kill.notified().await;
        return Ok(());
    }

    for (name, value) in &backend.inner.config.parameters {
        let mut body = Vec::new();
        put_cstr(&mut body, name);
        put_cstr(&mut body, value);
        write_message(&mut stream, b'S', &body).await?;
    }

    if let Some((pid, secret)) = backend.inner.config.backend_key {
        let mut body = Vec::new();
        body.extend_from_slice(&pid.to_be_bytes());
        body.extend_from_slice(&secret.to_be_bytes());
        write_message(&mut stream, b'K', &body).await?;
    }

    write_message(&mut stream, b'Z', b"I").await?;

    loop {
        tokio::select! {
            _ = backend.inner.kill.notified() => return Ok(()),
            message = read_message(&mut stream) => {
                let Ok((tag, _body)) = message else { return Ok(()); };
                match tag {
                    b'X' => return Ok(()),
                    b'Q' if !backend.inner.config.hold_query_open => {
                        write_message(&mut stream, b'C', b"SELECT 0\0").await?;
                        write_message(&mut stream, b'Z', b"I").await?;
                    }
                    _ => {}
                }
            }
        }
    }
}

async fn run_scram<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    backend: &FakeBackend,
    verifier: &Verifier,
    require_plus: bool,
) -> std::io::Result<bool> {
    let mechanisms: Vec<&str> = if require_plus {
        vec!["SCRAM-SHA-256-PLUS"]
    } else if backend.inner.tls_acceptor.is_some() {
        vec!["SCRAM-SHA-256-PLUS", "SCRAM-SHA-256"]
    } else {
        vec!["SCRAM-SHA-256"]
    };

    let mut body = AUTH_SASL.to_be_bytes().to_vec();
    for mechanism in &mechanisms {
        put_cstr(&mut body, mechanism);
    }
    body.push(0);
    write_message(stream, b'R', &body).await?;

    let (tag, body) = read_message(stream).await?;
    if tag != b'p' {
        return Err(std::io::Error::other("expected SASLInitialResponse"));
    }

    let mechanism_end = body
        .iter()
        .position(|&byte| byte == 0)
        .ok_or_else(|| std::io::Error::other("mechanism is not NUL-terminated"))?;
    let mechanism = String::from_utf8_lossy(&body[..mechanism_end]).into_owned();
    let mut position = mechanism_end + 1;

    if body.len() < position + 4 {
        return Err(std::io::Error::other("truncated SASL initial response"));
    }
    let data_len = i32::from_be_bytes(body[position..position + 4].try_into().unwrap());
    position += 4;
    if data_len < 0 || body.len() < position + data_len as usize {
        return Err(std::io::Error::other(
            "invalid SASL initial response length",
        ));
    }
    let client_first =
        String::from_utf8_lossy(&body[position..position + data_len as usize]).into_owned();

    lock(&backend.inner.recorded).observed_mechanism = Some(mechanism.clone());

    if require_plus && mechanism != "SCRAM-SHA-256-PLUS" {
        write_error(stream, "28P01", "channel binding required").await?;
        return Ok(false);
    }

    let header_end = second_comma_end(&client_first)
        .ok_or_else(|| std::io::Error::other("malformed client-first GS2 header"))?;
    let gs2_header = &client_first[..header_end];
    let client_first_bare = &client_first[header_end..];

    let client_nonce = client_first_bare
        .split(',')
        .find_map(|attribute| attribute.strip_prefix("r="))
        .ok_or_else(|| std::io::Error::other("client-first has no nonce"))?;
    let combined_nonce = format!("{client_nonce}FAKESERVERNONCE");

    let server_first = format!(
        "r={combined_nonce},s={},i={}",
        B64.encode(verifier.salt()),
        verifier.iterations()
    );

    let mut body = AUTH_SASL_CONTINUE.to_be_bytes().to_vec();
    body.extend_from_slice(server_first.as_bytes());
    write_message(stream, b'R', &body).await?;

    let (tag, body) = read_message(stream).await?;
    if tag != b'p' {
        return Err(std::io::Error::other("expected SASLResponse"));
    }
    let client_final = String::from_utf8_lossy(&body).into_owned();

    let (without_proof, proof_b64) = client_final
        .rsplit_once(",p=")
        .ok_or_else(|| std::io::Error::other("client-final has no proof"))?;

    let mut expected_cbind = gs2_header.as_bytes().to_vec();
    if mechanism == "SCRAM-SHA-256-PLUS" {
        let hash = backend
            .inner
            .tls_cert_hash
            .as_ref()
            .expect("PLUS requires a certificate hash");
        expected_cbind.extend_from_slice(&hash.digest);
    }
    let expected_c = B64.encode(expected_cbind);

    let c_matches = without_proof
        .split(',')
        .find_map(|attribute| attribute.strip_prefix("c="))
        .is_some_and(|value| value == expected_c);

    if mechanism == "SCRAM-SHA-256-PLUS" {
        lock(&backend.inner.recorded).channel_binding_matched = c_matches;
        if !c_matches {
            write_error(stream, "28P01", "channel binding mismatch").await?;
            return Ok(false);
        }
    }

    let auth_message = format!("{client_first_bare},{server_first},{without_proof}");
    let proof = B64
        .decode(proof_b64)
        .map_err(|_| std::io::Error::other("proof is not base64"))?;
    let client_signature = hmac_sha256(verifier.stored_key(), auth_message.as_bytes());

    if proof.len() != client_signature.len() {
        write_error(stream, "28P01", "malformed proof").await?;
        return Ok(false);
    }

    let client_key: Vec<u8> = proof
        .iter()
        .zip(client_signature.iter())
        .map(|(a, b)| a ^ b)
        .collect();

    if sha256(&client_key) != *verifier.stored_key() {
        write_error(stream, "28P01", "password authentication failed").await?;
        return Ok(false);
    }

    let server_signature = hmac_sha256(verifier.server_key(), auth_message.as_bytes());
    let mut body = AUTH_SASL_FINAL.to_be_bytes().to_vec();
    body.extend_from_slice(format!("v={}", B64.encode(server_signature)).as_bytes());
    write_message(stream, b'R', &body).await?;

    write_auth(stream, AUTH_OK, &[]).await?;
    Ok(true)
}

async fn write_auth<S: AsyncWrite + Unpin>(
    stream: &mut S,
    sub_code: i32,
    data: &[u8],
) -> std::io::Result<()> {
    let mut body = sub_code.to_be_bytes().to_vec();
    body.extend_from_slice(data);
    write_message(stream, b'R', &body).await
}

async fn write_error<S: AsyncWrite + Unpin>(
    stream: &mut S,
    code: &str,
    message: &str,
) -> std::io::Result<()> {
    let mut body = Vec::new();
    body.push(b'S');
    put_cstr(&mut body, "FATAL");
    body.push(b'C');
    put_cstr(&mut body, code);
    body.push(b'M');
    put_cstr(&mut body, message);
    body.push(0);
    write_message(stream, b'E', &body).await
}

async fn write_message<S: AsyncWrite + Unpin>(
    stream: &mut S,
    tag: u8,
    body: &[u8],
) -> std::io::Result<()> {
    let mut message = Vec::with_capacity(5 + body.len());
    message.push(tag);
    message.extend_from_slice(&((body.len() + 4) as u32).to_be_bytes());
    message.extend_from_slice(body);

    stream.write_all(&message).await?;
    stream.flush().await
}

async fn read_message<S: AsyncRead + Unpin>(stream: &mut S) -> std::io::Result<(u8, Vec<u8>)> {
    let mut header = [0u8; 5];
    stream.read_exact(&mut header).await?;

    let len = u32::from_be_bytes(header[1..5].try_into().unwrap()) as usize;
    if len < 4 {
        return Err(std::io::Error::other("invalid fake-backend frame length"));
    }

    let mut body = vec![0u8; len - 4];
    stream.read_exact(&mut body).await?;

    Ok((header[0], body))
}

async fn read_startup_message<S: AsyncRead + Unpin>(stream: &mut S) -> std::io::Result<Vec<u8>> {
    let mut length = [0u8; 4];
    stream.read_exact(&mut length).await?;

    let length = u32::from_be_bytes(length) as usize;
    if length < 4 {
        return Err(std::io::Error::other("invalid startup length"));
    }

    let mut body = vec![0u8; length - 4];
    stream.read_exact(&mut body).await?;

    Ok(body)
}

fn is_ssl_request(startup: &[u8]) -> bool {
    startup.len() == 4 && u32::from_be_bytes(startup.try_into().unwrap()) == SSL_REQUEST_CODE
}

fn parse_startup_params(startup: &[u8]) -> Vec<(String, String)> {
    let mut params = Vec::new();
    let mut position = 4usize;

    while position < startup.len() {
        let name_end = match startup[position..].iter().position(|&byte| byte == 0) {
            Some(offset) if offset > 0 => position + offset,
            _ => break,
        };
        let name = String::from_utf8_lossy(&startup[position..name_end]).into_owned();
        position = name_end + 1;

        let value_end = match startup[position..].iter().position(|&byte| byte == 0) {
            Some(offset) => position + offset,
            None => break,
        };
        let value = String::from_utf8_lossy(&startup[position..value_end]).into_owned();
        position = value_end + 1;

        params.push((name, value));
    }

    params
}

fn cstr(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn second_comma_end(value: &str) -> Option<usize> {
    let first = value.find(',')?;
    let second = value[first + 1..].find(',')? + first + 1;
    Some(second + 1)
}

fn put_cstr(buf: &mut Vec<u8>, value: &str) {
    buf.extend_from_slice(value.as_bytes());
    buf.push(b'\0');
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
