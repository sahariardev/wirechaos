use crate::proxy::auth::verifier::VerifierProvider;
use crate::proxy::backend::connection::Backend;
use crate::proxy::backend::registry::Registry;
use crate::proxy::backend::registry::SessionGuard;
use crate::proxy::backend::session_key_secret::SessionKeySecret;
use crate::proxy::buffer_pool::{MultiBufferPool, PooledBytes};
use crate::proxy::config::Config;
use crate::proxy::conn_read::ConnRead;
use crate::proxy::conn_registry::ConnRegistry;
use crate::proxy::conn_write::ConnWrite;
use crate::proxy::error::{
    connection_error, protocol_error, ClientAwareError, ConnectionErrorInner::*, ProxyError,
};
use crate::proxy::packet::MessageReader;
use crate::proxy::replication_mode::ReplicationMode;
use crate::proxy::startup_config_parse_util::{parse_options, parse_replication_mode};
use crate::proxy::tls::FrontendTls;
use crate::proxy::InternalError;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::TcpStream;

pub struct Conn<V: VerifierProvider> {
    pub conn_id: i32,
    pub buffer_reader: BufReader<ConnRead>,
    pub buffer_writer: BufWriter<ConnWrite>,
    pub pool: Arc<MultiBufferPool>,
    //todo:: rename this to tls
    pub ssl_done: bool,
    pub required_tls: bool,
    pub gss_done: bool,
    pub frontend_tls: Option<FrontendTls>,
    pub protocol_version: Option<u32>,
    pub params: HashMap<String, String>,
    pub user: Option<String>,
    pub database: Option<String>,
    pub replication_mode: ReplicationMode,
    pub provider: V,
    pub backend_registry: Registry,
    pub session_key_secret: Option<SessionKeySecret>,
    pub backend: Option<Arc<Backend>>,
    pub conn_registry: ConnRegistry,
    pub config: Arc<Config>,
    /// Kept alive for the session's lifetime so the registry entry — and with it
    /// the cancel key — exists exactly as long as the session does.
    session_guard: Option<SessionGuard>,
}

const CANCEL_REQUEST_CODE: u32 = (1234 << 16) | 5678;
const SSL_REQUEST_CODE: u32 = (1234 << 16) | 5679;
const GSSENC_REQUEST_CODE: u32 = (1234 << 16) | 5680;

//protocol version
const PROTOCOL_MAJOR_VERSION: u32 = 3;
const PROTOCOL_MINOR_VERSION: u32 = 0;
const PROTOCOL_VERSION_NUMBER: u32 = (PROTOCOL_MAJOR_VERSION << 16) | PROTOCOL_MINOR_VERSION;

const MSG_PARAMETER_STATUS: u8 = b'S';
const MSG_KEY_SECRET: u8 = b'K';
const MSG_READY_ACCEPT_QUERY: u8 = b'Z';
const MSG_ERROR: u8 = b'E';
const SQLSTATE_FEATURE_NOT_SUPPORTED: &str = "0A000";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupOutCome {
    Continued,
    Ready,
    Close,
}

impl<V: VerifierProvider> Conn<V> {
    #[allow(
        clippy::too_many_arguments,
        reason = "each argument transfers ownership of one per-session component; a builder would obscure the ownership transfer without adding safety"
    )]
    pub fn new(
        conn_id: i32,
        stream: TcpStream,
        pool: Arc<MultiBufferPool>,
        frontend_tls: Option<FrontendTls>,
        verifier_provider: V,
        backend_pool: Registry,
        conn_registry: ConnRegistry,
        config: Arc<Config>,
    ) -> Self {
        let (read_half, write_half) = stream.into_split();
        Self {
            conn_id,
            buffer_reader: BufReader::new(ConnRead::Plain(read_half)),
            buffer_writer: BufWriter::new(ConnWrite::Plain(write_half)),
            pool,
            ssl_done: false,
            gss_done: false,
            //todo:: pass this from parent config
            required_tls: false,
            frontend_tls,
            protocol_version: None,
            params: HashMap::new(),
            user: None,
            database: None,
            replication_mode: ReplicationMode::Off,
            provider: verifier_provider,
            backend_registry: backend_pool,
            session_key_secret: None,
            backend: None,
            conn_registry,
            config,
            session_guard: None,
        }
    }

    /// Drive the connection after the startup phase.
    ///
    /// Implemented by the relay: see doc/tasks/06-relay-engine.md. The `allow` is
    /// deliberate and tracked there — the lint stays active for new code, while this
    /// known gap is visible rather than hidden.
    pub async fn handle(&mut self) -> Result<(), InternalError> {
        let Some(_permit) = self.conn_registry.try_acquire() else {
            self.send_error_message(TooManyRequest.code(), TooManyRequest.message())
                .await?;
            return Ok(());
        };

        let deadline = self.config.authentication_timeout();

        match tokio::time::timeout(deadline, self.drive_startup_until_ready()).await {
            Ok(result) => result?,
            Err(_ellapsed) => {
                self.send_error_message(AuthTimeout.code(), AuthTimeout.message())
                    .await?;

                return Ok(());
            }
        }

        //todo::relay
        Ok(())
    }

    async fn drive_startup_until_ready(&mut self) -> Result<(), InternalError> {
        loop {
            match self.handle_startup().await {
                Ok(StartupOutCome::Continued) => {
                    continue;
                }
                Ok(StartupOutCome::Ready) => {
                    break;
                }
                Ok(StartupOutCome::Close) => {
                    return Ok(());
                }
                Err(ProxyError::Internal(err)) => return Err(err),
                Err(ProxyError::ConnectionError(err)) => {
                    // The handler did not write anything; the driver owns the
                    // single ErrorResponse for a startup failure, then closes.
                    self.send_error_message(err.code(), err.message()).await?;
                    return Ok(());
                }
            };
        }

        Ok(())
    }

    pub async fn handle_startup(&mut self) -> Result<StartupOutCome, ProxyError> {
        let buf = self.read_startup_packet().await?;
        let mut message_reader = MessageReader::new(buf);
        let protocol_code = message_reader.read_u32()?;

        match protocol_code {
            SSL_REQUEST_CODE => {
                self.handle_ssl_request().await?;
                Ok(StartupOutCome::Continued)
            }
            GSSENC_REQUEST_CODE => {
                self.handle_gssnc_request().await?;
                Ok(StartupOutCome::Continued)
            }
            CANCEL_REQUEST_CODE => {
                self.handle_cancel_request(&mut message_reader)?;
                // A cancel connection is a dead end: no auth, no response.
                Ok(StartupOutCome::Close)
            }
            PROTOCOL_VERSION_NUMBER => {
                if self.required_tls && !self.ssl_done {
                    return Err(connection_error(TlsRequired));
                }

                self.handle_startup_packet(protocol_code, &mut message_reader)
                    .await
            }
            // Any code that is not a magic request code is a StartupMessage
            // carrying a protocol version. Phase 1 speaks 3.0 only and rejects
            // everything else with PostgreSQL's exact wording (§3.2).
            invalid_version => Err(protocol_error(
                SQLSTATE_FEATURE_NOT_SUPPORTED,
                unsupported_protocol_message(invalid_version),
            )),
        }
    }

    pub async fn send_error_message(
        &mut self,
        code: &str,
        message: &str,
    ) -> Result<(), InternalError> {
        self.write_message(MSG_ERROR, &prepare_error_buf("FATAL", code, message))
            .await?;
        Ok(())
    }

    async fn handle_startup_packet(
        &mut self,
        protocol_version: u32,
        message_reader: &mut MessageReader,
    ) -> Result<StartupOutCome, ProxyError> {
        self.protocol_version = Some(protocol_version);

        let mut saw_terminator = false;
        while message_reader.remaining() > 0 {
            let key = message_reader.read_string()?;

            if key.is_empty() {
                saw_terminator = true;
                break;
            }

            let value = message_reader.read_string()?;
            self.params.insert(key, value);
        }

        if !saw_terminator || message_reader.remaining() != 0 {
            return Err(connection_error(InvalidStartupLayout));
        }

        let option = self.params.get("options");

        if let Some(value) = option {
            let mut parsed = parse_options(value.to_string())?;
            parsed.remove("replication");
            self.params.extend(parsed);
            self.params.remove("options");
        }

        let user = self
            .params
            .get("user")
            .map(|s| s.as_str())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| connection_error(MissingUser))?;

        self.user = Some(user.to_owned());
        self.database = Some(
            self.params
                .get("database")
                .filter(|d| !d.is_empty())
                .cloned()
                .unwrap_or_else(|| user.to_owned()),
        );

        if let Some(value) = self.params.get("replication") {
            let replication_mode = parse_replication_mode(value.to_string())?;
            self.replication_mode = replication_mode;
        }

        let client_key = self.handle_authentication().await?;

        if client_key.is_none() {
            // Rejected: `handle_authentication` already wrote the
            // ErrorResponse, so the driver must not send a second one. Close.
            return Ok(StartupOutCome::Close);
        }

        // todo:: the stub backend is replaced by the real link.
        let backend = Arc::new(Backend::default());

        let mut registered = None;
        for _ in 0..64 {
            let candidate = SessionKeySecret::new();
            match self
                .backend_registry
                .register(Arc::clone(&backend), self.conn_id, candidate)
            {
                Ok(guard) => {
                    registered = Some((candidate, guard));
                    break;
                }
                Err(_) => continue,
            }
        }

        let (session_key_secret, guard) =
            registered.ok_or_else(|| connection_error(InvalidState))?;

        self.backend = Some(backend);
        self.session_key_secret = Some(session_key_secret);
        self.session_guard = Some(guard);

        self.send_parameter_status().await?;
        self.send_key_secret().await?;
        self.send_ready_signal().await?;

        Ok(StartupOutCome::Ready)
    }

    /// Route a `CancelRequest` to the session it names.
    ///
    /// Implemented by the session registry: see doc/tasks/09-session-registry.md.
    fn handle_cancel_request(
        &mut self,
        message_reader: &mut MessageReader,
    ) -> Result<(), ProxyError> {
        if message_reader.remaining() != 8 {
            return Err(connection_error(InvalidMessageLength));
        }

        let pid = message_reader.read_u32()? as i32;
        let secret = message_reader.read_u32()? as i32;

        let session_key_secret = SessionKeySecret { key: pid, secret };

        match self.backend_registry.lookup_by_key(session_key_secret) {
            Some(_backend) => {
                //todo
            }
            None => tracing::debug!(
                session_pid = pid,
                "cancel request for an unknown or stale session; ignoring"
            ),
        }

        Ok(())
    }

    async fn handle_gssnc_request(&mut self) -> Result<(), ProxyError> {
        if self.gss_done {
            return Err(connection_error(GssAlreadyDone));
        }
        self.gss_done = true;

        self.buffer_writer
            .write_all(b"N")
            .await
            .map_err(ProxyError::internal)?;

        self.buffer_writer
            .flush()
            .await
            .map_err(ProxyError::internal)?;

        Ok(())
    }
    async fn handle_ssl_request(&mut self) -> Result<(), ProxyError> {
        if self.ssl_done {
            return Err(connection_error(TlsAlreadyDone));
        }
        self.ssl_done = true;

        if self.frontend_tls.is_some() {
            // Offer TLS: the client expects 'S' and then runs the
            // handshake on this socket.
            self.buffer_writer
                .write_all(b"S")
                .await
                .map_err(ProxyError::internal)?;
            self.buffer_writer
                .flush()
                .await
                .map_err(ProxyError::internal)?;
            self.promote_to_tls().await?;
        } else {
            // No TLS support configured: decline and keep the
            // connection in plaintext.
            self.buffer_writer
                .write_all(b"N")
                .await
                .map_err(ProxyError::internal)?;
            self.buffer_writer
                .flush()
                .await
                .map_err(ProxyError::internal)?;
        }

        Ok(())
    }

    async fn promote_to_tls(&mut self) -> Result<(), ProxyError> {
        let reader = std::mem::replace(&mut self.buffer_reader, BufReader::new(ConnRead::Empty));
        let writer = std::mem::replace(&mut self.buffer_writer, BufWriter::new(ConnWrite::Empty));

        let ConnRead::Plain(read_half) = reader.into_inner() else {
            // The `ssl_done` guard should make this unreachable, but a panic here
            // would take down the whole session task. Report it as a protocol-level
            // error instead, so one connection fails loudly and the rest survive.
            return Err(connection_error(InvalidData));
        };

        let ConnWrite::Plain(write_half) = writer.into_inner() else {
            return Err(connection_error(InvalidData));
        };

        let tcp = read_half
            .reunite(write_half)
            .map_err(ProxyError::internal)?;

        let tls_acceptor = self
            .frontend_tls
            .as_ref()
            .ok_or("TLS acceptor not set")
            .map_err(ProxyError::internal)?;

        let tls = tls_acceptor
            .acceptor
            .accept(tcp)
            .await
            .map_err(ProxyError::internal)?;

        let (read_half, write_half) = tokio::io::split(tls);
        self.buffer_reader = BufReader::new(ConnRead::Tls(read_half));
        self.buffer_writer = BufWriter::new(ConnWrite::Tls(write_half));
        Ok(())
    }

    pub async fn read_message_length(&mut self) -> Result<usize, ProxyError> {
        let mut hdr = [0u8; 4];
        self.buffer_reader
            .read_exact(&mut hdr)
            .await
            .map_err(|err| ProxyError::Internal(Box::new(err)))?;
        let len = u32::from_be_bytes(hdr) as usize;

        if len < 4 {
            return Err(connection_error(InvalidMessageLength));
        }

        Ok(len - 4)
    }

    pub async fn read_startup_packet(&mut self) -> Result<PooledBytes, ProxyError> {
        let length = self.read_message_length().await?;

        if length + 4 > self.config.max_startup_bytes() {
            return Err(connection_error(FirstMessageTooBig));
        }

        match self.read_message_body(length).await? {
            Some(message) => Ok(message),
            None => Err(connection_error(EmptyMessageBody)),
        }
    }

    pub async fn read_message_body(
        &mut self,
        length: usize,
    ) -> Result<Option<PooledBytes>, ProxyError> {
        if length == 0 {
            return Ok(None);
        }

        if length > self.pool.max_capacity() {
            return Err(connection_error(MessageTooLarge));
        }

        let pool = self.pool.clone();

        let mut buf = pool.get(length);

        self.buffer_reader
            .read_exact(&mut buf)
            .await
            .map_err(ProxyError::internal)?;

        Ok(Some(buf))
    }

    /// Write raw bytes to the peer over the current transport (plain or TLS)
    /// and flush. Used by the proxy to send protocol messages to the client.
    pub async fn write_raw(&mut self, data: &[u8]) -> Result<(), InternalError> {
        self.buffer_writer.write_all(data).await?;
        self.buffer_writer.flush().await?;
        Ok(())
    }

    pub async fn write_message(
        &mut self,
        message_type: u8,
        body: &[u8],
    ) -> Result<(), InternalError> {
        let len = (body.len() + 4) as u32;
        self.buffer_writer.write_all(&[message_type]).await?;
        self.buffer_writer.write_all(&len.to_be_bytes()).await?;
        self.buffer_writer.write_all(body).await?;
        self.buffer_writer.flush().await?;

        Ok(())
    }

    async fn send_parameter_status(&mut self) -> Result<(), ProxyError> {
        let backend = match self.backend.as_ref() {
            Some(value) => value,
            None => {
                return Err(connection_error(InvalidData));
            }
        };

        let parameters = backend.get_param_status_values();

        for (name, value) in parameters {
            let mut buf = Vec::new();
            put_cstr(&mut buf, &name);
            put_cstr(&mut buf, &value);

            self.write_message(MSG_PARAMETER_STATUS, &buf)
                .await
                .map_err(ProxyError::internal)?;
        }

        Ok(())
    }

    async fn send_key_secret(&mut self) -> Result<(), ProxyError> {
        let session_key_secret = match self.session_key_secret {
            Some(value) => value,
            None => {
                return Err(connection_error(InvalidState));
            }
        };

        let mut buf = Vec::with_capacity(8);
        buf.extend_from_slice(&(session_key_secret.key as u32).to_be_bytes());
        buf.extend_from_slice(&(session_key_secret.secret as u32).to_be_bytes());

        self.write_message(MSG_KEY_SECRET, &buf)
            .await
            .map_err(ProxyError::internal)?;
        Ok(())
    }

    async fn send_ready_signal(&mut self) -> Result<(), ProxyError> {
        let buf = vec![b'I'];
        self.write_message(MSG_READY_ACCEPT_QUERY, &buf)
            .await
            .map_err(ProxyError::internal)?;
        Ok(())
    }
}

/// PostgreSQL's message for a frontend protocol version we do not speak.
///
/// The wording is load-bearing: clients and the acceptance suite grep for it,
/// so the `major.minor` spelling and punctuation must match (§3.2, §4.3).
#[must_use]
fn unsupported_protocol_message(version: u32) -> String {
    let (major, minor) = (version >> 16, version & 0xffff);
    format!("unsupported frontend protocol {major}.{minor}: server supports 3.0 to 3.0")
}

fn put_cstr(buf: &mut Vec<u8>, value: &str) {
    buf.extend_from_slice(value.as_bytes());
    buf.push(b'\0');
}

fn prepare_error_buf(severity: &str, code: &str, message: &str) -> Vec<u8> {
    let mut body = Vec::new();

    body.push(b'S');
    put_cstr(&mut body, severity);
    body.push(b'V');
    put_cstr(&mut body, severity);
    body.push(b'C');
    put_cstr(&mut body, code);
    body.push(b'M');
    put_cstr(&mut body, message);
    body.push(b'\0');
    body
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_version_message_matches_postgres() {
        assert_eq!(
            unsupported_protocol_message(4 << 16),
            "unsupported frontend protocol 4.0: server supports 3.0 to 3.0"
        );
        assert_eq!(
            unsupported_protocol_message((3 << 16) | 2),
            "unsupported frontend protocol 3.2: server supports 3.0 to 3.0"
        );
    }

    #[test]
    fn error_body_carries_severity_code_and_message_fields() {
        let body = prepare_error_buf("FATAL", "53300", "sorry, too many clients already");

        assert_eq!(body.first(), Some(&b'S'));
        assert_eq!(body.last(), Some(&0));
        assert_eq!(body.iter().filter(|&&byte| byte == b'C').count(), 1);
        assert_eq!(body.iter().filter(|&&byte| byte == b'M').count(), 1);
    }
}
