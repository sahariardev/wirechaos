use crate::proxy::auth::verifier::VerifierProvider;
use crate::proxy::backend::connection::Backend;
use crate::proxy::backend::pool::BackendPool;
use crate::proxy::backend::session_key_secret::{self, SessionKeySecret};
use crate::proxy::buffer_pool::{MultiBufferPool, PooledBytes};
use crate::proxy::conn_read::ConnRead;
use crate::proxy::conn_write::ConnWrite;
use crate::proxy::packet::MessageReader;
use crate::proxy::replication_mode::ReplicationMode;
use crate::proxy::startup_config_parse_util::{parse_options, parse_replication_mode};
use crate::proxy::tls::FrontendTls;
use crate::proxy::ProxyError;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io;
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
    pub backend_pool: BackendPool,
    pub session_key_secret: Option<SessionKeySecret>,
    pub backend: Option<Arc<Backend>>,
}

const MAX_STARTUP_PACKET_LENGTH: u32 = 10000;
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

impl<V: VerifierProvider> Conn<V> {
    pub fn new(
        conn_id: i32,
        stream: TcpStream,
        pool: Arc<MultiBufferPool>,
        frontend_tls: Option<FrontendTls>,
        verifier_provider: V,
        backend_pool: BackendPool,
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
            backend_pool,
            session_key_secret: None,
            backend: None,
        }
    }

    /// Drive the connection after the startup phase.
    ///
    /// Implemented by the relay: see doc/tasks/06-relay-engine.md. The `allow` is
    /// deliberate and tracked there — the lint stays active for new code, while this
    /// known gap is visible rather than hidden.
    #[allow(clippy::todo)]
    pub async fn handle(&mut self) -> Result<(), ProxyError> {
        todo!("handle message: implemented in task 6 (relay engine)")
    }

    pub async fn handle_startup(&mut self) -> Result<(), ProxyError> {
        let buf = self.read_startup_packet().await?;
        let mut message_reader = MessageReader::new(buf);
        let protocol_code = message_reader.read_u32()?;
        match protocol_code {
            SSL_REQUEST_CODE => {
                self.handle_ssl_request().await?;
            }
            GSSENC_REQUEST_CODE => {
                self.handle_gssnc_request().await?;
            }
            CANCEL_REQUEST_CODE => {
                self.handle_cancel_request(&mut message_reader)?;
            }

            PROTOCOL_VERSION_NUMBER => {
                if self.required_tls && !self.ssl_done {
                    return Err(Box::new(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "TLS is required but the client did not request it",
                    )));
                }

                self.handle_startup_packet(protocol_code, &mut message_reader)
                    .await?;
            }
            _ => {}
        }

        Ok(())
    }

    async fn handle_startup_packet(
        &mut self,
        protocol_version: u32,
        message_reader: &mut MessageReader,
    ) -> Result<(), ProxyError> {
        self.protocol_version = Some(protocol_version);

        while message_reader.remaining() > 0 {
            let key = message_reader.read_string()?;

            if key.is_empty() {
                break;
            }

            let value = message_reader.read_string()?;
            self.params.insert(key, value);
        }

        let option = self.params.get("options");

        if let Some(value) = option {
            let mut parsed = parse_options(value.to_string())?;
            parsed.remove("replication");
            self.params.extend(parsed);
            self.params.remove("options");
        }

        if let Some(value) = self.params.get("user") {
            self.user = Some(value.to_string());
            self.database = Some(value.to_string());
        }

        if let Some(value) = self.params.get("database") {
            if !value.is_empty() {
                self.database = Some(value.to_string());
            }
        }

        if let Some(value) = self.params.get("replication") {
            let replication_mode = parse_replication_mode(value.to_string())?;
            self.replication_mode = replication_mode;
        }

        let client_key = self.handle_authentication().await?;

        if client_key.is_none() {
            // Rejected: the client has already been told why, so this is not a
            // fault to report — it is the end of the startup phase. Returning
            // here keeps `handle` (the relay) from ever seeing a connection
            // whose client never authenticated.
            //
            // todo:: close the socket explicitly, and let the session driver
            // distinguish "rejected" from "faulted" once it exists
            // (doc/tasks/06-relay-engine.md).
            return Err(Box::new(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "authentication rejected",
            )));
        }

        //todo:: using dummy backend now, in future we will add a proper backend
        let session_key_secret = SessionKeySecret::new(self.conn_id);
        let backend = Arc::new(Backend::default());

        self.backend = Some(Arc::clone(&backend));
        self.session_key_secret = Some(session_key_secret);
        self.backend_pool
            .add_new_backend(backend, self.conn_id, session_key_secret);

        self.send_parameter_status().await?;
        self.send_key_secret().await?;
        self.send_ready_signal().await?;

        Ok(())
    }

    /// Route a `CancelRequest` to the session it names.
    ///
    /// Implemented by the session registry: see doc/tasks/09-session-registry.md.
    #[allow(clippy::todo)]
    fn handle_cancel_request(
        &mut self,
        _message_reader: &mut MessageReader,
    ) -> Result<(), ProxyError> {
        todo!("handle cancel request: implemented in task 9 (session registry)")
    }
    async fn handle_gssnc_request(&mut self) -> Result<(), ProxyError> {
        if self.gss_done {
            return Err(Box::from("GSSENC Request is already done"));
        }
        self.gss_done = true;

        self.buffer_writer.write_all(b"N").await?;
        self.buffer_writer.flush().await?;

        Ok(())
    }
    async fn handle_ssl_request(&mut self) -> Result<(), ProxyError> {
        if self.ssl_done {
            return Err(Box::from("SSL Request is already done"));
        }
        self.ssl_done = true;

        if self.frontend_tls.is_some() {
            // Offer TLS: the client expects 'S' and then runs the
            // handshake on this socket.
            self.buffer_writer.write_all(b"S").await?;
            self.buffer_writer.flush().await?;
            self.promote_to_tls().await?;
        } else {
            // No TLS support configured: decline and keep the
            // connection in plaintext.
            self.buffer_writer.write_all(b"N").await?;
            self.buffer_writer.flush().await?;
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
            return Err(Box::new(io::Error::new(
                io::ErrorKind::InvalidData,
                "TLS promotion requested on a connection that is not plaintext",
            )));
        };

        let ConnWrite::Plain(write_half) = writer.into_inner() else {
            return Err(Box::new(io::Error::new(
                io::ErrorKind::InvalidData,
                "TLS promotion requested on a connection that is not plaintext",
            )));
        };

        let tcp = read_half.reunite(write_half)?;
        let tls_acceptor = self.frontend_tls.as_ref().ok_or("TLS acceptor not set")?;

        let tls = tls_acceptor.acceptor.accept(tcp).await?;

        let (read_half, write_half) = tokio::io::split(tls);
        self.buffer_reader = BufReader::new(ConnRead::Tls(read_half));
        self.buffer_writer = BufWriter::new(ConnWrite::Tls(write_half));
        Ok(())
    }

    pub async fn read_message_length(&mut self) -> Result<usize, ProxyError> {
        let mut hdr = [0u8; 4];
        self.buffer_reader.read_exact(&mut hdr).await?;
        let len = u32::from_be_bytes(hdr) as usize;

        if len < 4 {
            return Err(Box::new(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid message length: {}", len),
            )));
        }

        Ok(len - 4)
    }

    pub async fn read_startup_packet(&mut self) -> Result<PooledBytes, ProxyError> {
        let length = self.read_message_length().await?;

        if length > MAX_STARTUP_PACKET_LENGTH as usize {
            return Err(Box::new(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid message length: {}", length),
            )));
        }

        match self.read_message_body(length).await? {
            Some(message) => Ok(message),
            None => Err(Box::new(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Message body is empty",
            ))),
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
            return Err(Box::new(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Invalid message length: {} exceeds buffer pool capacity {}",
                    length,
                    self.pool.max_capacity()
                ),
            )));
        }

        let pool = self.pool.clone();

        let mut buf = pool.get(length);

        self.buffer_reader.read_exact(&mut buf).await?;

        Ok(Some(buf))
    }

    /// Write raw bytes to the peer over the current transport (plain or TLS)
    /// and flush. Used by the proxy to send protocol messages to the client.
    pub async fn write_raw(&mut self, data: &[u8]) -> Result<(), ProxyError> {
        self.buffer_writer.write_all(data).await?;
        self.buffer_writer.flush().await?;
        Ok(())
    }

    pub async fn write_message(&mut self, message_type: u8, body: &[u8]) -> Result<(), ProxyError> {
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
                return Err(Box::new(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Invalid data",
                )));
            }
        };

        if backend.get_param_status_values().is_empty() {
            return Ok(());
        }

        for (name, value) in backend.get_param_status_values() {
            let mut buf = Vec::new();
            put_cstr(&mut buf, &name);
            put_cstr(&mut buf, &value);

            self.write_message(MSG_PARAMETER_STATUS, &buf).await?;
        }

        Ok(())
    }

    async fn send_key_secret(&mut self) -> Result<(), ProxyError> {
        let session_key_secret = match self.session_key_secret {
            Some(value) => value,
            None => {
                return Err(Box::new(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Invalid data",
                )));
            }
        };

        let mut buf = Vec::new();
        put_cstr(&mut buf, &session_key_secret.key.to_string());
        put_cstr(&mut buf, &session_key_secret.secret.to_string());

        self.write_message(MSG_KEY_SECRET, &buf).await?;
        Ok(())
    }

    async fn send_ready_signal(&mut self) -> Result<(), ProxyError> {
        let buf = vec![b'I', b'\0'];
        self.write_message(MSG_READY_ACCEPT_QUERY, &buf).await?;
        Ok(())
    }
}

fn put_cstr(buf: &mut Vec<u8>, value: &str) {
    buf.extend_from_slice(value.as_bytes());
    buf.push(b'\0');
}
