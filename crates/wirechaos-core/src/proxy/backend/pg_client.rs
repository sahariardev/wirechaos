use crate::proxy::backend::error::PgError;
use crate::proxy::backend::scram_client::ScramClient;
use crate::proxy::backend::timeout_stream::TimeoutStream;
use crate::proxy::buffer_pool::{MultiBufferPool, PooledBytes};
use crate::proxy::conn::{PROTOCOL_VERSION_NUMBER, SSL_REQUEST_CODE};
use crate::proxy::conn_read::ConnRead;
use crate::proxy::conn_write::ConnWrite;
use crate::proxy::packet::MessageReader;
use crate::proxy::wire_util::put_cstr;
use rustls::pki_types::ServerName;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

pub struct PgClient {
    pool: Arc<MultiBufferPool>,
    stream: TimeoutStream,
    parameters_status_values: HashMap<String, String>,
}

pub struct PgConfig {
    client_key: Vec<u8>,
    server_key: Vec<u8>,
    stored_key: Vec<u8>,
    user: String,
    database: String,
    timeout: Duration,
    host: String,
    port: u16,
    tls_domain: Option<String>,
    salt: Vec<u8>,
    iterations: u32,
}

impl PgConfig {
    #[allow(
        clippy::too_many_arguments,
        reason = "the fields mirror the authenticated session's SCRAM material and the backend target one-to-one"
    )]
    #[must_use]
    pub fn new(
        client_key: Vec<u8>,
        server_key: Vec<u8>,
        stored_key: Vec<u8>,
        user: String,
        database: String,
        timeout: Duration,
        host: String,
        port: u16,
        tls_domain: Option<String>,
        salt: Vec<u8>,
        iterations: u32,
    ) -> Self {
        Self {
            client_key,
            server_key,
            stored_key,
            user,
            database,
            timeout,
            host,
            port,
            tls_domain,
            salt,
            iterations,
        }
    }
}

impl PgClient {
    pub async fn connect(config: PgConfig, pool: Arc<MultiBufferPool>) -> Result<Self, PgError> {
        let addr = format!("{}:{}", config.host, config.port);
        let raw_tcp = tokio::time::timeout(config.timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| PgError::Timeout)??;

        let stream = Self::try_tls(raw_tcp, &config).await?;

        let mut client = Self {
            stream,
            pool,
            parameters_status_values: HashMap::new(),
        };
        client.send_startup(&config.user, &config.database).await?;
        client.handle_startup_handshake(&config).await?;

        Ok(client)
    }

    /// The `ParameterStatus` values sent by the backend during startup.
    #[must_use]
    pub fn take_parameter_status_values(&mut self) -> HashMap<String, String> {
        std::mem::take(&mut self.parameters_status_values)
    }

    async fn handle_startup_handshake(&mut self, config: &PgConfig) -> Result<(), PgError> {
        loop {
            let (tag, payload_len) = self.read_next_header().await?;
            let payload = self.read_frame_payload(payload_len as usize).await?;
            let mut message = MessageReader::new(payload);

            match tag {
                b'R' => {
                    let auth_type = message
                        .read_u32()
                        .map_err(|_| PgError::Protocol("invalid auth type".to_owned()))?;
                    match auth_type {
                        0 => {} //AuthenticationOk,
                        10 => {
                            self.handle_scram_auth(config).await?;
                        }
                        other => {
                            return Err(PgError::Protocol(format!("Unexpected tag: {:?}", other)))
                        }
                    }
                }
                b'K' => {} //BackendKeyData,
                b'S' => {
                    let name = message.read_string().map_err(|_| {
                        PgError::Protocol("invalid parameter status name".to_owned())
                    })?;
                    let value = message.read_string().map_err(|_| {
                        PgError::Protocol("invalid parameter status value".to_owned())
                    })?;
                    self.parameters_status_values.insert(name, value);
                }
                b'Z' => break,
                other => return Err(PgError::Protocol(format!("Unexpected tag: {:?}", other))),
            }
        }

        Ok(())
    }

    async fn handle_scram_auth(&mut self, config: &PgConfig) -> Result<(), PgError> {
        let mut scram = ScramClient::new(
            config.client_key.clone(),
            config.server_key.clone(),
            config.stored_key.clone(),
        );

        let client_first = scram.client_first_message();

        let mut sasl_body = Vec::new();
        sasl_body.extend_from_slice(b"SCRAM-SHA-256\0");
        sasl_body.extend_from_slice(&(client_first.len() as i32).to_be_bytes());
        sasl_body.extend_from_slice(client_first.as_bytes());
        self.send_frame(b'p', &sasl_body).await?;

        let (tag, len) = self.read_next_header().await?;
        let payload = self.read_frame_payload(len as usize).await?;
        let mut message = MessageReader::new(payload);

        if tag != b'R' {
            return Err(PgError::Protocol(format!("Unexpected tag: {:?}", tag)));
        }

        let auth_type = message
            .read_u32()
            .map_err(|_| PgError::Protocol("invalid length".to_owned()))?;
        if auth_type != 11 {
            return Err(PgError::Protocol(format!(
                "Expected AuthenticationSASLContinue, got {auth_type}"
            )));
        }
        let server_first_len = message.remaining() as i32;
        let server_first = message
            .read_string_fixed_size(server_first_len)
            .map_err(|_| PgError::Protocol("invalid server first".to_owned()))?;

        let client_final =
            scram.client_final_message(&server_first, &config.salt, config.iterations)?;

        self.send_frame(b'p', client_final.as_bytes()).await?;

        let (tag, len) = self.read_next_header().await?;
        let payload = self.read_frame_payload(len as usize).await?;
        let mut message = MessageReader::new(payload);

        if tag != b'R' {
            return Err(PgError::Protocol("Expected AuthenticationSASLFinal".into()));
        }
        let auth_type = message
            .read_u32()
            .map_err(|_| PgError::Protocol("invalid length".to_owned()))?;
        if auth_type != 12 {
            return Err(PgError::Protocol(format!(
                "Expected AuthenticationSASLFinal, got {auth_type}"
            )));
        }

        let server_final_len = message.remaining() as i32;
        let server_final = message
            .read_string_fixed_size(server_final_len)
            .map_err(|_| PgError::Protocol("invalid server final".to_owned()))?;

        scram.verify_server_final(&server_final)?;

        let (tag, len) = self.read_next_header().await?;
        let payload = self.read_frame_payload(len as usize).await?;
        let mut message = MessageReader::new(payload);

        if tag != b'R' {
            return Err(PgError::Protocol("Expected AuthenticationOk".into()));
        }
        let auth_type = message
            .read_u32()
            .map_err(|_| PgError::Protocol("invalid length".to_owned()))?;
        if auth_type != 0 {
            return Err(PgError::Protocol(format!(
                "Expected AuthenticationOk, got {auth_type}"
            )));
        }

        Ok(())
    }

    async fn read_frame_payload(&mut self, payload_len: usize) -> Result<PooledBytes, PgError> {
        let mut buff = self.pool.get(payload_len);
        self.stream.read_exact(&mut buff).await?;

        Ok(buff)
    }

    async fn send_startup(&mut self, user: &str, database: &str) -> Result<(), PgError> {
        let mut message = Vec::new();
        message.extend_from_slice(&PROTOCOL_VERSION_NUMBER.to_be_bytes());
        put_cstr(&mut message, "user");
        put_cstr(&mut message, user);
        put_cstr(&mut message, "database");
        put_cstr(&mut message, database);

        message.push(b'\0');

        let len = (4 + message.len()) as i32;
        let mut packet = Vec::with_capacity(len as usize);
        packet.extend_from_slice(&len.to_be_bytes());
        packet.extend_from_slice(message.as_slice());

        self.stream.write_all(&packet).await?;
        self.stream.flush().await
    }

    async fn read_next_header(&mut self) -> Result<(u8, i32), PgError> {
        let mut buff = [0u8; 5];
        self.stream.read_exact(&mut buff).await?;

        let tag = buff[0];
        let len = i32::from_be_bytes([buff[1], buff[2], buff[3], buff[4]]);

        if len < 4 {
            return Err(PgError::Protocol(format!("Invalid frame length: {}", len)));
        }

        //length is always 4 + message body len, hence deducting 4 to get the message body len
        Ok((tag, len - 4))
    }

    async fn send_frame(&mut self, tag: u8, body: &[u8]) -> Result<(), PgError> {
        let len = (4 + body.len()) as i32;
        let mut packet = Vec::with_capacity(1 + len as usize);
        packet.push(tag);
        packet.extend_from_slice(&len.to_be_bytes());
        packet.extend_from_slice(body);

        self.stream.write_all(&packet).await?;
        self.stream.flush().await
    }

    async fn try_tls(
        mut tcp_stream: TcpStream,
        config: &PgConfig,
    ) -> Result<TimeoutStream, PgError> {
        Ok(match config.tls_domain.as_deref() {
            Some(domain) => {
                let server_supports_tls = tokio::time::timeout(config.timeout, async {
                    tcp_stream.write_all(&8u32.to_be_bytes()).await?;
                    tcp_stream
                        .write_all(&SSL_REQUEST_CODE.to_be_bytes())
                        .await?;
                    tcp_stream.flush().await?;

                    let mut buf = [0u8; 1];
                    tcp_stream.read_exact(&mut buf).await?;

                    // Anything other than 'S' means the server refused TLS, so
                    // fall back to a plaintext connection.
                    Ok::<bool, std::io::Error>(buf[0] == b'S')
                })
                .await
                .map_err(|_| PgError::Timeout)??;

                if server_supports_tls {
                    let mut root_store = rustls::RootCertStore::empty();
                    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

                    let tls_config = rustls::ClientConfig::builder()
                        .with_root_certificates(root_store)
                        .with_no_client_auth();

                    let connector = TlsConnector::from(Arc::new(tls_config));

                    let server_name = ServerName::try_from(domain.to_owned()).map_err(|_| {
                        PgError::Protocol(format!("invalid domain name: {}", domain))
                    })?;

                    let tls_stream = tokio::time::timeout(
                        config.timeout,
                        connector.connect(server_name, tcp_stream),
                    )
                    .await
                    .map_err(|_| PgError::Timeout)??;

                    let (read_half, write_half) = tokio::io::split(tls_stream);
                    TimeoutStream::new(
                        BufReader::new(ConnRead::ClientTls(read_half)),
                        BufWriter::new(ConnWrite::ClientTls(write_half)),
                        config.timeout,
                    )
                } else {
                    plain_stream(tcp_stream, config.timeout)
                }
            }
            None => plain_stream(tcp_stream, config.timeout),
        })
    }

    #[cfg(test)]
    pub(crate) fn for_test() -> Self {
        Self {
            pool: MultiBufferPool::new(16, 16, 0),
            stream: TimeoutStream::new(
                BufReader::new(ConnRead::Empty),
                BufWriter::new(ConnWrite::Empty),
                Duration::from_secs(0),
            ),
            parameters_status_values: HashMap::new(),
        }
    }
}

fn plain_stream(raw_tcp: TcpStream, timeout: Duration) -> TimeoutStream {
    let (read_half, write_half) = raw_tcp.into_split();
    TimeoutStream::new(
        BufReader::new(ConnRead::Plain(read_half)),
        BufWriter::new(ConnWrite::Plain(write_half)),
        timeout,
    )
}
