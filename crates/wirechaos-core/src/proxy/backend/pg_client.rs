use crate::proxy::backend::error::PgError;
use crate::proxy::backend::timeout_stream::TimeoutStream;
use crate::proxy::buffer_pool::MultiBufferPool;
use crate::proxy::conn::SSL_REQUEST_CODE;
use crate::proxy::conn_read::ConnRead;
use crate::proxy::conn_write::ConnWrite;
use rustls::pki_types::ServerName;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

pub struct PgClient {
    pool: Arc<MultiBufferPool>,
    stream: TimeoutStream,
}

pub struct PgConfig {
    client_key: String,
    server_key: String,
    stored_key: String,
    user: String,
    database: String,
    timeout: Duration,
    host: String,
    port: u16,
    tls_domain: Option<String>,
}

impl PgClient {
    pub async fn connect(config: PgConfig, pool: Arc<MultiBufferPool>) -> Result<Self, PgError> {
        let addr = format!("{}:{}", config.host, config.port);
        let raw_tcp = tokio::time::timeout(config.timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| PgError::Timeout)??;

        let stream = Self::try_tls(raw_tcp, &config).await?;

        let mut client = Self { stream, pool };
        client.send_startup(&config.user, &config.database).await?;
        //handle scram client auth

        Ok(client)
    }

    async fn send_startup(&mut self, user: &str, database: &str) -> Result<(), PgError> {
        todo!("implement this")
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
}

fn plain_stream(raw_tcp: TcpStream, timeout: Duration) -> TimeoutStream {
    let (read_half, write_half) = raw_tcp.into_split();
    TimeoutStream::new(
        BufReader::new(ConnRead::Plain(read_half)),
        BufWriter::new(ConnWrite::Plain(write_half)),
        timeout,
    )
}
