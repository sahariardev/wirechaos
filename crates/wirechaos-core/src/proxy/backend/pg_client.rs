use crate::proxy::backend::error::PgError;
use crate::proxy::backend::scram_client::ScramClient;
use crate::proxy::backend::timeout_stream::TimeoutStream;
use crate::proxy::backend::{
    md5_response, parse_sasl_mechanisms, select_mechanism, BackendKeyData, SaslMechanism,
    StartupNotification,
};
use crate::proxy::buffer_pool::{MultiBufferPool, PooledBytes};
use crate::proxy::config::{BackendTlsConfig, BackendTlsMode};
use crate::proxy::conn::{PROTOCOL_VERSION_NUMBER, SSL_REQUEST_CODE};
use crate::proxy::conn_read::ConnRead;
use crate::proxy::conn_write::ConnWrite;
use crate::proxy::packet::MessageReader;
use crate::proxy::tls::CertHash;
use crate::proxy::wire_util::put_cstr;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, RootCertStore, SignatureScheme};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::warn;
use zeroize::Zeroizing;

pub struct PgClient {
    pool: Arc<MultiBufferPool>,
    stream: TimeoutStream,
    startup_notifications: Vec<StartupNotification>,
    backend_key: Option<BackendKeyData>,
    ready_status: Option<u8>,
    server_signature_verified: bool,
    peer_cert_hash: Option<CertHash>,
    host: String,
    port: u16,
    connect_timeout: Duration,
}

pub struct PgConfig {
    client_key: Option<Zeroizing<Vec<u8>>>,
    server_key: Option<Zeroizing<Vec<u8>>>,
    stored_key: Option<Zeroizing<Vec<u8>>>,
    password: Option<Zeroizing<Vec<u8>>>,
    user: String,
    database: String,
    connect_timeout: Duration,
    startup_timeout: Duration,
    host: String,
    port: u16,
    tls: BackendTlsConfig,
    salt: Vec<u8>,
    iterations: u32,
    startup_params: Vec<(String, String)>,
}

impl PgConfig {
    #[allow(
        clippy::too_many_arguments,
        reason = "the fields mirror the authenticated session's SCRAM material and the backend target one-to-one"
    )]
    #[must_use]
    pub fn new(
        client_key: Option<Vec<u8>>,
        server_key: Option<Vec<u8>>,
        stored_key: Option<Vec<u8>>,
        password: Option<Vec<u8>>,
        user: String,
        database: String,
        connect_timeout: Duration,
        startup_timeout: Duration,
        host: String,
        port: u16,
        tls: BackendTlsConfig,
        salt: Vec<u8>,
        iterations: u32,
        startup_params: Vec<(String, String)>,
    ) -> Self {
        Self {
            client_key: client_key.map(Zeroizing::new),
            server_key: server_key.map(Zeroizing::new),
            stored_key: stored_key.map(Zeroizing::new),
            password: password.map(Zeroizing::new),
            user,
            database,
            connect_timeout,
            startup_timeout,
            host,
            port,
            tls,
            salt,
            iterations,
            startup_params,
        }
    }

    fn tls_server_name(&self) -> Option<String> {
        self.tls.domain.clone().or_else(|| Some(self.host.clone()))
    }
}

impl PgClient {
    pub async fn connect(config: PgConfig, pool: Arc<MultiBufferPool>) -> Result<Self, PgError> {
        let addr = format!("{}:{}", config.host, config.port);
        let raw_tcp = tokio::time::timeout(config.connect_timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| PgError::ConnectTimeout)??;

        let (stream, peer_cert_hash) = Self::try_tls(raw_tcp, &config).await?;

        let mut client = Self {
            stream,
            pool,
            startup_notifications: Vec::new(),
            backend_key: None,
            ready_status: None,
            server_signature_verified: false,
            peer_cert_hash,
            host: config.host.clone(),
            port: config.port,
            connect_timeout: config.connect_timeout,
        };

        client.write_startup_message(&config).await?;

        tokio::time::timeout(
            config.startup_timeout,
            client.handle_startup_handshake(&config),
        )
        .await
        .map_err(|_| PgError::StartupTimeout)??;

        Ok(client)
    }

    /// The `ParameterStatus`/`NoticeResponse` messages sent by the backend
    /// during startup, in the order they arrived.
    #[must_use]
    pub fn take_startup_notifications(&mut self) -> Vec<StartupNotification> {
        std::mem::take(&mut self.startup_notifications)
    }

    #[must_use]
    pub fn backend_key(&self) -> Option<BackendKeyData> {
        self.backend_key
    }

    #[must_use]
    pub fn ready_status(&self) -> Option<u8> {
        self.ready_status
    }

    #[must_use]
    pub fn server_signature_verified(&self) -> bool {
        self.server_signature_verified
    }

    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    #[must_use]
    pub fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    async fn handle_startup_handshake(&mut self, config: &PgConfig) -> Result<(), PgError> {
        loop {
            let (tag, payload_len) = self.read_message_header().await?;
            let payload = self.read_message_body(payload_len).await?;

            match tag {
                b'R' => {
                    if payload.len() < 4 {
                        return Err(PgError::Protocol(
                            "authentication message is shorter than its sub-code".to_owned(),
                        ));
                    }

                    let auth_type = u32::from_be_bytes(
                        payload[..4]
                            .try_into()
                            .map_err(|_| PgError::Protocol("invalid auth type".to_owned()))?,
                    );

                    match auth_type {
                        0 => {} // AuthenticationOk: consumed, the client had its own.
                        3 => self.handle_cleartext(config).await?,
                        5 => self.handle_md5(config, &payload[4..]).await?,
                        10 => self.handle_sasl(config, &payload[4..]).await?,
                        11 | 12 => {
                            return Err(PgError::Protocol(format!(
                                "unexpected authentication continuation ({auth_type}) before SASL started"
                            )))
                        }
                        other => {
                            return Err(PgError::UnsupportedAuth(unsupported_method_message(
                                other,
                            )))
                        }
                    }
                }
                b'S' => {
                    let mut message = MessageReader::new(payload);
                    let name = message.read_string().map_err(|_| {
                        PgError::Protocol("invalid ParameterStatus name".to_owned())
                    })?;
                    let value = message.read_string().map_err(|_| {
                        PgError::Protocol("invalid ParameterStatus value".to_owned())
                    })?;

                    self.startup_notifications
                        .push(StartupNotification::ParameterStatus(name, value));
                }
                b'N' => {
                    // Forwarded verbatim to the client by the startup driver.
                    self.startup_notifications
                        .push(StartupNotification::Notice(payload.to_vec()));
                }
                b'K' => {
                    if payload.len() != 8 {
                        return Err(PgError::Protocol(
                            "BackendKeyData body is not two Int32s".to_owned(),
                        ));
                    }

                    let pid =
                        i32::from_be_bytes(payload[0..4].try_into().map_err(|_| {
                            PgError::Protocol("invalid BackendKeyData pid".to_owned())
                        })?);
                    let secret = i32::from_be_bytes(payload[4..8].try_into().map_err(|_| {
                        PgError::Protocol("invalid BackendKeyData secret".to_owned())
                    })?);

                    self.backend_key = Some(BackendKeyData { pid, secret });
                }
                b'Z' => {
                    let status = payload.first().copied().ok_or_else(|| {
                        PgError::Protocol("ReadyForQuery has no transaction status".to_owned())
                    })?;
                    self.ready_status = Some(status);
                    break;
                }
                b'E' => {
                    let (severity, code, message) = parse_error_response(&payload);
                    return Err(PgError::Backend {
                        severity,
                        code,
                        message,
                    });
                }
                other => {
                    return Err(PgError::Protocol(format!(
                        "unexpected message {:?} during the startup phase",
                        other as char
                    )));
                }
            }
        }

        Ok(())
    }

    async fn handle_cleartext(&mut self, config: &PgConfig) -> Result<(), PgError> {
        let Some(password) = config.password.as_ref() else {
            return Err(PgError::UnsupportedAuth(
                "backend requires a cleartext password, but only a SCRAM secret is available; \
                 configure a plaintext password for this user"
                    .to_owned(),
            ));
        };

        let mut body = password.clone();
        body.push(0);

        self.write_message(b'p', &body).await
    }

    async fn handle_md5(&mut self, config: &PgConfig, body: &[u8]) -> Result<(), PgError> {
        if body.len() != 4 {
            return Err(PgError::Protocol(
                "AuthenticationMD5Password must carry a 4-byte salt".to_owned(),
            ));
        }

        let Some(password) = config.password.as_ref() else {
            return Err(PgError::UnsupportedAuth(
                "backend requires MD5 authentication, but only a SCRAM secret is available; \
                 MD5 cannot be derived from StoredKey/ServerKey, so configure a plaintext password"
                    .to_owned(),
            ));
        };

        let salt: [u8; 4] = body
            .try_into()
            .map_err(|_| PgError::Protocol("invalid MD5 salt".to_owned()))?;
        let response = md5_response(&config.user, password, &salt);

        let mut body = response.into_bytes();
        body.push(0);

        self.write_message(b'p', &body).await
    }

    async fn handle_sasl(&mut self, config: &PgConfig, body: &[u8]) -> Result<(), PgError> {
        let offered = parse_sasl_mechanisms(body);

        if offered.is_empty() {
            return Err(PgError::UnsupportedAuth(format!(
                "backend offered no supported SASL mechanism (offered: {:?})",
                lossy_mechanism_names(body)
            )));
        }

        let channel_binding_available = self.peer_cert_hash.is_some();
        let chosen = select_mechanism(
            config.tls.channel_binding,
            channel_binding_available,
            &offered,
        )?;

        let mut scram = ScramClient::new(
            config.client_key.as_ref().map(|key| key.to_vec()),
            config.server_key.as_ref().map(|key| key.to_vec()),
            config.stored_key.as_ref().map(|key| key.to_vec()),
            config.password.as_ref().map(|password| password.to_vec()),
        );

        if chosen == SaslMechanism::ScramSha256Plus {
            let cert_hash = self.peer_cert_hash.as_ref().ok_or_else(|| {
                PgError::ChannelBindingRequired(
                    "the backend selected -PLUS but no certificate hash is available".to_owned(),
                )
            })?;
            scram.use_channel_binding(cert_hash.cbind_input());
        }

        let client_first = scram.client_first_message();

        let mut sasl_body = Vec::new();
        put_cstr(&mut sasl_body, chosen.name());
        sasl_body.extend_from_slice(&(client_first.len() as i32).to_be_bytes());
        sasl_body.extend_from_slice(client_first.as_bytes());
        self.write_message(b'p', &sasl_body).await?;

        let server_first = self.read_authentication_data(11).await?;
        let server_first = String::from_utf8(server_first)
            .map_err(|_| PgError::Protocol("server-first is not UTF-8".to_owned()))?;

        let client_final =
            scram.client_final_message(&server_first, &config.salt, config.iterations)?;

        self.write_message(b'p', client_final.as_bytes()).await?;

        let server_final = self.read_authentication_data(12).await?;
        let server_final = String::from_utf8(server_final)
            .map_err(|_| PgError::Protocol("server-final is not UTF-8".to_owned()))?;

        self.server_signature_verified = scram.verify_server_final(&server_final)?;

        if !self.server_signature_verified {
            warn!(
                user = %config.user,
                "backend SCRAM v= signature could not be verified: no ServerKey was available"
            );
        }

        Ok(())
    }

    async fn read_authentication_data(&mut self, expected: u32) -> Result<Vec<u8>, PgError> {
        let (tag, payload_len) = self.read_message_header().await?;
        let payload = self.read_message_body(payload_len).await?;

        if tag == b'E' {
            let (severity, code, message) = parse_error_response(&payload);
            return Err(PgError::Backend {
                severity,
                code,
                message,
            });
        }

        if tag != b'R' {
            return Err(PgError::Protocol(format!(
                "expected an authentication message, got {:?}",
                tag as char
            )));
        }

        if payload.len() < 4 {
            return Err(PgError::Protocol(
                "authentication message is shorter than its sub-code".to_owned(),
            ));
        }

        let auth_type = u32::from_be_bytes(
            payload[..4]
                .try_into()
                .map_err(|_| PgError::Protocol("invalid auth type".to_owned()))?,
        );

        if auth_type != expected {
            return Err(PgError::Protocol(format!(
                "expected authentication sub-code {expected}, got {auth_type}"
            )));
        }

        Ok(payload[4..].to_vec())
    }

    async fn read_message_body(&mut self, payload_len: usize) -> Result<PooledBytes, PgError> {
        if payload_len > self.pool.max_capacity() {
            return Err(PgError::Protocol(format!(
                "backend message body {payload_len} exceeds the buffer pool capacity"
            )));
        }

        let mut buff = self.pool.get(payload_len);
        self.stream.read_exact(&mut buff).await?;

        Ok(buff)
    }

    async fn write_startup_message(&mut self, config: &PgConfig) -> Result<(), PgError> {
        let mut message = Vec::new();
        message.extend_from_slice(&PROTOCOL_VERSION_NUMBER.to_be_bytes());

        let mut saw_user = false;
        let mut saw_database = false;
        let mut saw_application_name = false;

        for (name, value) in &config.startup_params {
            match name.as_str() {
                "user" => saw_user = true,
                "database" => saw_database = true,
                "application_name" => saw_application_name = true,
                _ => {}
            }

            put_cstr(&mut message, name);
            put_cstr(&mut message, value);
        }

        if !saw_user {
            put_cstr(&mut message, "user");
            put_cstr(&mut message, &config.user);
        }
        if !saw_database {
            put_cstr(&mut message, "database");
            put_cstr(&mut message, &config.database);
        }
        if !saw_application_name {
            put_cstr(&mut message, "application_name");
            put_cstr(&mut message, "wirechaos");
        }

        message.push(b'\0');

        let len = (4 + message.len()) as i32;
        let mut packet = Vec::with_capacity(1 + len as usize);
        packet.extend_from_slice(&len.to_be_bytes());
        packet.extend_from_slice(message.as_slice());

        self.write_raw(&packet).await
    }

    async fn read_message_header(&mut self) -> Result<(u8, usize), PgError> {
        let mut buff = [0u8; 5];
        self.stream.read_exact(&mut buff).await?;

        let tag = buff[0];
        let len = i32::from_be_bytes([buff[1], buff[2], buff[3], buff[4]]);

        if len < 4 {
            return Err(PgError::Protocol(format!("invalid frame length: {len}")));
        }

        // `length` is always 4 + message body len.
        Ok((tag, (len - 4) as usize))
    }

    async fn write_message(&mut self, tag: u8, body: &[u8]) -> Result<(), PgError> {
        let len = (4 + body.len()) as i32;
        let mut packet = Vec::with_capacity(1 + len as usize);
        packet.push(tag);
        packet.extend_from_slice(&len.to_be_bytes());
        packet.extend_from_slice(body);

        self.write_raw(&packet).await
    }

    async fn write_raw(&mut self, bytes: &[u8]) -> Result<(), PgError> {
        self.stream.write_all(bytes).await?;
        self.stream.flush().await
    }

    async fn try_tls(
        mut tcp_stream: TcpStream,
        config: &PgConfig,
    ) -> Result<(TimeoutStream, Option<CertHash>), PgError> {
        if config.tls.mode == BackendTlsMode::Disable {
            return Ok((plain_stream(tcp_stream, config.startup_timeout), None));
        }

        let server_supports_tls = tokio::time::timeout(config.connect_timeout, async {
            tcp_stream.write_all(&8u32.to_be_bytes()).await?;
            tcp_stream
                .write_all(&SSL_REQUEST_CODE.to_be_bytes())
                .await?;
            tcp_stream.flush().await?;

            let mut buf = [0u8; 1];
            tcp_stream.read_exact(&mut buf).await?;

            Ok::<bool, std::io::Error>(buf[0] == b'S')
        })
        .await
        .map_err(|_| PgError::TlsTimeout)??;

        if !server_supports_tls {
            return match config.tls.mode {
                BackendTlsMode::Prefer => {
                    Ok((plain_stream(tcp_stream, config.startup_timeout), None))
                }
                BackendTlsMode::Disable => {
                    Ok((plain_stream(tcp_stream, config.startup_timeout), None))
                }
                BackendTlsMode::Require | BackendTlsMode::VerifyFull => Err(PgError::Tls(
                    "backend does not support TLS, but the configured tls mode requires it"
                        .to_owned(),
                )),
            };
        }

        let server_name = config
            .tls_server_name()
            .and_then(|name| ServerName::try_from(name).ok())
            .ok_or_else(|| {
                PgError::Tls(format!(
                    "invalid backend TLS server name for {:?}",
                    config.tls_server_name()
                ))
            })?;

        let tls_config = Arc::new(build_tls_config(config)?);
        let connector = TlsConnector::from(tls_config);

        let tls_stream = tokio::time::timeout(
            config.connect_timeout,
            connector.connect(server_name, tcp_stream),
        )
        .await
        .map_err(|_| PgError::TlsTimeout)??;

        let cert_hash = tls_stream
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|certs| certs.first())
            .and_then(|leaf| match CertHash::new(leaf) {
                Ok(hash) => hash,
                Err(error) => {
                    warn!(%error, "backend leaf certificate could not be hashed; -PLUS unavailable");
                    None
                }
            });

        let (read_half, write_half) = tokio::io::split(tls_stream);
        Ok((
            TimeoutStream::new(
                BufReader::new(ConnRead::ClientTls(read_half)),
                BufWriter::new(ConnWrite::ClientTls(write_half)),
                config.startup_timeout,
            ),
            cert_hash,
        ))
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
            startup_notifications: Vec::new(),
            backend_key: None,
            ready_status: None,
            server_signature_verified: false,
            peer_cert_hash: None,
            host: String::new(),
            port: 0,
            connect_timeout: Duration::from_secs(1),
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

fn unsupported_method_message(code: u32) -> String {
    let method = match code {
        2 => "Kerberos",
        6 => "SCM credentials",
        7 => "GSSAPI",
        8 => "GSSAPI continuation",
        9 => "SSPI",
        other => return format!("backend requested unsupported authentication method {other}"),
    };

    format!("backend requested {method} authentication, which wirechaos does not support")
}

fn lossy_mechanism_names(body: &[u8]) -> Vec<String> {
    body.split(|&byte| byte == 0)
        .filter(|name| !name.is_empty())
        .map(|name| String::from_utf8_lossy(name).into_owned())
        .collect()
}

fn parse_error_response(body: &[u8]) -> (String, String, String) {
    let mut severity = "FATAL".to_owned();
    let mut code = "XX000".to_owned();
    let mut message = String::new();
    let mut position = 0;

    while position < body.len() && body[position] != 0 {
        let field = body[position];
        position += 1;

        let start = position;
        while position < body.len() && body[position] != 0 {
            position += 1;
        }

        let value = String::from_utf8_lossy(&body[start..position]).into_owned();
        position += 1;

        match field {
            b'S' => severity = value,
            b'V' => severity = value,
            b'C' => code = value,
            b'M' => message = value,
            _ => {}
        }
    }

    (severity, code, message)
}

fn build_tls_config(config: &PgConfig) -> Result<rustls::ClientConfig, PgError> {
    let provider = crypto_provider();
    let algorithms = provider.signature_verification_algorithms;

    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| PgError::Tls(format!("invalid TLS protocol configuration: {error}")))?;

    let client_config = match config.tls.mode {
        BackendTlsMode::Disable => {
            return Err(PgError::Tls(
                "TLS was requested but backend.tls.mode is disable".to_owned(),
            ))
        }
        BackendTlsMode::Prefer => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification { algorithms }))
            .with_no_client_auth(),
        BackendTlsMode::Require => {
            let roots = load_root_store(config)?;
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(ChainOnlyVerification {
                    roots,
                    algorithms,
                }))
                .with_no_client_auth()
        }
        BackendTlsMode::VerifyFull => {
            let roots = load_root_store(config)?;
            builder.with_root_certificates(roots).with_no_client_auth()
        }
    };

    Ok(client_config)
}

fn crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    rustls::crypto::CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
}

fn load_root_store(config: &PgConfig) -> Result<RootCertStore, PgError> {
    let Some(path) = config.tls.root_cert_file.as_ref() else {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        return Ok(roots);
    };

    let pem = std::fs::read(path).map_err(|error| {
        PgError::Tls(format!(
            "cannot read backend.tls.root_cert_file {}: {error}",
            path.display()
        ))
    })?;

    let mut roots = RootCertStore::empty();
    let mut reader = std::io::BufReader::new(pem.as_slice());
    let mut added = 0usize;

    for certificate in rustls_pemfile::certs(&mut reader) {
        let certificate = certificate.map_err(|error| {
            PgError::Tls(format!(
                "invalid certificate in backend.tls.root_cert_file {}: {error}",
                path.display()
            ))
        })?;

        roots.add(certificate).map_err(|error| {
            PgError::Tls(format!(
                "unusable certificate in backend.tls.root_cert_file {}: {error}",
                path.display()
            ))
        })?;
        added += 1;
    }

    if added == 0 {
        return Err(PgError::Tls(format!(
            "backend.tls.root_cert_file {} contains no certificates",
            path.display()
        )));
    }

    Ok(roots)
}

#[derive(Debug)]
struct NoCertificateVerification {
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms
            .mapping
            .iter()
            .map(|(scheme, _)| *scheme)
            .collect()
    }
}

#[derive(Debug)]
struct ChainOnlyVerification {
    roots: RootCertStore,
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for ChainOnlyVerification {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let parsed = rustls::server::ParsedCertificate::try_from(end_entity)?;

        // `require` validates the chain but deliberately skips the host-name
        // check, matching libpq's `sslmode=require`. Only `verify-full` defends
        // against a MITM on a different trusted certificate.
        rustls::client::verify_server_cert_signed_by_trust_anchor(
            &parsed,
            &self.roots,
            intermediates,
            now,
            self.algorithms.all,
        )?;

        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms
            .mapping
            .iter()
            .map(|(scheme, _)| *scheme)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::config::{BackendTlsMode, ChannelBindingMode};

    #[test]
    fn error_response_fields_are_parsed() {
        let body = b"SFATAL\0VFATAL\0C28P01\0Mpassword authentication failed\0\0";
        let (severity, code, message) = parse_error_response(body);

        assert_eq!(severity, "FATAL");
        assert_eq!(code, "28P01");
        assert_eq!(message, "password authentication failed");
    }

    #[test]
    fn unsupported_methods_name_the_method() {
        assert!(unsupported_method_message(7).contains("GSSAPI"));
        assert!(unsupported_method_message(9).contains("SSPI"));
        assert!(unsupported_method_message(2).contains("Kerberos"));
        assert!(unsupported_method_message(6).contains("SCM"));
        assert!(unsupported_method_message(99).contains("99"));
    }

    #[test]
    fn configuration_defaults_are_libpq_compatible() {
        let tls = BackendTlsConfig::default();
        assert_eq!(tls.mode, BackendTlsMode::Prefer);
        assert_eq!(tls.channel_binding, ChannelBindingMode::Prefer);
    }
}
