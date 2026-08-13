//! Integration tests for the connection startup phase.
//!
//! A real PostgreSQL client drives `Conn::handle_startup` through the startup
//! message exchange over a real loopback TCP socket:
//!   1. an SSLRequest (code 80877103) — replied 'S' and promoted to TLS when
//!      an acceptor is configured, or 'N' to stay plaintext
//!   2. a GSSENCRequest (code 80877104) — always declined with 'N'
//!   3. a plain StartupMessage — parsed without any promotion
//!   4. error cases — re-issued requests, and malformed/oversized lengths

use std::sync::Arc;

use rustls::{Certificate, PrivateKey, RootCertStore, ServerConfig, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use wirechaos_core::proxy::buffer_pool::MultiBufferPool;
use wirechaos_core::proxy::conn::Conn;

/// (1234 << 16) | 5679 — the SSLRequest startup-message code.
const SSL_REQUEST_CODE: u32 = 80877103;
/// (1234 << 16) | 5680 — the GSSENCRequest startup-message code.
const GSSENC_REQUEST_CODE: u32 = 80877104;
/// Protocol version 3.0 as a startup-message Int32.
const PROTOCOL_VERSION_3_0: u32 = 196608;

/// A pool with buckets [4, 8, 16, 32, 64]. The SSLRequest body (4 bytes) and
/// the startup bodies we send (16 bytes) must each hit an exact bucket, since
/// `MultiBufferPool::get` requires an exact capacity match.
fn buffer_pool() -> Arc<MultiBufferPool> {
    MultiBufferPool::new(4, 64, 4)
}

/// Generate a fresh self-signed cert and build a matching server acceptor and
/// client connector from it.
fn tls_pair() -> (TlsAcceptor, TlsConnector, Certificate) {
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

    (
        acceptor,
        connector,
        Certificate(cert_der.as_ref().to_vec()),
    )
}

/// Build a StartupMessage wire payload carrying protocol 3.0 plus `params`.
/// `4 + params.len()` must land exactly on a pool bucket (16 for 12-byte params).
fn startup_message(params: &[u8]) -> Vec<u8> {
    let body_len = 4 + params.len() as u32;
    let mut msg = Vec::with_capacity(4 + body_len as usize);
    msg.extend_from_slice(&(4 + body_len).to_be_bytes());
    msg.extend_from_slice(&PROTOCOL_VERSION_3_0.to_be_bytes());
    msg.extend_from_slice(params);
    msg
}

/// Server side of the happy path: accept, handle the SSLRequest (which replies
/// 'S' and upgrades the socket to TLS), then read the real StartupMessage and
/// echo a fixed reply — all over the promoted TLS transport.
#[tokio::test]
async fn ssl_request_promotes_connection_to_tls() {
    let (acceptor, connector, _) = tls_pair();
    let pool = buffer_pool();

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");

    let server = tokio::spawn(async move {
        let (socket, _peer) = listener.accept().await.expect("accept");
        let mut conn = Conn::new(socket, pool, Some(acceptor));

        // First call: read the SSLRequest, reply 'S', upgrade to TLS.
        conn.handle_startup()
            .await
            .expect("handle SSLRequest and promote to TLS");

        // Second read: the real StartupMessage now arrives over TLS.
        let startup = conn
            .read_startup_packet()
            .await
            .expect("read startup over TLS");
        let version =
            u32::from_be_bytes(startup.as_slice()[..4].try_into().unwrap());
        assert_eq!(
            version,
            PROTOCOL_VERSION_3_0,
            "startup message should carry protocol 3.0"
        );

        // Prove the write half is encrypted too: send an AuthenticationOk.
        conn.write_raw(b"R\x00\x00\x00\x08\x00\x00\x00\x00")
            .await
            .expect("write reply over TLS");
    });

    // ---- client side ----
    let mut tcp = TcpStream::connect(addr).await.expect("connect");

    // 1. SSLRequest: length 8 + code 80877103.
    tcp.write_all(&8u32.to_be_bytes()).await.expect("ssl request len");
    tcp.write_all(&SSL_REQUEST_CODE.to_be_bytes())
        .await
        .expect("ssl request code");
    tcp.flush().await.expect("flush ssl request");

    // 2. Server must answer 'S' on the plaintext channel.
    let mut reply = [0u8; 1];
    tcp.read_exact(&mut reply).await.expect("read 'S'");
    assert_eq!(&reply, b"S", "server should offer TLS");

    // 3. TLS handshake over the same socket.
    let server_name = ServerName::try_from("localhost").expect("server name");
    let tls = connector
        .connect(server_name, tcp)
        .await
        .expect("tls handshake");
    let (mut tls_reader, mut tls_writer) = tokio::io::split(tls);

    // 4. Real startup over TLS: 12 bytes of params -> 16-byte body.
    let params = b"user\x00peter\x00\x00";
    tls_writer
        .write_all(&startup_message(params))
        .await
        .expect("send startup over TLS");
    tls_writer.flush().await.expect("flush startup");

    // 5. Read the server's encrypted reply.
    let mut auth_ok = [0u8; 9];
    tls_reader
        .read_exact(&mut auth_ok)
        .await
        .expect("read reply over TLS");
    assert_eq!(&auth_ok, b"R\x00\x00\x00\x08\x00\x00\x00\x00");

    server.await.expect("server task completed cleanly");
}

/// A plain StartupMessage (no SSLRequest) must be parsed and the connection
/// must stay plaintext — the SSLRequest path must not be triggered.
#[tokio::test]
async fn plaintext_startup_without_ssl_request_stays_plain() {
    let pool = buffer_pool();

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");

    let server = tokio::spawn(async move {
        let (socket, _peer) = listener.accept().await.expect("accept");
        let mut conn = Conn::new(socket, pool, None); // no TLS acceptor configured

        // No promotion happened — read a follow-up message on the plain socket.
        conn.handle_startup()
            .await
            .expect("handle plaintext startup");

        // No promotion happened — read a follow-up message on the plain socket.
        let len = conn.read_message_length().await.expect("read message length");
        let body = conn
            .read_message_body(len)
            .await
            .expect("read message body")
            .expect("body must not be empty");
        body.as_slice().to_vec()
    });

    let mut tcp = TcpStream::connect(addr).await.expect("connect");

    // StartupMessage first (12-byte params -> 16-byte body, a pool bucket).
    tcp.write_all(&startup_message(b"user\x00peter\x00\x00"))
        .await
        .expect("send startup");
    tcp.flush().await.expect("flush startup");

    // Then an 8-byte length-prefixed payload (8 is a pool bucket).
    let payload = b"12345678";
    let mut msg = Vec::with_capacity(4 + payload.len());
    msg.extend_from_slice(&((payload.len() as u32) + 4).to_be_bytes());
    msg.extend_from_slice(payload);
    tcp.write_all(&msg).await.expect("send payload");
    tcp.flush().await.expect("flush payload");

    let body = server.await.expect("server task completed cleanly");
    assert_eq!(body, payload);
}

/// When no TLS acceptor is configured, an SSLRequest must be declined with 'N'
/// and the connection must stay usable in plaintext.
#[tokio::test]
async fn ssl_request_declined_without_tls_acceptor() {
    let pool = buffer_pool();

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");

    let server = tokio::spawn(async move {
        let (socket, _peer) = listener.accept().await.expect("accept");
        let mut conn = Conn::new(socket, pool, None); // TLS disabled

        // Server replied 'N'; the client proceeds in plaintext.
        conn.handle_startup()
            .await
            .expect("handle SSLRequest with TLS disabled");

        // Server replied 'N'; the client proceeds in plaintext.
        let startup = conn
            .read_startup_packet()
            .await
            .expect("read startup in plaintext");
        u32::from_be_bytes(startup.as_slice()[..4].try_into().unwrap())
    });

    let mut tcp = TcpStream::connect(addr).await.expect("connect");

    // SSLRequest: length 8 + code 80877103.
    tcp.write_all(&8u32.to_be_bytes()).await.expect("ssl request len");
    tcp.write_all(&SSL_REQUEST_CODE.to_be_bytes())
        .await
        .expect("ssl request code");
    tcp.flush().await.expect("flush ssl request");

    // Server must answer 'N' (no TLS offered).
    let mut reply = [0u8; 1];
    tcp.read_exact(&mut reply).await.expect("read 'N'");
    assert_eq!(&reply, b"N", "server should decline TLS");

    // Proceed in plaintext with the real startup message.
    tcp.write_all(&startup_message(b"user\x00peter\x00\x00"))
        .await
        .expect("send startup");
    tcp.flush().await.expect("flush startup");

    let version = server.await.expect("server task completed cleanly");
    assert_eq!(version, PROTOCOL_VERSION_3_0);
}

/// A GSSENCRequest must be declined with 'N' and the connection must stay
/// usable in plaintext — mirroring the SSL decline path.
#[tokio::test]
async fn gssenc_request_is_declined_and_connection_stays_plain() {
    let pool = buffer_pool();

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");

    let server = tokio::spawn(async move {
        let (socket, _peer) = listener.accept().await.expect("accept");
        let mut conn = Conn::new(socket, pool, None);

        conn.handle_startup()
            .await
            .expect("handle GSSENCRequest (declined with 'N')");

        // No promotion happened — the real startup still arrives in plaintext.
        let startup = conn
            .read_startup_packet()
            .await
            .expect("read startup in plaintext");
        u32::from_be_bytes(startup.as_slice()[..4].try_into().unwrap())
    });

    let mut tcp = TcpStream::connect(addr).await.expect("connect");

    // GSSENCRequest: length 8 + code 80877104.
    tcp.write_all(&8u32.to_be_bytes()).await.expect("gssenc request len");
    tcp.write_all(&GSSENC_REQUEST_CODE.to_be_bytes())
        .await
        .expect("gssenc request code");
    tcp.flush().await.expect("flush gssenc request");

    // Server must answer 'N' (GSSAPI encryption not offered).
    let mut reply = [0u8; 1];
    tcp.read_exact(&mut reply).await.expect("read 'N'");
    assert_eq!(&reply, b"N", "server should decline GSSAPI encryption");

    // Continue with the real startup message in plaintext.
    tcp.write_all(&startup_message(b"user\x00peter\x00\x00"))
        .await
        .expect("send startup");
    tcp.flush().await.expect("flush startup");

    let version = server.await.expect("server task completed cleanly");
    assert_eq!(version, PROTOCOL_VERSION_3_0);
}

/// A second SSLRequest on the same connection must be rejected with an error:
/// the `ssl_done` guard trips and the connection is not promoted twice.
#[tokio::test]
async fn double_ssl_request_returns_error() {
    let pool = buffer_pool();

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");

    let server = tokio::spawn(async move {
        let (socket, _peer) = listener.accept().await.expect("accept");
        let mut conn = Conn::new(socket, pool, None);

        conn.handle_startup()
            .await
            .expect("first SSLRequest succeeds");

        // A second SSLRequest must trip the guard.
        let err = conn
            .handle_startup()
            .await
            .expect_err("second SSLRequest should error");
        assert!(
            err.to_string().contains("already done"),
            "unexpected error: {err}"
        );
    });

    let mut tcp = TcpStream::connect(addr).await.expect("connect");

    // First SSLRequest is answered with 'N' (no TLS acceptor configured).
    tcp.write_all(&8u32.to_be_bytes()).await.expect("ssl request len");
    tcp.write_all(&SSL_REQUEST_CODE.to_be_bytes())
        .await
        .expect("ssl request code");
    tcp.flush().await.expect("flush ssl request");

    let mut reply = [0u8; 1];
    tcp.read_exact(&mut reply).await.expect("read 'N'");
    assert_eq!(&reply, b"N");

    // Second SSLRequest: the server rejects it and drops the connection.
    tcp.write_all(&8u32.to_be_bytes()).await.expect("ssl request len");
    tcp.write_all(&SSL_REQUEST_CODE.to_be_bytes())
        .await
        .expect("ssl request code");
    tcp.flush().await.expect("flush ssl request");

    server.await.expect("server task completed cleanly");
}

/// A second GSSENCRequest on the same connection must be rejected with an
/// error, mirroring the SSL guard.
#[tokio::test]
async fn double_gssenc_request_returns_error() {
    let pool = buffer_pool();

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");

    let server = tokio::spawn(async move {
        let (socket, _peer) = listener.accept().await.expect("accept");
        let mut conn = Conn::new(socket, pool, None);

        conn.handle_startup()
            .await
            .expect("first GSSENCRequest succeeds");

        // A second GSSENCRequest must trip the guard.
        let err = conn
            .handle_startup()
            .await
            .expect_err("second GSSENCRequest should error");
        assert!(
            err.to_string().contains("already done"),
            "unexpected error: {err}"
        );
    });

    let mut tcp = TcpStream::connect(addr).await.expect("connect");

    // First GSSENCRequest is answered with 'N'.
    tcp.write_all(&8u32.to_be_bytes()).await.expect("gssenc request len");
    tcp.write_all(&GSSENC_REQUEST_CODE.to_be_bytes())
        .await
        .expect("gssenc request code");
    tcp.flush().await.expect("flush gssenc request");

    let mut reply = [0u8; 1];
    tcp.read_exact(&mut reply).await.expect("read 'N'");
    assert_eq!(&reply, b"N");

    // Second GSSENCRequest: the server rejects it and drops the connection.
    tcp.write_all(&8u32.to_be_bytes()).await.expect("gssenc request len");
    tcp.write_all(&GSSENC_REQUEST_CODE.to_be_bytes())
        .await
        .expect("gssenc request code");
    tcp.flush().await.expect("flush gssenc request");

    server.await.expect("server task completed cleanly");
}

/// A length prefix smaller than 4 (not even room for the 4-byte code) must be
/// rejected by `read_message_length`.
#[tokio::test]
async fn invalid_message_length_returns_error() {
    let pool = buffer_pool();

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");

    let server = tokio::spawn(async move {
        let (socket, _peer) = listener.accept().await.expect("accept");
        let mut conn = Conn::new(socket, pool, None);

        let err = conn
            .handle_startup()
            .await
            .expect_err("a length below 4 must be rejected");
        assert!(
            err.to_string().contains("Invalid message length"),
            "unexpected error: {err}"
        );
    });

    let mut tcp = TcpStream::connect(addr).await.expect("connect");

    // Total length 2 < 4: the server errors before reading a body.
    tcp.write_all(&2u32.to_be_bytes()).await.expect("send short length");
    tcp.flush().await.expect("flush short length");

    server.await.expect("server task completed cleanly");
}

/// A startup packet whose body exceeds MAX_STARTUP_PACKET_LENGTH (10000) must
/// be rejected before its body is read.
#[tokio::test]
async fn oversized_startup_packet_returns_error() {
    let pool = buffer_pool();

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");

    let server = tokio::spawn(async move {
        let (socket, _peer) = listener.accept().await.expect("accept");
        let mut conn = Conn::new(socket, pool, None);

        let err = conn
            .handle_startup()
            .await
            .expect_err("an oversized startup packet must be rejected");
        assert!(
            err.to_string().contains("Invalid message length"),
            "unexpected error: {err}"
        );
    });

    let mut tcp = TcpStream::connect(addr).await.expect("connect");

    // MAX_STARTUP_PACKET_LENGTH is 10000; a total length of 10005 yields a
    // body length of 10001, which exceeds it.
    tcp.write_all(&10005u32.to_be_bytes())
        .await
        .expect("send oversized length");
    tcp.flush().await.expect("flush oversized length");

    server.await.expect("server task completed cleanly");
}
