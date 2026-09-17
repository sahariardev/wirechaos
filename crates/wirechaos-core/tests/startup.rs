//! Integration tests for the connection startup phase.
//!
//! A real PostgreSQL client drives `Conn::handle_startup` through the startup
//! message exchange over a real loopback TCP socket:
//!   1. an SSLRequest (code 80877103) — replied 'S' and promoted to TLS when
//!      an acceptor is configured, or 'N' to stay plaintext
//!   2. a GSSENCRequest (code 80877104) — always declined with 'N'
//!   3. a plain StartupMessage — parsed, and (when it carries a `user`)
//!      followed by the SCRAM-SHA-256 exchange
//!   4. error cases — re-issued requests, a missing `user`, a plaintext
//!      startup while TLS is required, and malformed/oversized lengths

mod common;

use common::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use wirechaos_core::proxy::conn::Conn;

/// Server side of the happy path: accept, handle the SSLRequest (which replies
/// 'S' and upgrades the socket to TLS), then read the real StartupMessage and
/// echo a fixed reply — all over the promoted TLS transport.
#[tokio::test]
async fn ssl_request_promotes_connection_to_tls() {
    let (acceptor, connector) = tls_pair();
    let pool = buffer_pool();

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");

    let server = tokio::spawn(async move {
        let (socket, _peer) = listener.accept().await.expect("accept");
        let mut conn = Conn::new(socket, pool, Some(acceptor), TestVerifierProvider::new());

        // First call: read the SSLRequest, reply 'S', upgrade to TLS.
        conn.handle_startup()
            .await
            .expect("handle SSLRequest and promote to TLS");

        // Second read: the real StartupMessage now arrives over TLS.
        let startup = conn
            .read_startup_packet()
            .await
            .expect("read startup over TLS");
        let version = u32::from_be_bytes(startup.as_slice()[..4].try_into().unwrap());
        assert_eq!(
            version, PROTOCOL_VERSION_3_0,
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
    tcp.write_all(&8u32.to_be_bytes())
        .await
        .expect("ssl request len");
    tcp.write_all(&SSL_REQUEST_CODE.to_be_bytes())
        .await
        .expect("ssl request code");
    tcp.flush().await.expect("flush ssl request");

    // 2. Server must answer 'S' on the plaintext channel.
    let mut reply = [0u8; 1];
    tcp.read_exact(&mut reply).await.expect("read 'S'");
    assert_eq!(&reply, b"S", "server should offer TLS");

    // 3. TLS handshake over the same socket.
    let tls = connector
        .connect(server_name(), tcp)
        .await
        .expect("tls handshake");
    let (mut tls_reader, mut tls_writer) = tokio::io::split(tls);

    // 4. Real startup over TLS: 12 bytes of params -> 16-byte body.
    let params = b"user\x00peter\x00\x00";
    write_startup_payload(&mut tls_writer, &startup_message(params)).await;

    // 5. Read the server's encrypted reply.
    let mut auth_ok = [0u8; 9];
    tls_reader
        .read_exact(&mut auth_ok)
        .await
        .expect("read reply over TLS");
    assert_eq!(&auth_ok, b"R\x00\x00\x00\x08\x00\x00\x00\x00");

    server.await.expect("server task completed cleanly");
}

/// A plain StartupMessage (no SSLRequest) must be parsed, must authenticate
/// the client on the very same socket — no TLS negotiation may be injected —
/// and must leave the connection usable afterwards.
#[tokio::test]
async fn plaintext_startup_authenticates_and_stays_usable() {
    let pool = buffer_pool();

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");

    let server = tokio::spawn(async move {
        let (socket, _peer) = listener.accept().await.expect("accept");
        // No TLS acceptor configured: the connection must stay plaintext.
        let mut conn = Conn::new(socket, pool, None, TestVerifierProvider::new());

        conn.handle_startup()
            .await
            .expect("parse plaintext startup and authenticate");

        let user = conn.user.clone();
        let database = conn.database.clone();

        // The connection survived the exchange and still frames messages.
        let len = conn
            .read_message_length()
            .await
            .expect("read message length");
        let body = conn
            .read_message_body(len)
            .await
            .expect("read message body")
            .expect("body must not be empty");

        (body.as_slice().to_vec(), user, database)
    });

    let mut tcp = TcpStream::connect(addr).await.expect("connect");

    // StartupMessage first, with an explicit database.
    write_startup_payload(
        &mut tcp,
        &startup_message(b"user\x00peter\x00database\x00app\x00\x00"),
    )
    .await;

    // The next byte back must be the SASL request ('R'): an 'S' or 'N' here
    // would mean the plaintext connection was treated as an SSLRequest.
    let mut client = ScramClient::new(USER, PASSWORD, CLIENT_NONCE);
    begin_sasl(&mut tcp, &client.client_first()).await;

    let server_first = read_server_first(&mut tcp).await;
    client.handle_server_first(&server_first);
    write_message(&mut tcp, MSG_PASSWORD, client.client_final().as_bytes()).await;
    assert_eq!(
        read_server_final(&mut tcp).await,
        client.expected_server_final()
    );

    // Then an 8-byte length-prefixed payload on the plain socket.
    let payload = b"12345678";
    let mut msg = Vec::with_capacity(4 + payload.len());
    msg.extend_from_slice(&((payload.len() as u32) + 4).to_be_bytes());
    msg.extend_from_slice(payload);
    write_startup_payload(&mut tcp, &msg).await;

    let (body, user, database) = server.await.expect("server task completed cleanly");

    assert_eq!(body, payload, "the connection must still carry messages");
    assert_eq!(
        user.as_deref(),
        Some(USER),
        "the startup user must be parsed"
    );
    assert_eq!(
        database.as_deref(),
        Some("app"),
        "the startup database must override the user default"
    );
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
        let mut conn = Conn::new(socket, pool, None, TestVerifierProvider::new()); // TLS disabled

        // Server replied 'N'; the client proceeds in plaintext.
        conn.handle_startup()
            .await
            .expect("handle SSLRequest with TLS disabled");

        let startup = conn
            .read_startup_packet()
            .await
            .expect("read startup in plaintext");
        u32::from_be_bytes(startup.as_slice()[..4].try_into().unwrap())
    });

    let mut tcp = TcpStream::connect(addr).await.expect("connect");

    // SSLRequest: length 8 + code 80877103.
    tcp.write_all(&8u32.to_be_bytes())
        .await
        .expect("ssl request len");
    tcp.write_all(&SSL_REQUEST_CODE.to_be_bytes())
        .await
        .expect("ssl request code");
    tcp.flush().await.expect("flush ssl request");

    // Server must answer 'N' (no TLS offered).
    let mut reply = [0u8; 1];
    tcp.read_exact(&mut reply).await.expect("read 'N'");
    assert_eq!(&reply, b"N", "server should decline TLS");

    // Proceed in plaintext with the real startup message.
    write_startup_payload(&mut tcp, &startup_message(b"user\x00peter\x00\x00")).await;

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
        let mut conn = Conn::new(socket, pool, None, TestVerifierProvider::new());

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
    tcp.write_all(&8u32.to_be_bytes())
        .await
        .expect("gssenc request len");
    tcp.write_all(&GSSENC_REQUEST_CODE.to_be_bytes())
        .await
        .expect("gssenc request code");
    tcp.flush().await.expect("flush gssenc request");

    // Server must answer 'N' (GSSAPI encryption not offered).
    let mut reply = [0u8; 1];
    tcp.read_exact(&mut reply).await.expect("read 'N'");
    assert_eq!(&reply, b"N", "server should decline GSSAPI encryption");

    // Continue with the real startup message in plaintext.
    write_startup_payload(&mut tcp, &startup_message(b"user\x00peter\x00\x00")).await;

    let version = server.await.expect("server task completed cleanly");
    assert_eq!(version, PROTOCOL_VERSION_3_0);
}

/// When TLS is required, a client that skips the SSLRequest must be rejected
/// instead of being allowed to authenticate in the clear.
#[tokio::test]
async fn startup_is_rejected_when_tls_is_required() {
    let pool = buffer_pool();

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");

    let server = tokio::spawn(async move {
        let (socket, _peer) = listener.accept().await.expect("accept");
        let mut conn = Conn::new(socket, pool, None, TestVerifierProvider::new());
        conn.required_tls = true;

        conn.handle_startup()
            .await
            .expect_err("a plaintext startup must be rejected when TLS is required")
            .to_string()
    });

    let mut tcp = TcpStream::connect(addr).await.expect("connect");

    // No SSLRequest: straight to the startup message.
    write_startup_payload(&mut tcp, &startup_message(b"user\x00peter\x00\x00")).await;

    let error = server.await.expect("server task completed cleanly");
    assert!(
        error.contains("TLS is required"),
        "unexpected error: {error}"
    );
}

/// The required-TLS guard must not reject a client that did promote the
/// connection: SSLRequest + TLS + startup + SCRAM must all succeed.
#[tokio::test]
async fn startup_over_tls_is_accepted_when_tls_is_required() {
    let (acceptor, connector) = tls_pair();
    let pool = buffer_pool();

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");

    let server = tokio::spawn(async move {
        let (socket, _peer) = listener.accept().await.expect("accept");
        let mut conn = Conn::new(socket, pool, Some(acceptor), TestVerifierProvider::new());
        conn.required_tls = true;

        // SSLRequest: reply 'S' and promote to TLS.
        conn.handle_startup().await.expect("promote to TLS");

        // StartupMessage and authentication over the promoted transport.
        conn.handle_startup()
            .await
            .expect("startup over TLS must be accepted");

        conn.user.clone()
    });

    let mut tcp = TcpStream::connect(addr).await.expect("connect");

    tcp.write_all(&8u32.to_be_bytes())
        .await
        .expect("ssl request len");
    tcp.write_all(&SSL_REQUEST_CODE.to_be_bytes())
        .await
        .expect("ssl request code");
    tcp.flush().await.expect("flush ssl request");

    let mut reply = [0u8; 1];
    tcp.read_exact(&mut reply).await.expect("read 'S'");
    assert_eq!(&reply, b"S", "server should offer TLS");

    let mut tls = connector
        .connect(server_name(), tcp)
        .await
        .expect("tls handshake");

    write_startup_payload(&mut tls, &startup_message(b"user\x00peter\x00\x00")).await;

    let mut client = ScramClient::new(USER, PASSWORD, CLIENT_NONCE);
    begin_sasl(&mut tls, &client.client_first()).await;

    let server_first = read_server_first(&mut tls).await;
    client.handle_server_first(&server_first);
    write_message(&mut tls, MSG_PASSWORD, client.client_final().as_bytes()).await;
    assert_eq!(
        read_server_final(&mut tls).await,
        client.expected_server_final()
    );

    let user = server.await.expect("server task completed cleanly");
    assert_eq!(user.as_deref(), Some(USER));
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
        let mut conn = Conn::new(socket, pool, None, TestVerifierProvider::new());

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
    tcp.write_all(&8u32.to_be_bytes())
        .await
        .expect("ssl request len");
    tcp.write_all(&SSL_REQUEST_CODE.to_be_bytes())
        .await
        .expect("ssl request code");
    tcp.flush().await.expect("flush ssl request");

    let mut reply = [0u8; 1];
    tcp.read_exact(&mut reply).await.expect("read 'N'");
    assert_eq!(&reply, b"N");

    // Second SSLRequest: the server rejects it and drops the connection.
    tcp.write_all(&8u32.to_be_bytes())
        .await
        .expect("ssl request len");
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

        let mut conn = Conn::new(socket, pool, None, TestVerifierProvider::new());

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
    tcp.write_all(&8u32.to_be_bytes())
        .await
        .expect("gssenc request len");
    tcp.write_all(&GSSENC_REQUEST_CODE.to_be_bytes())
        .await
        .expect("gssenc request code");
    tcp.flush().await.expect("flush gssenc request");

    let mut reply = [0u8; 1];
    tcp.read_exact(&mut reply).await.expect("read 'N'");
    assert_eq!(&reply, b"N");

    // Second GSSENCRequest: the server rejects it and drops the connection.
    tcp.write_all(&8u32.to_be_bytes())
        .await
        .expect("gssenc request len");
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
        let mut conn = Conn::new(socket, pool, None, TestVerifierProvider::new());

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
    write_length_prefix(&mut tcp, 2).await;

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
        let mut conn = Conn::new(socket, pool, None, TestVerifierProvider::new());

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
    write_length_prefix(&mut tcp, 10005).await;

    server.await.expect("server task completed cleanly");
}
