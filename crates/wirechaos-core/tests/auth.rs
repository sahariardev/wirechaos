//! Integration tests for the SCRAM-SHA-256 authentication exchange.
//!
//! A real PostgreSQL client drives `Conn::handle_authentication` over a real
//! loopback TCP socket:
//!   1. the server offers SCRAM-SHA-256 in an AuthenticationSASL (R, 10)
//!   2. the client answers with a SASLInitialResponse ('p') carrying
//!      client-first
//!   3. the server replies AuthenticationSASLContinue (R, 11) with server-first
//!   4. the client sends its proof in a client-final message
//!   5. the server finishes with AuthenticationSASLFinal (R, 12) carrying the
//!      server signature, and hands the extracted ClientKey back to the caller
//!
//! Rejections (wrong password, malformed SCRAM data, unusable startup user)
//! must reach the client as a framed ErrorResponse or as an error return —
//! never as a panic or a hung connection.

// Test scaffolding: see the note in `common/mod.rs`. Production code keeps the
// `unwrap_used`/`expect_used` deny; helpers in a separate integration-test crate
// need the relaxation stated explicitly.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::net::SocketAddr;

use common::*;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use wirechaos_core::proxy::conn::Conn;

/// Spawn a server that accepts one connection, pretends the startup message
/// already supplied `user`, and runs the authentication exchange.
///
/// The outcome crosses the task boundary as `Result<Option<Vec<u8>>, String>`
/// (the extracted ClientKey, or the error message) because the crate's
/// `Box<dyn Error>` is not `Send`.
async fn spawn_auth_server(
    provider: TestVerifierProvider,
    user: Option<&'static str>,
) -> (SocketAddr, JoinHandle<Result<Option<Vec<u8>>, String>>) {
    let pool = buffer_pool();
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");

    let server = tokio::spawn(async move {
        let (socket, _peer) = listener.accept().await.expect("accept");
        let mut conn = Conn::new(socket, pool, None, provider);
        conn.user = user.map(str::to_string);

        conn.handle_authentication()
            .await
            .map_err(|error| error.to_string())
    });

    (addr, server)
}

/// Run the exchange up to the point where the server waits for client-final.
async fn exchange_until_client_final(tcp: &mut TcpStream, client: &mut ScramClient) {
    begin_sasl(tcp, &client.client_first()).await;

    let server_first = read_server_first(tcp).await;
    client.handle_server_first(&server_first);
}

#[tokio::test]
async fn scram_sha256_exchange_authenticates_the_client() {
    let (addr, server) = spawn_auth_server(TestVerifierProvider::new(), Some(USER)).await;
    let mut tcp = TcpStream::connect(addr).await.expect("connect");

    let mut client = ScramClient::new(USER, PASSWORD, CLIENT_NONCE);

    // 1. + 2. AuthenticationSASL request, answered with client-first.
    exchange_until_client_final(&mut tcp, &mut client).await;

    // 3. client-final, then the server's signature.
    write_message(&mut tcp, MSG_PASSWORD, client.client_final().as_bytes()).await;
    let server_final = read_server_final(&mut tcp).await;

    assert_eq!(
        server_final,
        client.expected_server_final(),
        "server-final must be HMAC(ServerKey, auth message)"
    );

    let client_key = server
        .await
        .expect("server task completed cleanly")
        .expect("authentication must succeed");

    assert_eq!(
        client_key.as_deref(),
        Some(client.client_key()),
        "the proxy must extract the ClientKey the client proved knowledge of"
    );
}

#[tokio::test]
async fn wrong_password_is_reported_to_the_client() {
    let (addr, server) = spawn_auth_server(TestVerifierProvider::new(), Some(USER)).await;
    let mut tcp = TcpStream::connect(addr).await.expect("connect");

    // The client proves knowledge of a password the verifier was not built
    // from, so the proof cannot reconstruct StoredKey.
    let mut client = ScramClient::new(USER, "not-pencil", CLIENT_NONCE);
    exchange_until_client_final(&mut tcp, &mut client).await;
    write_message(&mut tcp, MSG_PASSWORD, client.client_final().as_bytes()).await;

    let error = read_error(&mut tcp).await;
    assert_eq!(error.get(&'S').map(String::as_str), Some("FATAL"));
    assert_eq!(
        error.get(&'C').map(String::as_str),
        Some("28P01"),
        "invalid_password must be reported: {error:?}"
    );
    let expected_message = format!("password authentication failed for user \"{USER}\"");
    assert_eq!(
        error.get(&'M').map(String::as_str),
        Some(expected_message.as_str())
    );

    let outcome = server
        .await
        .expect("server task completed cleanly")
        .expect("a rejected password is not a connection-level error");

    assert!(
        outcome.is_none(),
        "no ClientKey may be handed to the caller after a failed authentication"
    );
}

#[tokio::test]
async fn unknown_user_is_rejected() {
    let (addr, server) = spawn_auth_server(TestVerifierProvider::empty(), Some(USER)).await;
    let _tcp = TcpStream::connect(addr).await.expect("connect");

    let error = server
        .await
        .expect("server task completed cleanly")
        .expect_err("an unknown user must fail authentication");

    assert!(
        error.contains("unknown user"),
        "the verifier provider's error must surface: {error}"
    );
}

#[tokio::test]
async fn startup_without_user_is_rejected_instead_of_panicking() {
    let (addr, server) = spawn_auth_server(TestVerifierProvider::new(), None).await;
    let _tcp = TcpStream::connect(addr).await.expect("connect");

    let error = server
        .await
        .expect("server task completed cleanly")
        .expect_err("authentication without a startup user must fail");

    assert!(
        error.to_lowercase().contains("user"),
        "the missing user must be named in the error: {error}"
    );
}

#[tokio::test]
async fn non_sasl_message_is_rejected() {
    let (addr, server) = spawn_auth_server(TestVerifierProvider::new(), Some(USER)).await;
    let mut tcp = TcpStream::connect(addr).await.expect("connect");

    // Consume the SASL request, then answer with something that is not a
    // PasswordMessage.
    let (message_type, body) = read_message(&mut tcp).await;
    assert_eq!(message_type, MSG_AUTH);
    assert_eq!(auth_sub_code(&body), AUTH_SASL);
    write_message(&mut tcp, b'Q', b"select 1\0").await;

    let error = server
        .await
        .expect("server task completed cleanly")
        .expect_err("a non-SASL response must be rejected");

    assert!(
        error.contains("Invalid message"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn unsupported_mechanism_is_rejected() {
    let (addr, server) = spawn_auth_server(TestVerifierProvider::new(), Some(USER)).await;
    let mut tcp = TcpStream::connect(addr).await.expect("connect");

    let (message_type, body) = read_message(&mut tcp).await;
    assert_eq!(message_type, MSG_AUTH);
    assert_eq!(auth_sub_code(&body), AUTH_SASL);

    // SCRAM-SHA-256-PLUS was never offered, so it must be refused.
    let body = sasl_initial_response_body("SCRAM-SHA-256-PLUS", b"p=tls-unique,,n=peter,r=abc");
    write_message(&mut tcp, MSG_PASSWORD, &body).await;

    let error = server
        .await
        .expect("server task completed cleanly")
        .expect_err("an unoffered mechanism must be rejected");

    assert!(
        error.contains("invalid mechanism"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn malformed_client_first_is_reported_as_a_protocol_error() {
    let (addr, server) = spawn_auth_server(TestVerifierProvider::new(), Some(USER)).await;
    let mut tcp = TcpStream::connect(addr).await.expect("connect");

    // A client-first-message needs a GS2 header plus a bare part.
    begin_sasl(&mut tcp, "n,").await;

    let error = read_error(&mut tcp).await;
    assert_eq!(error.get(&'S').map(String::as_str), Some("FATAL"));
    assert!(
        error
            .get(&'M')
            .expect("ErrorResponse must carry a message field")
            .contains("malformed SCRAM message"),
        "unexpected error fields: {error:?}"
    );

    let outcome = server
        .await
        .expect("server task completed cleanly")
        .expect("a SCRAM protocol error is not a connection-level error");

    assert!(outcome.is_none());
}

#[tokio::test]
async fn client_final_with_proof_first_is_reported_as_a_protocol_error() {
    let (addr, server) = spawn_auth_server(TestVerifierProvider::new(), Some(USER)).await;
    let mut tcp = TcpStream::connect(addr).await.expect("connect");

    let mut client = ScramClient::new(USER, PASSWORD, CLIENT_NONCE);
    exchange_until_client_final(&mut tcp, &mut client).await;

    // The proof has to be the last attribute: a client-final that puts it
    // first must be a protocol error, not a parser panic.
    let malformed = format!("p=AAAA,c=biws,r={}", client.combined_nonce());
    write_message(&mut tcp, MSG_PASSWORD, malformed.as_bytes()).await;

    let error = read_error(&mut tcp).await;
    assert!(
        error
            .get(&'M')
            .expect("ErrorResponse must carry a message field")
            .contains("malformed SCRAM message"),
        "unexpected error fields: {error:?}"
    );

    let outcome = server
        .await
        .expect("server task completed cleanly")
        .expect("a malformed client-final is not a connection-level error");

    assert!(outcome.is_none());
}

#[tokio::test]
async fn oversized_message_is_rejected_without_panicking() {
    let (addr, server) = spawn_auth_server(TestVerifierProvider::new(), Some(USER)).await;
    let mut tcp = TcpStream::connect(addr).await.expect("connect");

    let (message_type, body) = read_message(&mut tcp).await;
    assert_eq!(message_type, MSG_AUTH);
    assert_eq!(auth_sub_code(&body), AUTH_SASL);

    // A PasswordMessage whose declared body is far beyond the pool's largest
    // bucket must fail the connection rather than abort the process.
    let mut header = Vec::with_capacity(5);
    header.push(MSG_PASSWORD);
    header.extend_from_slice(&(4096u32 + 4).to_be_bytes());
    tcp.write_all(&header)
        .await
        .expect("write oversized message header");
    tcp.flush().await.expect("flush oversized message header");

    let error = server
        .await
        .expect("server task completed cleanly")
        .expect_err("an unallocatable message length must be rejected");

    assert!(error.contains("capacity"), "unexpected error: {error}");
}
