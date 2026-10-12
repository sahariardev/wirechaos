//! Task 4 acceptance tests: the post-auth sequence, protocol-version policy,
//! connection limits, the authentication timeout, and malformed startup
//! packets — all driven through `Conn::handle` over a real socket.

mod common;

use std::sync::Arc;

use common::*;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use wirechaos_core::proxy::backend::registry::Registry;
use wirechaos_core::proxy::config::Config;
use wirechaos_core::proxy::conn_registry::ConnRegistry;

/// A `psql`-shaped client must receive `AuthenticationOk`, `ParameterStatus*`,
/// `BackendKeyData`, and `ReadyForQuery('I')`, in that order.
#[tokio::test]
async fn client_receives_the_full_post_auth_sequence() {
    let addr = spawn_startup_server(Registry::new(), ConnRegistry::new(10), test_config()).await;

    let mut tcp = TcpStream::connect(addr).await.expect("connect");
    let post_auth = complete_startup_and_auth(&mut tcp).await;

    assert_eq!(post_auth.ready_status, b'I', "a fresh session is idle");

    let (_, secret) = post_auth
        .backend_key
        .expect("BackendKeyData is required for CancelRequest");
    assert_ne!(secret, 0, "a zero cancel secret would be guessable");

    // The stub backend forwards no ParameterStatus values yet (task 5 wires the
    // real one); the sequence must still be well-formed. `read_post_auth_sequence`
    // already enforces the ordering ('S'* then 'K' then 'Z').
}

/// The proxy mints a fresh `(pid, secret)` per session rather than reusing one.
#[tokio::test]
async fn proxy_mints_a_fresh_cancel_key_per_session() {
    let first = spawn_startup_server(Registry::new(), ConnRegistry::new(10), test_config()).await;
    let mut first_conn = TcpStream::connect(first).await.expect("connect");
    let first_key = complete_startup_and_auth(&mut first_conn)
        .await
        .backend_key
        .expect("key issued");

    let second = spawn_startup_server(Registry::new(), ConnRegistry::new(10), test_config()).await;
    let mut second_conn = TcpStream::connect(second).await.expect("connect");
    let second_key = complete_startup_and_auth(&mut second_conn)
        .await
        .backend_key
        .expect("key issued");

    assert_ne!(first_key, second_key, "keys must be per-session");
    assert_ne!(first_key.1, 0);
    assert_ne!(second_key.1, 0);
}

/// A non-3.0 protocol version is rejected with `0A000` and PostgreSQL's wording.
#[tokio::test]
async fn unsupported_protocol_version_is_rejected() {
    let addr = spawn_startup_server(Registry::new(), ConnRegistry::new(10), test_config()).await;
    let mut tcp = TcpStream::connect(addr).await.expect("connect");

    let mut body = (4u32 << 16).to_be_bytes().to_vec();
    body.extend_from_slice(b"user\x00peter\x00\x00");
    let mut packet = ((body.len() + 4) as u32).to_be_bytes().to_vec();
    packet.extend_from_slice(&body);
    write_startup_payload(&mut tcp, &packet).await;

    let error = read_error(&mut tcp).await;
    assert_eq!(error[&'S'], "FATAL");
    assert_eq!(error[&'C'], "0A000");
    assert_eq!(
        error[&'M'],
        "unsupported frontend protocol 4.0: server supports 3.0 to 3.0"
    );
}

/// A startup packet without a `user` is a `28000`, not a generic auth failure.
#[tokio::test]
async fn missing_user_is_rejected_with_28000() {
    let addr = spawn_startup_server(Registry::new(), ConnRegistry::new(10), test_config()).await;
    let mut tcp = TcpStream::connect(addr).await.expect("connect");

    write_startup_payload(&mut tcp, &startup_message(b"database\x00appdb\x00\x00")).await;

    let error = read_error(&mut tcp).await;
    assert_eq!(error[&'C'], "28000");
    assert!(error[&'M'].contains("no PostgreSQL user name specified"));
}

/// The mandatory startup terminator: a body that ends without the final NUL is
/// rejected instead of being silently accepted.
#[tokio::test]
async fn a_startup_without_a_terminator_is_rejected() {
    let addr = spawn_startup_server(Registry::new(), ConnRegistry::new(10), test_config()).await;
    let mut tcp = TcpStream::connect(addr).await.expect("connect");

    let mut body = PROTOCOL_VERSION_3_0.to_be_bytes().to_vec();
    body.extend_from_slice(b"user\x00peter\x00"); // no terminating NUL
    let mut packet = ((body.len() + 4) as u32).to_be_bytes().to_vec();
    packet.extend_from_slice(&body);
    write_startup_payload(&mut tcp, &packet).await;

    let error = read_error(&mut tcp).await;
    assert_eq!(error[&'C'], "08P01");
}

/// Bytes after the terminator are a protocol violation.
#[tokio::test]
async fn a_startup_with_trailing_bytes_is_rejected() {
    let addr = spawn_startup_server(Registry::new(), ConnRegistry::new(10), test_config()).await;
    let mut tcp = TcpStream::connect(addr).await.expect("connect");

    let mut body = PROTOCOL_VERSION_3_0.to_be_bytes().to_vec();
    body.extend_from_slice(b"user\x00peter\x00\x00junk");
    let mut packet = ((body.len() + 4) as u32).to_be_bytes().to_vec();
    packet.extend_from_slice(&body);
    write_startup_payload(&mut tcp, &packet).await;

    let error = read_error(&mut tcp).await;
    assert_eq!(error[&'C'], "08P01");
}

/// The limit is checked before authentication, and a full proxy answers the
/// accepted socket with `FATAL 53300` rather than refusing it.
#[tokio::test]
async fn connection_limit_answers_53300_instead_of_refusing() {
    let addr = spawn_startup_server(Registry::new(), ConnRegistry::new(0), test_config()).await;

    // Connect and send nothing: the capacity check precedes the startup read.
    let mut tcp = TcpStream::connect(addr)
        .await
        .expect("the socket must be accepted, not refused");

    let error = read_error(&mut tcp).await;
    assert_eq!(error[&'C'], "53300");
    assert_eq!(error[&'M'], "sorry, too many clients already");
}

/// A client that connects and stalls is closed with `57014` before it can hold
/// a slot indefinitely.
#[tokio::test]
async fn authentication_timeout_closes_a_silent_connection() {
    let mut config = Config::default();
    config.limits.authentication_timeout_ms = 200;

    let addr = spawn_startup_server(Registry::new(), ConnRegistry::new(10), Arc::new(config)).await;

    let _tcp = TcpStream::connect(addr).await.expect("connect");
    // Never send anything: the deadline must fire.

    // A second read on the same socket would block; read from a clone instead
    // is not needed — the server writes the FATAL on timeout.
    let mut reader = _tcp;
    let error = read_error(&mut reader).await;
    assert_eq!(error[&'S'], "FATAL");
    assert_eq!(error[&'C'], "57014");
    assert!(error[&'M'].contains("authentication"));
}

/// A cancel whose key matches no live session is ignored, and the cancel
/// connection is closed with no response at all.
#[tokio::test]
async fn unknown_cancel_key_is_ignored_without_a_response() {
    let addr = spawn_startup_server(Registry::new(), ConnRegistry::new(10), test_config()).await;
    let mut cancel_conn = TcpStream::connect(addr).await.expect("connect");

    let mut packet = 16u32.to_be_bytes().to_vec();
    packet.extend_from_slice(&80877102u32.to_be_bytes());
    packet.extend_from_slice(&9999u32.to_be_bytes());
    packet.extend_from_slice(&0xAAAA_AAAAu32.to_be_bytes());
    write_startup_payload(&mut cancel_conn, &packet).await;

    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(IO_TIMEOUT, cancel_conn.read(&mut byte))
        .await
        .expect("must not hang");

    assert!(
        matches!(read, Ok(0) | Err(_)),
        "a cancel connection is answered with a close, not a message"
    );
}
