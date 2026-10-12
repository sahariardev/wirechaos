//! The accept loop: an over-capacity server answers `FATAL 53300` on the
//! **accepted** socket instead of refusing the connection.

mod common;

use std::sync::Arc;

use common::*;
use tokio::net::{TcpListener, TcpStream};
use wirechaos_core::proxy::auth::credentials::CredentialStore;
use wirechaos_core::proxy::config::Config;
use wirechaos_core::proxy::server::{serve, ServerConfig, ServerState};

#[tokio::test]
async fn a_full_server_answers_53300_instead_of_refusing() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");

    let mut config = Config::default();
    config.limits.max_connections = 0; // every connection is over the cap

    let state = ServerState::new(ServerConfig {
        bind: addr,
        config: Arc::new(config),
        credentials: CredentialStore::with_password(USER, PASSWORD),
        frontend_tls: None,
        pool_min: 4,
        pool_max: 1024,
    });
    tokio::spawn(serve(listener, state));

    let mut tcp = TcpStream::connect(addr)
        .await
        .expect("the socket must be accepted, not refused");

    let error = read_error(&mut tcp).await;
    assert_eq!(error[&'C'], "53300");
    assert_eq!(error[&'M'], "sorry, too many clients already");
}

/// The listener survives an abrupt client disconnect and keeps accepting.
#[tokio::test]
async fn an_abrupt_disconnect_does_not_stop_the_listener() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");

    let state = ServerState::new(ServerConfig {
        bind: addr,
        config: test_config(),
        credentials: CredentialStore::with_password(USER, PASSWORD),
        frontend_tls: None,
        pool_min: 4,
        pool_max: 1024,
    });
    tokio::spawn(serve(listener, state));

    // Connect and drop without sending anything.
    drop(TcpStream::connect(addr).await.expect("first connect"));

    // The acceptor must still be alive to take the next connection.
    let mut second = TcpStream::connect(addr).await.expect("second connect");

    // Send a real startup so the second session actually progresses; the point
    // is only that the listener survived the first client's abrupt exit.
    write_startup_payload(
        &mut second,
        &startup_message(format!("user\x00{USER}\x00\x00").as_bytes()),
    )
    .await;

    let mut client = ScramClient::new(USER, PASSWORD, CLIENT_NONCE);
    begin_sasl(&mut second, &client.client_first()).await;
    let server_first = read_server_first(&mut second).await;
    client.handle_server_first(&server_first);
    write_message(&mut second, MSG_PASSWORD, client.client_final().as_bytes()).await;
    assert_eq!(
        read_server_final(&mut second).await,
        client.expected_server_final()
    );
}
