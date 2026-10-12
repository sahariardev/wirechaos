#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::fs;
use std::net::SocketAddr;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use common::*;
use tempfile::tempdir;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use wirechaos_core::proxy::auth::credentials::CredentialStore;
use wirechaos_core::proxy::auth::verifier::{Verifier, VerifierProvider};

/// Spawn a server that accepts one connection, pretends the startup message
/// already supplied `user`, and runs the authentication exchange.
async fn spawn_auth_server<V>(
    provider: V,
    user: Option<&str>,
) -> (SocketAddr, JoinHandle<Result<Option<Vec<u8>>, String>>)
where
    V: VerifierProvider,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let user = user.map(str::to_string);

    let server = tokio::spawn(async move {
        let (socket, _peer) = listener.accept().await.expect("accept");
        let mut conn = test_conn_for(socket, None, provider);
        conn.user = user;

        conn.handle_authentication()
            .await
            .map_err(|error| error.to_string())
    });

    (addr, server)
}

/// Run a full exchange against a secret-only store and return the server's
/// outcome (the extracted ClientKey, or a failure message).
async fn authenticate(
    user: &str,
    password: &str,
    store: CredentialStore,
) -> Result<Option<Vec<u8>>, String> {
    let (addr, server) = spawn_auth_server(store, Some(user)).await;
    let mut tcp = TcpStream::connect(addr).await.expect("connect");
    let mut client = ScramClient::new(user, password, CLIENT_NONCE);

    begin_sasl(&mut tcp, &client.client_first()).await;
    let server_first = read_server_first(&mut tcp).await;
    client.handle_server_first(&server_first);
    write_message(&mut tcp, MSG_PASSWORD, client.client_final().as_bytes()).await;

    assert_eq!(
        read_server_final(&mut tcp).await,
        client.expected_server_final()
    );
    read_authentication_ok(&mut tcp).await;

    server.await.expect("server task completed cleanly")
}

#[tokio::test]
async fn secret_only_store_authenticates_a_client_without_any_plaintext() {
    // The store holds only the SCRAM secret; the proxy must never need the
    // password to verify the client's proof.
    let secret = Verifier::from_password(PASSWORD, SALT, SALT_ITERATIONS).to_pg_secret();
    let store = CredentialStore::from_yaml(&format!(
        "users:\n  - name: {USER}\n    scram_secret: \"{secret}\"\n"
    ))
    .expect("valid store");

    let (addr, server) = spawn_auth_server(store, Some(USER)).await;
    let mut tcp = TcpStream::connect(addr).await.expect("connect");
    let mut client = ScramClient::new(USER, PASSWORD, CLIENT_NONCE);

    begin_sasl(&mut tcp, &client.client_first()).await;
    let server_first = read_server_first(&mut tcp).await;
    client.handle_server_first(&server_first);
    write_message(&mut tcp, MSG_PASSWORD, client.client_final().as_bytes()).await;

    assert_eq!(
        read_server_final(&mut tcp).await,
        client.expected_server_final()
    );
    read_authentication_ok(&mut tcp).await;

    let outcome = server
        .await
        .expect("server task completed cleanly")
        .expect("auth must succeed");

    assert_eq!(outcome.as_deref(), Some(client.client_key()));
}

#[tokio::test]
async fn secret_only_store_sends_the_stored_salt_so_the_client_key_is_reusable() {
    // Salt reuse (auth design §5.4): the server-first salt must be the stored
    // one, because that is what makes the captured ClientKey valid for the
    // backend.
    let salt = [0x11u8; 16];
    let secret = Verifier::from_password(PASSWORD, salt, SALT_ITERATIONS).to_pg_secret();
    let store = CredentialStore::from_yaml(&format!(
        "users:\n  - name: {USER}\n    scram_secret: \"{secret}\"\n"
    ))
    .expect("valid store");

    let (addr, _server) = spawn_auth_server(store, Some(USER)).await;
    let mut tcp = TcpStream::connect(addr).await.expect("connect");
    begin_sasl(
        &mut tcp,
        &ScramClient::new(USER, PASSWORD, CLIENT_NONCE).client_first(),
    )
    .await;

    let server_first = read_server_first(&mut tcp).await;
    let salt_b64 = server_first
        .split(',')
        .find_map(|attr| attr.strip_prefix("s="))
        .expect("server-first must carry a salt");

    assert_eq!(
        B64.decode(salt_b64).unwrap(),
        salt,
        "the proxy must send the stored salt, not a fresh one"
    );
    assert!(server_first.contains(",i=4096"));
}

#[tokio::test]
async fn reload_adds_a_user_without_disturbing_live_sessions() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("users.yaml");
    fs::write(
        &path,
        format!("users:\n  - name: {USER}\n    password: \"{PASSWORD}\"\n"),
    )
    .unwrap();

    let store = CredentialStore::from_file(&path).expect("initial store");
    let handle = store.reload_handle();

    // A live session starts before the reload...
    let (addr_a, server_a) = spawn_auth_server(store.clone(), Some(USER)).await;
    let mut live = TcpStream::connect(addr_a).await.expect("connect");
    let mut live_client = ScramClient::new(USER, PASSWORD, CLIENT_NONCE);
    begin_sasl(&mut live, &live_client.client_first()).await;
    let server_first = read_server_first(&mut live).await;
    live_client.handle_server_first(&server_first);

    // ...then the file gains a user and is reloaded.
    fs::write(
        &path,
        format!(
            "users:\n  - name: {USER}\n    password: \"{PASSWORD}\"\n  - name: carol\n    password: \"carol-pw\"\n"
        ),
    )
    .unwrap();
    let report = handle.reload().expect("reload must succeed");
    assert_eq!(report.user_count, 2);

    // The in-flight exchange still completes against the old snapshot.
    write_message(
        &mut live,
        MSG_PASSWORD,
        live_client.client_final().as_bytes(),
    )
    .await;
    assert_eq!(
        read_server_final(&mut live).await,
        live_client.expected_server_final()
    );
    read_authentication_ok(&mut live).await;
    server_a
        .await
        .expect("server task completed cleanly")
        .expect("live exchange must succeed");

    // The new user can authenticate immediately.
    let (addr_b, server_b) = spawn_auth_server(store, Some("carol")).await;
    let mut tcp = TcpStream::connect(addr_b).await.expect("connect");
    let mut carol = ScramClient::new("carol", "carol-pw", CLIENT_NONCE);
    begin_sasl(&mut tcp, &carol.client_first()).await;
    let server_first = read_server_first(&mut tcp).await;
    carol.handle_server_first(&server_first);
    write_message(&mut tcp, MSG_PASSWORD, carol.client_final().as_bytes()).await;
    assert_eq!(
        read_server_final(&mut tcp).await,
        carol.expected_server_final()
    );
    server_b
        .await
        .expect("server task completed cleanly")
        .expect("carol must authenticate");
}

#[tokio::test]
async fn a_broken_reload_keeps_the_previous_store_and_reports_readiness() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("users.yaml");
    fs::write(
        &path,
        format!("users:\n  - name: {USER}\n    password: \"{PASSWORD}\"\n"),
    )
    .unwrap();

    let store = CredentialStore::from_file(&path).unwrap();
    let handle = store.reload_handle();
    fs::write(
        &path,
        "users:\n  - name: broken\n    scram_secret: \"SCRAM-SHA-1$4096:AA$AA:AA\"\n",
    )
    .unwrap();

    let error = handle
        .reload()
        .err()
        .expect("invalid file must be rejected");
    assert!(
        error.to_string().contains("broken"),
        "the report must name the entry: {error}"
    );

    // The previous user still authenticates, and readiness reflects the problem.
    assert!(store.lookup(USER).await.unwrap().is_some());
    assert!(handle.last_reload_error().is_some());
}

#[tokio::test]
async fn store_outage_is_reported_as_unavailable_not_as_a_bad_password() {
    let store = CredentialStore::failing("lookup database down");
    let (addr, _server) = spawn_auth_server(store, Some(USER)).await;

    let mut tcp = TcpStream::connect(addr).await.expect("connect");
    let error = read_error(&mut tcp).await;

    assert_eq!(error[&'S'], "FATAL");
    assert_eq!(
        error[&'C'], "08006",
        "an outage must not look like a credential failure"
    );
    assert!(!error[&'M'].contains("password authentication failed"));
}

#[tokio::test]
async fn logs_never_contain_secret_material() {
    let capture = LogCapture::start();
    let secret = Verifier::from_password(PASSWORD, SALT, SALT_ITERATIONS).to_pg_secret();

    let store = CredentialStore::from_yaml(&format!(
        "users:\n  - name: {USER}\n    password: \"{PASSWORD}\"\n  - name: bob\n    scram_secret: \"{secret}\"\n"
    ))
    .expect("valid store");

    // A failed attempt still writes logs.
    let (addr, _server) = spawn_auth_server(store, Some(USER)).await;
    let mut tcp = TcpStream::connect(addr).await.expect("connect");
    let mut client = ScramClient::new(USER, "wrong-password", CLIENT_NONCE);
    begin_sasl(&mut tcp, &client.client_first()).await;
    let server_first = read_server_first(&mut tcp).await;
    client.handle_server_first(&server_first);
    write_message(&mut tcp, MSG_PASSWORD, client.client_final().as_bytes()).await;
    let _ = read_error(&mut tcp).await;

    let logs = capture.text();
    assert!(!logs.contains(PASSWORD), "the password leaked into logs");
    assert!(
        !logs.contains(&secret),
        "the stored secret leaked into logs: {logs}"
    );
    assert!(
        !logs.contains(&B64.encode(SALT)),
        "key material leaked into logs"
    );
    assert!(
        logs.contains(USER),
        "the user name should still be logged for triage"
    );
}

#[tokio::test]
async fn password_form_applies_saslprep_before_deriving_the_verifier() {
    // `I\u{00AD}X` prepares to `IX`, so a client that sends `IX` must match a
    // store built from the unprepared form.
    let store = CredentialStore::from_yaml(&format!(
        "users:\n  - name: {USER}\n    password: \"I\u{00AD}X\"\n"
    ))
    .expect("valid store");

    let outcome = authenticate(USER, "IX", store).await;
    assert!(
        outcome.expect("auth must succeed").is_some(),
        "the extracted ClientKey must be handed back"
    );
}
