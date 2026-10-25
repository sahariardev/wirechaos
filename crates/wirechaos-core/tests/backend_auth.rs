//! Task 5 acceptance tests: the proxy as a PostgreSQL client.
//!
//! The fake backend is a real protocol peer: it verifies the proxy's SCRAM
//! proof, checks the `-PLUS` binding against its own certificate, and records
//! what it received.

// Test scaffolding: panicking is how a failed expectation is reported.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::HashMap;

use common::fake_backend::FakeBackend;
use common::*;
use tokio::net::{TcpListener, TcpStream};
use wirechaos_core::proxy::auth::credentials::CredentialStore;
use wirechaos_core::proxy::auth::verifier::Verifier;
use wirechaos_core::proxy::backend::registry::Registry;
use wirechaos_core::proxy::backend::session_key_secret::SessionKeySecret;
use wirechaos_core::proxy::backend::BackendKeyData;
use wirechaos_core::proxy::config::{BackendTlsMode, ChannelBindingMode, Config};
use wirechaos_core::proxy::conn_registry::ConnRegistry;

fn secret_store(secret: &str) -> CredentialStore {
    CredentialStore::from_yaml(&format!(
        "users:\n  - name: {USER}\n    scram_secret: \"{secret}\"\n"
    ))
    .expect("valid secret-only store")
}

/// Complete the frontend exchange, then read the backend failure. The proxy
/// always sends `AuthenticationOk` for the *client* before it touches the
/// backend, so a backend failure arrives as an ErrorResponse afterwards.
async fn authenticate_then_read_error(tcp: &mut TcpStream) -> HashMap<char, String> {
    let startup = format!("user\x00{USER}\x00\x00");
    write_startup_payload(tcp, &startup_message(startup.as_bytes())).await;

    let mut client = ScramClient::new(USER, PASSWORD, CLIENT_NONCE);
    begin_sasl(tcp, &client.client_first()).await;

    let server_first = read_server_first(tcp).await;
    client.handle_server_first(&server_first);
    write_message(tcp, MSG_PASSWORD, client.client_final().as_bytes()).await;
    assert_eq!(read_server_final(tcp).await, client.expected_server_final());

    read_authentication_ok(tcp).await;
    read_error(tcp).await
}

#[tokio::test]
async fn proxy_authenticates_to_a_scram_backend_with_a_stored_secret_only() {
    let verifier = Verifier::from_password(PASSWORD, SALT, SALT_ITERATIONS);
    let secret = verifier.to_pg_secret();

    let backend = FakeBackend::start()
        .requiring_scram()
        .with_secret(&secret)
        .start()
        .await;

    let addr = spawn_proxy_with_provider(
        secret_store(&secret),
        Registry::new(),
        ConnRegistry::new(10),
        config_for_backend(backend.addr()),
    )
    .await;

    let mut tcp = TcpStream::connect(addr).await.expect("connect");
    let post_auth = complete_startup_and_auth(&mut tcp).await;

    assert_eq!(post_auth.ready_status, b'I');
    assert!(
        backend.saw_authentication_ok(),
        "the proxy must have authenticated to the backend"
    );
}

#[tokio::test]
async fn backend_parameter_status_and_cancel_key_are_captured() {
    let backend_key = BackendKeyData {
        pid: 4242,
        secret: 0x0BCD_1234,
    };

    let backend = FakeBackend::start()
        .with_trust_auth()
        .with_parameter("client_encoding", "UTF8")
        .with_backend_key(backend_key.pid, backend_key.secret)
        .start()
        .await;

    let registry = Registry::new();
    let addr = spawn_proxy_with_provider_holding(
        TestVerifierProvider::new(),
        registry.clone(),
        ConnRegistry::new(10),
        config_for_backend(backend.addr()),
    )
    .await;

    let mut tcp = TcpStream::connect(addr).await.expect("connect");
    let post_auth = complete_startup_and_auth(&mut tcp).await;

    let parameters: Vec<_> = post_auth
        .parameters
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    assert_eq!(
        parameters,
        vec![("server_version", "17.2"), ("client_encoding", "UTF8")],
        "backend ParameterStatus values must be forwarded in order"
    );

    let issued = post_auth
        .backend_key
        .expect("the client must receive a key");
    assert_ne!(
        issued,
        (backend_key.pid, backend_key.secret),
        "the client must receive a proxy-minted key, not the backend's"
    );

    let recorded = registry
        .lookup_backend_key(SessionKeySecret {
            key: issued.0,
            secret: issued.1,
        })
        .expect("the registry must hold the backend's real key");
    assert_eq!(recorded, backend_key);
}

#[tokio::test]
async fn unreachable_backend_becomes_a_fatal_error_not_a_hang() {
    let dead = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind then drop")
        .local_addr()
        .expect("dead address");

    let addr = spawn_proxy_with_provider(
        TestVerifierProvider::new(),
        Registry::new(),
        ConnRegistry::new(10),
        config_for_backend(dead),
    )
    .await;

    let mut tcp = TcpStream::connect(addr).await.expect("connect");
    let error = authenticate_then_read_error(&mut tcp).await;

    assert_eq!(error[&'S'], "FATAL");
    assert_eq!(error[&'C'], "08006");
    assert!(
        error[&'M'].contains("backend"),
        "unexpected message: {:?}",
        error[&'M']
    );
}

#[tokio::test]
async fn wrong_backend_secret_is_generalised_for_the_client_but_detailed_in_the_log() {
    let capture = LogCapture::start();

    let backend = FakeBackend::start()
        .requiring_scram()
        .with_secret(
            &Verifier::from_password("a-different-password", SALT, SALT_ITERATIONS).to_pg_secret(),
        )
        .start()
        .await;

    let proxy_secret = Verifier::from_password(PASSWORD, SALT, SALT_ITERATIONS).to_pg_secret();
    let addr = spawn_proxy_with_provider(
        secret_store(&proxy_secret),
        Registry::new(),
        ConnRegistry::new(10),
        config_for_backend(backend.addr()),
    )
    .await;

    let mut tcp = TcpStream::connect(addr).await.expect("connect");
    let error = authenticate_then_read_error(&mut tcp).await;

    assert_eq!(error[&'C'], "28P01");
    assert_eq!(
        error[&'M'], "backend authentication failed",
        "the client must not learn backend detail"
    );

    let logs = capture.text();
    assert!(
        logs.contains("password authentication failed"),
        "the log needs the backend's detail: {logs}"
    );
    assert!(!logs.contains(PASSWORD), "no secret material in logs");
}

#[tokio::test]
async fn md5_only_backend_is_refused_when_only_a_secret_is_stored() {
    let backend = FakeBackend::start().requiring_md5().start().await;
    let secret = Verifier::from_password(PASSWORD, SALT, SALT_ITERATIONS).to_pg_secret();

    let addr = spawn_proxy_with_provider(
        secret_store(&secret),
        Registry::new(),
        ConnRegistry::new(10),
        config_for_backend(backend.addr()),
    )
    .await;

    let mut tcp = TcpStream::connect(addr).await.expect("connect");
    let error = authenticate_then_read_error(&mut tcp).await;

    assert_eq!(error[&'C'], "28P01");
    assert!(
        error[&'M'].contains("MD5") || error[&'M'].contains("authentication method"),
        "the failure must name the real cause: {:?}",
        error[&'M']
    );
    assert!(
        backend.received_md5_response().is_none(),
        "the proxy must never send a bogus MD5 response"
    );
}

#[tokio::test]
async fn cleartext_challenge_is_answered_when_a_plaintext_password_is_configured() {
    let backend = FakeBackend::start()
        .requiring_cleartext()
        .with_password_for(USER, PASSWORD)
        .start()
        .await;

    let addr = spawn_proxy_with_provider(
        CredentialStore::with_password(USER, PASSWORD),
        Registry::new(),
        ConnRegistry::new(10),
        config_for_backend(backend.addr()),
    )
    .await;

    let mut tcp = TcpStream::connect(addr).await.expect("connect");
    let post_auth = complete_startup_and_auth(&mut tcp).await;

    assert_eq!(post_auth.ready_status, b'I');
    assert_eq!(
        backend.received_password().as_deref(),
        Some(PASSWORD),
        "the proxy must answer the cleartext challenge with the configured password"
    );
}

#[tokio::test]
async fn md5_challenge_is_answered_when_a_plaintext_password_is_configured() {
    let backend = FakeBackend::start()
        .requiring_md5()
        .with_password_for(USER, PASSWORD)
        .start()
        .await;

    let addr = spawn_proxy_with_provider(
        CredentialStore::with_password(USER, PASSWORD),
        Registry::new(),
        ConnRegistry::new(10),
        config_for_backend(backend.addr()),
    )
    .await;

    let mut tcp = TcpStream::connect(addr).await.expect("connect");
    let post_auth = complete_startup_and_auth(&mut tcp).await;

    assert_eq!(post_auth.ready_status, b'I');
    assert!(
        backend.received_md5_response().is_some(),
        "the proxy must answer the MD5 challenge with a real response"
    );
}

#[tokio::test]
async fn unsupported_backend_method_is_refused_without_a_silent_fallback() {
    let backend = FakeBackend::start()
        .requiring_unsupported(7) // AuthenticationGSS
        .start()
        .await;

    let addr = spawn_proxy_with_provider(
        TestVerifierProvider::new(),
        Registry::new(),
        ConnRegistry::new(10),
        config_for_backend(backend.addr()),
    )
    .await;

    let mut tcp = TcpStream::connect(addr).await.expect("connect");
    let error = authenticate_then_read_error(&mut tcp).await;

    assert_eq!(error[&'C'], "28P01");
    assert!(
        error[&'M'].contains("GSSAPI"),
        "unexpected message: {:?}",
        error[&'M']
    );
    assert!(!backend.saw_authentication_ok());
}

#[tokio::test]
async fn backend_startup_timeout_is_a_08006() {
    let backend = FakeBackend::start()
        .with_trust_auth()
        .hanging_after_startup()
        .start()
        .await;

    let addr = spawn_proxy_with_provider(
        TestVerifierProvider::new(),
        Registry::new(),
        ConnRegistry::new(10),
        config_for_backend_with_timeouts(backend.addr(), 1_000, 200),
    )
    .await;

    let mut tcp = TcpStream::connect(addr).await.expect("connect");
    let error = authenticate_then_read_error(&mut tcp).await;

    assert_eq!(error[&'C'], "08006");
    assert!(
        error[&'M'].contains("starting up") || error[&'M'].contains("backend"),
        "unexpected message: {:?}",
        error[&'M']
    );

    backend.kill_connection();
}

#[tokio::test]
async fn channel_binding_require_selects_plus_toward_a_tls_backend() {
    let backend = FakeBackend::start()
        .with_tls()
        .requiring_plus()
        .with_password_for(USER, PASSWORD)
        .start()
        .await;

    let mut config = Config::default();
    config.backend.address = backend.addr().to_string();
    config.backend.tls.mode = BackendTlsMode::Prefer;
    config.backend.tls.channel_binding = ChannelBindingMode::Require;
    config.backend.tls.domain = Some("localhost".to_owned());

    let addr = spawn_proxy_with_provider(
        TestVerifierProvider::new(),
        Registry::new(),
        ConnRegistry::new(10),
        std::sync::Arc::new(config),
    )
    .await;

    let mut tcp = TcpStream::connect(addr).await.expect("connect");
    let post_auth = complete_startup_and_auth(&mut tcp).await;

    assert_eq!(post_auth.ready_status, b'I');
    assert_eq!(
        backend.observed_mechanism().as_deref(),
        Some("SCRAM-SHA-256-PLUS"),
        "channel_binding=require must select -PLUS"
    );
    assert!(
        backend.channel_binding_matched(),
        "the backend verified our c= against its certificate"
    );
}

#[tokio::test]
async fn channel_binding_require_fails_when_the_backend_cannot_be_bound() {
    let backend = FakeBackend::start()
        .requiring_scram()
        .with_password_for(USER, PASSWORD)
        .start()
        .await;

    let mut config = Config::default();
    config.backend.address = backend.addr().to_string();
    config.backend.tls.mode = BackendTlsMode::Disable;
    config.backend.tls.channel_binding = ChannelBindingMode::Require;

    let addr = spawn_proxy_with_provider(
        TestVerifierProvider::new(),
        Registry::new(),
        ConnRegistry::new(10),
        std::sync::Arc::new(config),
    )
    .await;

    let mut tcp = TcpStream::connect(addr).await.expect("connect");
    let error = authenticate_then_read_error(&mut tcp).await;

    assert_eq!(error[&'C'], "28P01");
    let message = error[&'M'].to_lowercase();
    assert!(
        message.contains("tls") || message.contains("channel binding"),
        "the failure must explain why binding is impossible: {:?}",
        error[&'M']
    );
}
