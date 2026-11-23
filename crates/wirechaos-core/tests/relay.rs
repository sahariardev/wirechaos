//! End-to-end relay tests over a real client TCP connection.

mod common;

use common::*;
use tokio::net::TcpStream;
use wirechaos_core::proxy::backend::registry::Registry;
use wirechaos_core::proxy::conn_registry::ConnRegistry;

#[tokio::test]
async fn simple_query_passthrough_reaches_the_backend_and_returns() {
    let addr = spawn_startup_server(Registry::new(), ConnRegistry::new(100), test_config()).await;

    let mut client = TcpStream::connect(addr).await.expect("connect proxy");
    let _post_auth = complete_startup_and_auth(&mut client).await;

    write_message(&mut client, b'Q', b"select 1\0").await;

    let first = read_message(&mut client).await;
    assert_eq!(first.0, b'C', "expected CommandComplete");
    let second = read_message(&mut client).await;
    assert_eq!(second.0, b'Z', "expected ReadyForQuery");
    assert_eq!(second.1, b"I");
}
