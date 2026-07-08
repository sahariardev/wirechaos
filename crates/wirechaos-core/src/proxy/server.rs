use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};
use tracing::{info, warn};

pub async fn run_server() -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    info!("server started on port 8080");

    loop {
        match listener.accept().await {
            Ok((socket, addr)) => {
                info!("accepted connection from {:?}", addr);
                tokio::spawn(async move {
                    handle_connection(socket, addr)
                        .await
                        .expect("failed to handle connection");
                });
            }
            Err(e) => {
                warn!("failed to accept client connection: {}", e);
            }
        }
    }
}

async fn handle_connection(mut socket: TcpStream, addr: SocketAddr) -> anyhow::Result<()> {
    info!("accepted connection from {:?}", addr);

    let (mut reader, mut writer) = socket.split();

    let bytes_copied = tokio::io::copy(&mut reader, &mut writer).await?;
    info!("bytes copied: {:?}", bytes_copied);
    Ok(())
}

//todo:: implement wire protocol step by step
// first handle tls non tls
