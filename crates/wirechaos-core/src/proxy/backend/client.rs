use crate::proxy::conn::SSL_REQUEST_CODE;
use crate::proxy::error::ProxyError;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
const BACKEND_TIMEOUT: Duration = Duration::from_secs(5);
pub struct Backend {
    parameters_status_values: HashMap<String, String>,
    is_ssl: bool,
    addr: SocketAddr,
}

impl Backend {
    pub fn get_param_status_values(&self) -> Vec<(String, String)> {
        let mut params: Vec<(String, String)> = Vec::new();

        for (key, value) in &self.parameters_status_values {
            params.push((key.to_owned(), value.to_owned()));
        }

        params
    }

    pub async fn new(is_ssl: bool, host_port: String) -> Result<Arc<Self>, ProxyError> {
        let addr: SocketAddr = host_port.parse().map_err(|e| ProxyError::internal(e))?;

        let backend = Self {
            is_ssl,
            addr,
            parameters_status_values: HashMap::new(),
        };

        //timeout
        let mut tcp = timeout(BACKEND_TIMEOUT, TcpStream::connect(addr))
            .await
            .expect("backend connection timeout")
            .expect("backend connection failed");
        //write the first message

        if is_ssl {
            tcp.write_all(&8u32.to_be_bytes()).await.expect("write");
            tcp.write_all(&SSL_REQUEST_CODE.to_be_bytes())
                .await
                .expect("write");
            tcp.flush().await.expect("flush");

            let mut buf = [0u8; 1];
            tcp.read_exact(&mut buf).await.expect("read");

            if buf[0] != b'S' {
                //todo:: Return ProxyError::BackendRefused
                //todo:: need to decide what kind of response it should return to the client
            }

            //server accept tls connection, initiate tls request
        }
        //send auth

        //send SSL request if ssl supportes
        todo!("implement this")
    }
}

//firs connect with the backend
// >> hostname and port needed
// two type of connection with ssl and without ssl
// if server returns N, handle it, if connection error happens handle it, in both
// cases tell client to close connection
//
// need to handle server sends N
