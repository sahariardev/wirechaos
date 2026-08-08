use crate::proxy::buffer_pool::{MultiBufferPool, PooledBytes};
use crate::proxy::conn_read::ConnRead;
use crate::proxy::conn_write::ConnWrite;
use crate::proxy::packet::MessageReader;
use std::sync::Arc;
use tokio::io;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;

pub struct Conn {
    buffer_reader: BufReader<ConnRead>,
    buffer_writer: BufWriter<ConnWrite>,
    pool: Arc<MultiBufferPool>,
    ssl_done: bool,
    tls_acceptor: Option<TlsAcceptor>,
}

const MAX_STARTUP_PACKET_LENGTH: u32 = 10000;
const CANCEL_REQUEST_CODE: u32 = (1234 << 16) | 5678;
const SSL_REQUEST_CODE: u32 = (1234 << 16) | 5679;
const GSSENC_REQUEST_CODE: u32 = (1234 << 16) | 5680;

impl Conn {
    pub fn new(
        stream: TcpStream,
        pool: Arc<MultiBufferPool>,
        tls_acceptor: Option<TlsAcceptor>,
    ) -> Self {
        let (read_half, write_half) = stream.into_split();
        Self {
            buffer_reader: BufReader::new(ConnRead::Plain(read_half)),
            buffer_writer: BufWriter::new(ConnWrite::Plain(write_half)),
            pool,
            ssl_done: false,
            tls_acceptor,
        }
    }

    pub async fn handle(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        todo!("handle message")
    }

    pub async fn handle_startup(mut self) -> Result<Self, Box<dyn std::error::Error>> {
        let buf = self.read_startup_packet().await?;
        let mut message_reader = MessageReader::new(buf);
        let protocol_code = message_reader.read_u32()?;

        match protocol_code {
            SSL_REQUEST_CODE => {
                if self.ssl_done {
                    return Err(Box::from("SSL Request is already done"));
                }
                //handle ssl request code
                self.ssl_done = true;
                self.buffer_writer.write_all(b"S").await?;
                self.buffer_writer.flush().await?;
                
                self = self.promote_to_tls().await?;
            }
            _ => {}
        }

        Ok(self)
    }

    async fn promote_to_tls(mut self) -> Result<Self, Box<dyn std::error::Error>> {
        let ConnRead::Plain(read_half) = self.buffer_reader.into_inner() else {
            unreachable!("ssl_done guard prevents a double upgrade")
        };

        let ConnWrite::Plain(write_half) = self.buffer_writer.into_inner() else {
            unreachable!("ssl_done guard prevents a double upgrade")
        };

        let tcp = read_half.reunite(write_half)?;
        let acceptor = self.tls_acceptor.as_ref().ok_or("TLS acceptor not set")?;

        let tls = acceptor.accept(tcp).await?;

        let (read_half, write_half) = tokio::io::split(tls);
        self.buffer_reader = BufReader::new(ConnRead::Tls(read_half));
        self.buffer_writer = BufWriter::new(ConnWrite::Tls(write_half));
        Ok(self)
    }

    pub async fn read_message_length(&mut self) -> Result<usize, Box<dyn std::error::Error>> {
        let mut hdr = [0u8; 4];
        self.buffer_reader.read_exact(&mut hdr).await?;
        let len = u32::from_be_bytes(hdr) as usize;

        if len < 4 {
            return Err(Box::new(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid message length: {}", len),
            )));
        }

        Ok(len - 4)
    }

    pub async fn read_startup_packet(&mut self) -> Result<PooledBytes, Box<dyn std::error::Error>> {
        let length = self.read_message_length().await?;

        if length > MAX_STARTUP_PACKET_LENGTH as usize {
            return Err(Box::new(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid message length: {}", length),
            )));
        }

        let message = self.read_message_body(length).await?;

        if message.is_none() {
            return Err(Box::new(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Message body is empty",
            )));
        }

        Ok(message.unwrap())
    }

    pub async fn read_message_body(
        &mut self,
        length: usize,
    ) -> Result<Option<PooledBytes>, Box<dyn std::error::Error>> {
        if length == 0 {
            return Ok(None);
        }

        let pool = self.pool.clone();

        let mut buf = pool.get(length);

        self.buffer_reader.read_exact(&mut buf).await?;

        Ok(Some(buf))
    }
}
