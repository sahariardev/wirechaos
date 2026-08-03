use crate::proxy::buffer_pool::{MultiBufferPool, PooledBytes};
use crate::proxy::packet::MessageReader;
use std::sync::Arc;
use tokio::io;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;

pub struct Conn {
    buffer_reader: BufReader<OwnedReadHalf>,
    buffer_writer: BufWriter<OwnedWriteHalf>,
    pool: Arc<MultiBufferPool>,
    ssl_done: bool,
}

const MAX_STARTUP_PACKET_LENGTH: u32 = 10000;
const CANCEL_REQUEST_CODE: u32 = (1234 << 16) | 5678;
const SSL_REQUEST_CODE: u32 = (1234 << 16) | 5679;
const GSSENC_REQUEST_CODE: u32 = (1234 << 16) | 5680;

impl Conn {
    pub fn new(stream: TcpStream, pool: Arc<MultiBufferPool>) -> Self {
        let (reader, writer) = stream.into_split();

        Self {
            buffer_reader: BufReader::new(reader),
            buffer_writer: BufWriter::new(writer),
            pool,
            ssl_done: false,
        }
    }

    pub async fn handle(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        todo!("handle message")
    }

    pub async fn handle_startup(&mut self) -> Result<(), Box<dyn std::error::Error>> {
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

                let check = self.buffer_reader.fill_buf().await?;

                if !check.is_empty() {
                    return Err(Box::from("received unencrypted data after SSL request: possible man-in-the-middle attack"));
                }
                //todo:: promote connection to tls connection

            }
            _ => {}
        }

        todo!("handle startup")
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
