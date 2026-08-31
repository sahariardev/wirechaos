use crate::proxy::buffer_pool::{MultiBufferPool, PooledBytes};
use crate::proxy::conn_read::ConnRead;
use crate::proxy::conn_write::ConnWrite;
use crate::proxy::packet::MessageReader;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;

pub struct Conn {
    buffer_reader: BufReader<ConnRead>,
    buffer_writer: BufWriter<ConnWrite>,
    pool: Arc<MultiBufferPool>,
    //todo:: rename this to tls
    ssl_done: bool,
    required_tls: bool,
    gss_done: bool,
    tls_acceptor: Option<TlsAcceptor>,
    protocol_version: Option<u32>,
    params: HashMap<String, String>,
}

const MAX_STARTUP_PACKET_LENGTH: u32 = 10000;
const CANCEL_REQUEST_CODE: u32 = (1234 << 16) | 5678;
const SSL_REQUEST_CODE: u32 = (1234 << 16) | 5679;
const GSSENC_REQUEST_CODE: u32 = (1234 << 16) | 5680;

//protocol version
const PROTOCOL_MAJOR_VERSION: u32 = 3;
const PROTOCOL_MINOR_VERSION: u32 = 0;
const PROTOCOL_VERSION_NUMBER: u32 = (PROTOCOL_MAJOR_VERSION << 16) | PROTOCOL_MINOR_VERSION;

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
            gss_done: false,
            //todo:: pass this from parent config
            required_tls: false,
            tls_acceptor,
            protocol_version: None,
            params: HashMap::new(),
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
                self.handle_ssl_request().await?;
            }
            GSSENC_REQUEST_CODE => {
                self.handle_gssnc_request().await?;
            }
            CANCEL_REQUEST_CODE => {
                self.handle_cancel_request(&mut message_reader)?;
            }

            PROTOCOL_VERSION_NUMBER => {
                if self.required_tls && !self.ssl_done {
                    //throw error in this case
                }
            }
            _ => {}
        }

        Ok(())
    }

    fn handle_startup_packet(
        &mut self,
        protocol_version: u32,
        message_reader: &mut MessageReader,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.protocol_version = Some(protocol_version);

        while message_reader.remaining() > 0 {
            let key = message_reader.read_string()?;

            if key == "" {
                break;
            }

            let value = message_reader.read_string()?;
            self.params.insert(key, value);
        }

        //parse param from key value pair

        //initiate authenticate
        todo!("handle_startup packet")
    }

    fn handle_cancel_request(
        &mut self,
        message_reader: &mut MessageReader,
    ) -> Result<(), Box<dyn std::error::Error>> {
        todo!("handle cancel request")
    }
    async fn handle_gssnc_request(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.gss_done {
            return Err(Box::from("GSSENC Request is already done"));
        }
        self.gss_done = true;

        self.buffer_writer.write_all(b"N").await?;
        self.buffer_writer.flush().await?;

        Ok(())
    }
    async fn handle_ssl_request(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.ssl_done {
            return Err(Box::from("SSL Request is already done"));
        }
        self.ssl_done = true;

        if self.tls_acceptor.is_some() {
            // Offer TLS: the client expects 'S' and then runs the
            // handshake on this socket.
            self.buffer_writer.write_all(b"S").await?;
            self.buffer_writer.flush().await?;
            self.promote_to_tls().await?;
        } else {
            // No TLS support configured: decline and keep the
            // connection in plaintext.
            self.buffer_writer.write_all(b"N").await?;
            self.buffer_writer.flush().await?;
        }

        Ok(())
    }

    async fn promote_to_tls(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let reader = std::mem::replace(&mut self.buffer_reader, BufReader::new(ConnRead::Empty));
        let writer = std::mem::replace(&mut self.buffer_writer, BufWriter::new(ConnWrite::Empty));

        let ConnRead::Plain(read_half) = reader.into_inner() else {
            unreachable!("ssl_done guard prevents a double upgrade")
        };

        let ConnWrite::Plain(write_half) = writer.into_inner() else {
            unreachable!("ssl_done guard prevents a double upgrade")
        };

        let tcp = read_half.reunite(write_half)?;
        let acceptor = self.tls_acceptor.as_ref().ok_or("TLS acceptor not set")?;

        let tls = acceptor.accept(tcp).await?;

        let (read_half, write_half) = tokio::io::split(tls);
        self.buffer_reader = BufReader::new(ConnRead::Tls(read_half));
        self.buffer_writer = BufWriter::new(ConnWrite::Tls(write_half));
        Ok(())
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

    /// Write raw bytes to the peer over the current transport (plain or TLS)
    /// and flush. Used by the proxy to send protocol messages to the client.
    pub async fn write_raw(&mut self, data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        self.buffer_writer.write_all(data).await?;
        self.buffer_writer.flush().await?;
        Ok(())
    }
}
