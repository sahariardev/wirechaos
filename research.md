Why the "simple" enum won't compile

The version I sketched earlier (enum Stream { Plain(TcpStream), Tls(TlsStream<TcpStream>) }) stored a copy of the stream in both BufReader and BufWriter. That works for
TcpStream because it's a cheap Arc clone. But I checked your lockfile: tokio-rustls 0.24.1's TlsStream derives only Debug, not Clone (src/server.rs:14). So you can't put the
same TlsStream into two owned buffers. The fix is to split the TLS stream into owned halves with tokio::io::split (the one sanctioned way to get two owners out of any non-Clone
AsyncRead + AsyncWrite).

The code

use std::pin::Pin;
use std::task::{Context, Poll};

use crate::proxy::buffer_pool::{MultiBufferPool, PooledBytes};
use crate::proxy::packet::MessageReader;
use std::sync::Arc;
use tokio::io;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

/// Read half of the transport. Two enums (not one) because after TLS the read
/// and write halves genuinely are different types — `TlsStream` isn't `Clone`,
/// so it's split into `ReadHalf`/`WriteHalf`.
enum ConnRead {
Plain(TcpStream),
Tls(tokio::io::ReadHalf<TlsStream<TcpStream>>),
}

enum ConnWrite {
Plain(TcpStream),
Tls(tokio::io::WriteHalf<TlsStream<TcpStream>>),
}

impl AsyncRead for ConnRead {
fn poll_read(
self: Pin<&mut Self>,
cx: &mut Context<'_>,
buf: &mut io::ReadBuf<'_>,
) -> Poll<io::Result<()>> {
match self.get_mut() {
ConnRead::Plain(s) => Pin::new(s).poll_read(cx, buf),
ConnRead::Tls(s) => Pin::new(s).poll_read(cx, buf),
}
}
}

impl AsyncWrite for ConnWrite {
fn poll_write(
self: Pin<&mut Self>,
cx: &mut Context<'_>,
buf: &[u8],
) -> Poll<io::Result<usize>> {
match self.get_mut() {
ConnWrite::Plain(s) => Pin::new(s).poll_write(cx, buf),
ConnWrite::Tls(s) => Pin::new(s).poll_write(cx, buf),
}
}

      fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
          match self.get_mut() {
              ConnWrite::Plain(s) => Pin::new(s).poll_flush(cx),
              ConnWrite::Tls(s) => Pin::new(s).poll_flush(cx),
          }
      }

      fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
          match self.get_mut() {
              ConnWrite::Plain(s) => Pin::new(s).poll_shutdown(cx),
              ConnWrite::Tls(s) => Pin::new(s).poll_shutdown(cx),
          }
      }
}

pub struct Conn {
buffer_reader: BufReader<ConnRead>,
buffer_writer: BufWriter<ConnWrite>,
pool: Arc<MultiBufferPool>,
ssl_done: bool,
tls_acceptor: Option<TlsAcceptor>,
// `socket: TcpStream` is gone — the reader/writer already hold cheap
// clones of it, and promotion re-derives one via get_ref().
}

const MAX_STARTUP_PACKET_LENGTH: u32 = 10000;
const CANCEL_REQUEST_CODE: u32 = (1234 << 16) | 5678;
const SSL_REQUEST_CODE: u32 = (1234 << 16) | 5679;
const GSSENC_REQUEST_CODE: u32 = (1234 << 16) | 5680;

impl Conn {
pub fn new(stream: TcpStream, pool: Arc<MultiBufferPool>) -> Self {
Self {
buffer_reader: BufReader::new(ConnRead::Plain(stream.clone())),
buffer_writer: BufWriter::new(ConnWrite::Plain(stream)),
pool,
ssl_done: false,
tls_acceptor: None,
}
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
                  self.ssl_done = true;

                  self.buffer_writer.write_all(b"S").await?;
                  self.buffer_writer.flush().await?;

                  self.promote_to_tls().await?;
              }
              _ => {}
          }

          todo!("handle startup")
      }

      /// Swap the plaintext transport for TLS, in place.
      async fn promote_to_tls(&mut self) -> Result<(), Box<dyn std::error::Error>> {
          // Defensive: tokio's BufWriter does NOT flush on drop, so make sure
          // the 'S' byte is out before we drop the plaintext writer.
          self.buffer_writer.flush().await?;

          // Clone a TcpStream handle out of the reader (get_ref borrows, so no
          // move-out-of-&mut-self / placeholder dance). All clones share the socket.
          let tcp = match self.buffer_reader.get_ref() {
              ConnRead::Plain(s) => s.clone(),
              ConnRead::Tls(_) => unreachable!("ssl_done guard prevents a double upgrade"),
          };

          let acceptor = self.tls_acceptor
              .as_ref()
              .ok_or("TLS acceptor not configured")?;
          let tls = acceptor.accept(tcp).await?; // TlsStream<TcpStream>

          // Split the non-Clone TLS stream into owned halves.
          let (read_half, write_half) = tokio::io::split(tls);

          // Reassigning drops the old plaintext buffers (already flushed).
          self.buffer_reader = BufReader::new(ConnRead::Tls(read_half));
          self.buffer_writer = BufWriter::new(ConnWrite::Tls(write_half));
          Ok(())
      }

      // read_message_length / read_startup_packet / read_message_body: unchanged.
      // They already go through self.buffer_reader / self.pool and work over the
      // new enums identically.
}

Two things this changes beyond the enum

1. I removed your fill_buf() MITM check — it was broken. I read tokio 1.52.3's poll_fill_buf (src/io/util/buf_reader.rs:123): when the internal buffer is empty it poll_reads the
   self.buffer_reader = BufReader::new(ConnRead::Tls(read_half));
   self.buffer_writer = BufWriter::new(ConnWrite::Tls(write_half));
   Ok(())
   }

   // read_message_length / read_startup_packet / read_message_body: unchanged.
   // They already go through self.buffer_reader / self.pool and work over the
   // new enums identically.
   }

Two things this changes beyond the enum

1. I removed your fill_buf() MITM check — it was broken. I read tokio 1.52.3's poll_fill_buf (src/io/util/buf_reader.rs:123): when the internal buffer is empty it poll_reads the
   socket. After you send 'S', a legit client immediately starts the TLS handshake, so fill_buf() will (a) block on slow clients, or (b) catch the client's ClientHello and wrongly
   reject it as "unencrypted data." With this design you don't need the check at all: if a client stuffed plaintext after the SSLRequest, those bytes sit in the old BufReader's
   buffer, get dropped when it's discarded, and the client sees a broken TLS handshake — rejection is automatic. If you want to keep an explicit check, it must run before sending
   'S' and peek only already-buffered data, not block.

2. The tokio::io::split BiLock tradeoff. split shares the TLS stream through a BiLock, so every read/write does a lock acquire. In your one-task-per-connection model (read →
   process → write, sequentially) it's never contended — a couple of atomics per poll, noise next to TLS record decryption. It only starts to matter if you later split reads and
   writes into two concurrent tasks; if you ever do, revisit this and prefer the promote-before-Conn::new (Option A) shape.

Net: socket field gone, promotion is a single method, and read_message_* work unchanged over both transports.
