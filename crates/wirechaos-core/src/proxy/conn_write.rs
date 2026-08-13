use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncWrite, WriteHalf};
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;

#[derive(Default)]
pub enum ConnWrite{
    #[default]
    Empty,
    Plain(OwnedWriteHalf),
    Tls(WriteHalf<TlsStream<TcpStream>>),
}

impl AsyncWrite for ConnWrite {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            ConnWrite::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
            ConnWrite::Tls(stream) => Pin::new(stream).poll_write(cx, buf),
            ConnWrite::Empty => Poll::Ready(Ok(0)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            ConnWrite::Plain(stream) => Pin::new(stream).poll_flush(cx),
            ConnWrite::Tls(stream) => Pin::new(stream).poll_flush(cx),
            ConnWrite::Empty => Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            ConnWrite::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            ConnWrite::Tls(stream) => Pin::new(stream).poll_shutdown(cx),
            ConnWrite::Empty => Poll::Ready(Ok(())),
        }
    }
}