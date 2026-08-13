
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, ReadBuf, ReadHalf, WriteHalf};
use tokio::net::tcp::OwnedReadHalf;
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;

#[derive(Default)]
pub enum ConnRead {
    #[default]
    Empty,
    Plain(OwnedReadHalf),
    Tls(ReadHalf<TlsStream<TcpStream>>)
}

impl AsyncRead for ConnRead {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            ConnRead::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            ConnRead::Tls(stream) => Pin::new(stream).poll_read(cx, buf),
            ConnRead::Empty => Poll::Ready(Ok(())),
        }
    }
}
