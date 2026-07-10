use crate::proxy::pool::BufferPool;
use std::sync::Arc;
use tokio::io::{BufReader, BufWriter};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;

pub struct Conn {
    buffer_reader: BufReader<OwnedReadHalf>,
    buffer_writer: BufWriter<OwnedWriteHalf>,
}

impl Conn {
    pub fn new(stream: TcpStream) -> Self {
        let (reader, writer) = stream.into_split();

        Self {
            buffer_reader: BufReader::new(reader),
            buffer_writer: BufWriter::new(writer),
        }
    }

    pub async fn process_next_message(
        &mut self,
        pool: &Arc<BufferPool>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        todo!("handle message")
    }
}
