use crate::proxy::backend::error::PgError;
use crate::proxy::conn_read::ConnRead;
use crate::proxy::conn_write::ConnWrite;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};

pub struct TimeoutStream {
    buffer_reader: BufReader<ConnRead>,
    buffer_writer: BufWriter<ConnWrite>,
    timeout: Duration,
}

impl TimeoutStream {
    pub fn new(
        buf_reader: BufReader<ConnRead>,
        buf_writer: BufWriter<ConnWrite>,
        timeout: Duration,
    ) -> Self {
        Self {
            buffer_reader: buf_reader,
            buffer_writer: buf_writer,
            timeout,
        }
    }

    pub async fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), PgError> {
        tokio::time::timeout(self.timeout, self.buffer_reader.read_exact(buf))
            .await
            .map_err(|_| PgError::Timeout)??;

        Ok(())
    }

    pub async fn write_all(&mut self, buf: &[u8]) -> Result<(), PgError> {
        tokio::time::timeout(self.timeout, self.buffer_writer.write_all(buf))
            .await
            .map_err(|_| PgError::Timeout)??;

        Ok(())
    }

    pub async fn flush(&mut self) -> Result<(), PgError> {
        tokio::time::timeout(self.timeout, self.buffer_writer.flush())
            .await
            .map_err(|_| PgError::Timeout)??;
        Ok(())
    }
}
