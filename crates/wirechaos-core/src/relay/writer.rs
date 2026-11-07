use crate::relay::error::RelayError;
use crate::relay::reader::{Frame, FrameBody};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

pub(crate) struct FrameWriter {}

impl FrameWriter {
    pub(crate) fn new() -> Self {
        Self {}
    }

    pub(crate) async fn write_frame<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        frame: &Frame,
    ) -> Result<(), RelayError> {
        writer
            .write(&[frame.header.type_byte])
            .await
            .map_err(|_| RelayError::ConnectionClosed)?;
        let total_len = frame.header.body_len + 4 as usize;

        writer
            .write(total_len.to_be_bytes().as_ref())
            .await
            .map_err(|_| RelayError::ConnectionClosed)?;

        match &frame.body {
            FrameBody::Pooled(bytes) => {
                writer
                    .write(bytes)
                    .await
                    .map_err(|_| RelayError::ConnectionClosed)?;
            }
            _ => {}
        }

        Ok(())
    }
    pub(crate) async fn flush<W: AsyncRead + Unpin + AsyncWriteExt>(
        &mut self,
        writer: &mut W,
    ) -> Result<(), RelayError> {
        writer
            .flush()
            .await
            .map_err(|_| RelayError::ConnectionClosed)?;
        Ok(())
    }
}
