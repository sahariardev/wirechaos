use crate::proxy::buffer_pool::{MultiBufferPool, PooledBytes};
use crate::relay::RelayError;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub(crate) type ShutdownSignal = tokio::sync::watch::Receiver<bool>;

pub(crate) enum RawStop {
    Eof,
    Shutdown,
}

pub(crate) async fn copy_direction<R, W>(
    reader: &mut R,
    writer: &mut W,
    shutdown: &mut ShutdownSignal,
    pool: Arc<MultiBufferPool>,
    pool_size: usize,
) -> Result<RawStop, RelayError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = pool.get(pool_size);

    loop {
        tokio::select! {
            biased;

            shutdown = shutdown.changed() => {
                if shutdown.is_err(){
                    break;
                }
            }

            result = handle_copy_direction(reader, writer, &mut buffer) => {
                result?;
            }
        }
    }

    Ok(RawStop::Eof)
}

async fn handle_copy_direction<R, W>(
    reader: &mut R,
    writer: &mut W,
    buffer: &mut PooledBytes,
) -> Result<(), RelayError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let n = reader.read(buffer).await.map_err(|e| RelayError::Io(e))?;
    if n == 0 {
        return Ok(());
    }

    let _ = writer
        .write_all(&mut buffer[0..n])
        .await
        .map_err(|e| RelayError::Io(e))?;

    Ok(())
}
