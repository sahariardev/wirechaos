use bytes::BytesMut;
use tokio::sync::Mutex;

pub struct BufferPool {
    buffers: Mutex<Vec<BytesMut>>,
}

impl BufferPool {
    pub fn new(initial_capacity: usize) -> Self {
        let mut buffers = Vec::new();

        for _ in 0..initial_capacity {
            buffers.push(BytesMut::with_capacity(initial_capacity));
        }

        Self {
            buffers: Mutex::new(buffers),
        }
    }

    pub async fn rent_buffer(&self) -> BytesMut {
        todo!("buffer pool rent_buffer")
    }

    pub async fn rent_buffer_with_size(&self, size: usize) -> BytesMut {
        let mut lock = self.buffers.lock().await;

        if let Some(pos) = lock.iter().position(|b| b.capacity() >= size) {
            let mut buf = lock.remove(pos);
            buf.clear();
            buf
        } else {
            BytesMut::with_capacity(size)
        }
    }

    pub async fn return_buffer(&self, mut buf: BytesMut) {
        buf.clear();
        let mut lock = self.buffers.lock().await;
        lock.push(buf);
    }
}
