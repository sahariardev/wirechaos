use tokio::sync::Mutex;

pub struct BufferPool {
    buffers: Mutex<Vec<Vec<u8>>>,
}

impl BufferPool {
    fn new(initial_capacity: usize) -> Self {
        let mut buffers = Vec::new();

        for _ in 0..initial_capacity {
            buffers.push(vec![0u8; 65536]);
        }

        Self {
            buffers: Mutex::new(buffers),
        }
    }

    async fn rent_buffer(&self) -> Vec<u8> {
        let mut lock = self.buffers.lock().await;
        lock.pop().unwrap_or_else(|| vec![0u8; 65536])
    }

    async fn return_buffer(&self, buf: Vec<u8>) {
        let mut lock = self.buffers.lock().await;
        lock.push(buf);
    }
}
