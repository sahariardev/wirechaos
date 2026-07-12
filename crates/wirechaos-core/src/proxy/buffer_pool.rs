use bytes::BytesMut;
use std::ops::{Deref, DerefMut};
use std::sync::{Arc, Mutex};

pub struct PooledBytes {
    buf: Option<BytesMut>,
    original_capacity: usize,
    bucket_index: usize,
    pool: Arc<MultiBufferPool>,
}

impl PooledBytes {
    pub fn as_slice(&self) -> &[u8] {
        self.buf.as_ref().unwrap()
    }
}

impl Deref for PooledBytes {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        self.buf.as_ref().unwrap()
    }
}

impl DerefMut for PooledBytes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.buf.as_mut().unwrap()
    }
}

impl Drop for PooledBytes {
    fn drop(&mut self) {
        if let Some(mut buf) = self.buf.take() {
            unsafe {
                buf.set_len(self.original_capacity);
            }

            self.pool.return_buffer(self.bucket_index, buf)
        }
    }
}

struct BufferBucket {
    capacity: usize,
    buffers: Mutex<Vec<BytesMut>>,
}

pub struct MultiBufferPool {
    buckets: Vec<BufferBucket>,
}

impl MultiBufferPool {
    pub fn new(min_len: usize, max_len: usize, pre_allocation_per_bucket: usize) -> Arc<Self> {
        let mut buckets = Vec::new();
        let mut current_size = min_len;

        while current_size <= max_len {
            let mut buffs = Vec::with_capacity(pre_allocation_per_bucket);
            for _ in 0..pre_allocation_per_bucket {
                buffs.push(BytesMut::with_capacity(current_size));
            }

            buckets.push(BufferBucket {
                capacity: current_size,
                buffers: Mutex::new(buffs),
            });

            current_size *= 2;
        }

        Arc::new(Self { buckets })
    }

    pub fn get(self: &Arc<Self>, requested_size: usize) -> PooledBytes {
        let (bucket_index, bucket) = self
            .buckets
            .iter()
            .enumerate()
            .find(|(_, bucket)| bucket.capacity == requested_size)
            .expect("Requested buffer size exceeds pool maxium capacity");

        let mut lock = bucket.buffers.lock().unwrap();

        let mut buf = lock
            .pop()
            .unwrap_or_else(|| BytesMut::with_capacity(bucket.capacity));

        drop(lock);

        unsafe {
            buf.set_len(requested_size);
        }

        PooledBytes {
            buf: Some(buf),
            original_capacity: bucket.capacity,
            bucket_index,
            pool: Arc::clone(self),
        }
    }

    fn return_buffer(&self, bucket_index: usize, buffer: BytesMut) {
        let bucket = &self.buckets[bucket_index];

        let mut lock = bucket.buffers.lock().unwrap();

        if lock.len() < lock.capacity() {
            lock.push(buffer);
        }
    }
}
