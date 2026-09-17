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

    /// Rent a buffer that can hold at least `requested_size` bytes.
    ///
    /// The smallest bucket that fits is used, and the returned [`PooledBytes`]
    /// only exposes `requested_size` bytes: message bodies come straight off
    /// the wire, so they can be any length, not just a bucket size. The buffer
    /// is restored to its full capacity when it is dropped back into the pool.
    ///
    /// # Panics
    ///
    /// Panics when `requested_size` is larger than the biggest bucket. Callers
    /// handling peer-supplied lengths must check [`MultiBufferPool::max_capacity`]
    /// first.
    pub fn get(self: &Arc<Self>, requested_size: usize) -> PooledBytes {
        let (bucket_index, bucket) = self
            .buckets
            .iter()
            .enumerate()
            .find(|(_, bucket)| bucket.capacity >= requested_size)
            .unwrap_or_else(|| {
                panic!(
                    "Requested buffer size {} exceeds pool maxium capacity {}",
                    requested_size,
                    self.max_capacity()
                )
            });

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

    /// The largest allocation this pool can serve.
    pub fn max_capacity(&self) -> usize {
        self.buckets.last().map_or(0, |bucket| bucket.capacity)
    }

    fn return_buffer(&self, bucket_index: usize, buffer: BytesMut) {
        let bucket = &self.buckets[bucket_index];

        let mut lock = bucket.buffers.lock().unwrap();

        if lock.len() < lock.capacity() {
            lock.push(buffer);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_uses_the_smallest_bucket_that_fits() {
        let pool = MultiBufferPool::new(4, 64, 2);

        // An exact bucket size uses that bucket...
        let exact = pool.get(8);
        assert_eq!(exact.len(), 8);
        assert_eq!(exact.original_capacity, 8);

        // ...and anything else is rounded up to the next one.
        let rounded = pool.get(9);
        assert_eq!(rounded.len(), 9, "the caller only sees what it asked for");
        assert_eq!(rounded.original_capacity, 16);
    }

    #[test]
    fn returned_buffers_are_reusable_after_rounding() {
        let pool = MultiBufferPool::new(4, 64, 1);

        for _ in 0..4 {
            let mut buf = pool.get(20);
            assert_eq!(buf.len(), 20);
            buf.copy_from_slice(&[7u8; 20]);
        }
    }

    #[test]
    fn max_capacity_is_the_largest_bucket() {
        assert_eq!(MultiBufferPool::new(4, 64, 1).max_capacity(), 64);
        // Buckets double, so a non-power-of-two maximum is rounded down.
        assert_eq!(MultiBufferPool::new(4, 100, 1).max_capacity(), 64);
    }
}
