//! Pooled message buffers.
//!
//! The relay is a per-message code path, so allocating a fresh `BytesMut` for every
//! frame would put the allocator on the hot path and make the latency budget
//! (doc/tasks/11-performance-validation.md) hostage to it. Buffers are therefore
//! rented from a set of fixed-size buckets and returned when the message is done.
//!
//! Two properties matter to callers:
//!
//! * **Sizes are rounded up.** A body of any length is served by the smallest bucket
//!   that fits, but the caller only ever sees the bytes it asked for.
//! * **Contents are not zeroed.** A returned buffer keeps its allocation; the next
//!   renter is expected to write the bytes it reads (see the `SAFETY` notes below).

use bytes::BytesMut;
use std::mem;
use std::ops::{Deref, DerefMut};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

/// A buffer rented from a [`MultiBufferPool`].
///
/// Exposes exactly `requested_size` bytes to the caller and returns the allocation
/// to its bucket - restored to the bucket's full capacity - on drop.
pub struct PooledBytes {
    buf: BytesMut,
    original_capacity: usize,
    bucket_index: usize,
    pool: Arc<MultiBufferPool>,
}

impl PooledBytes {
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }
}

impl Deref for PooledBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.buf
    }
}

impl DerefMut for PooledBytes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.buf
    }
}

impl Drop for PooledBytes {
    fn drop(&mut self) {
        // Restore the allocation to the bucket's full capacity before returning it.
        //
        // SAFETY: `original_capacity` is the capacity of the bucket this buffer was
        // rented from, and `get` only ever calls `set_len` with a value at or below
        // that capacity, so the length stays within the allocation. The bytes beyond
        // the requested length are uninitialised by design - zeroing them per message
        // is exactly the cost this pool exists to avoid - and every read path writes
        // the slice it reads into (`read_exact` in `Conn::read_message_body`).
        #[allow(unsafe_code)]
        unsafe {
            self.buf.set_len(self.original_capacity);
        }

        let buf = mem::take(&mut self.buf);
        self.pool.return_buffer(self.bucket_index, buf);
    }
}

struct BufferBucket {
    capacity: usize,
    /// Pre-allocated buffers. The `Vec`'s *capacity* is the pool's ceiling for this
    /// bucket: buffers arriving after that are dropped rather than retained, which
    /// keeps the pool's memory flat under bursty load.
    buffers: Mutex<Vec<BytesMut>>,
}

impl BufferBucket {
    /// Lock this bucket, recovering if a previous holder panicked.
    ///
    /// Poisoning is not a reason to take the proxy down: the guarded value is a
    /// `Vec` that is only pushed to and popped from, so it cannot be left in a
    /// half-updated state that would matter here. Propagating the panic would fail
    /// every subsequent connection instead of one.
    fn lock(&self) -> MutexGuard<'_, Vec<BytesMut>> {
        self.buffers.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A pool of reusable buffers, one set per power-of-two size between `min_len` and
/// `max_len` inclusive.
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
    /// The smallest bucket that fits is used, and the returned [`PooledBytes`] only
    /// exposes `requested_size` bytes: message bodies come straight off the wire, so
    /// they can be any length, not just a bucket size. The buffer returns to its
    /// bucket at full capacity when dropped.
    ///
    /// # Panics
    ///
    /// Panics when `requested_size` exceeds [`MultiBufferPool::max_capacity`].
    /// Callers handling peer-supplied lengths MUST check that first, so that a
    /// hostile length prefix becomes a protocol error rather than a panic.
    pub fn get(self: &Arc<Self>, requested_size: usize) -> PooledBytes {
        let (bucket_index, bucket) = self
            .buckets
            .iter()
            .enumerate()
            .find(|(_, bucket)| bucket.capacity >= requested_size)
            .unwrap_or_else(|| {
                panic!(
                    "requested buffer size {requested_size} exceeds pool capacity {}",
                    self.max_capacity()
                )
            });

        let mut buf = {
            let mut buffers = bucket.lock();
            buffers
                .pop()
                .unwrap_or_else(|| BytesMut::with_capacity(bucket.capacity))
        };

        // SAFETY: `requested_size <= bucket.capacity`, and every buffer in the bucket
        // either came from `BytesMut::with_capacity(bucket.capacity)` or was restored
        // to that length by `PooledBytes::drop`, so the length stays within capacity.
        // The exposed bytes are uninitialised until the caller writes them; see the
        // note in `PooledBytes::drop`.
        #[allow(unsafe_code)]
        unsafe {
            buf.set_len(requested_size);
        }

        PooledBytes {
            buf,
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
        let mut buffers = bucket.lock();

        if buffers.len() < buffers.capacity() {
            buffers.push(buffer);
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

    #[test]
    fn a_poisoned_bucket_does_not_take_down_the_pool() {
        let pool = MultiBufferPool::new(4, 16, 1);

        // Poison the bucket's mutex the way a panicking holder would.
        let bucket = &pool.buckets[0];
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = bucket.buffers.lock().expect("lock is free");
            panic!("holder panics while holding the bucket lock");
        }));

        // The pool must still serve buffers rather than failing every later session.
        let buf = pool.get(4);
        assert_eq!(buf.len(), 4);
    }
}
