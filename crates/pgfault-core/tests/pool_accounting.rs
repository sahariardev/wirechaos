//! Pool accounting proof.

use pgfault_core::proxy::buffer_pool::MultiBufferPool;

#[test]
fn pool_returns_to_baseline_after_success() {
    let pool = MultiBufferPool::new(4, 64 * 1024, 4);
    let baseline = pool.metrics().rented();

    for i in 0..1000u32 {
        let mut buffer = pool.get(128);
        buffer[..4].copy_from_slice(&i.to_be_bytes());
    }

    assert_eq!(pool.metrics().rented(), baseline);
}

#[test]
fn no_pool_growth_over_1000_frames() {
    let pool = MultiBufferPool::new(4, 64 * 1024, 4);
    let baseline = pool.metrics().rented();

    for _ in 0..1000 {
        let a = pool.get(8);
        let b = pool.get(64);
        drop(a);
        drop(b);
    }

    assert_eq!(pool.metrics().rented(), baseline);
    assert!(pool.metrics().high_water() <= 2);
}

#[test]
fn dropped_buffer_returns_even_after_panic_unwind() {
    let pool = MultiBufferPool::new(4, 64, 2);
    let baseline = pool.metrics().rented();

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _buffer = pool.get(8);
        panic!("simulated action panic while a buffer is rented");
    }));

    assert!(result.is_err());
    assert_eq!(pool.metrics().rented(), baseline);
}
