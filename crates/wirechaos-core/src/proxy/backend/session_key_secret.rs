use rand::{thread_rng, Rng};

#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy, Default)]
pub struct SessionKeySecret {
    pub key: i32,
    pub secret: i32,
}

impl SessionKeySecret {

    #[must_use]
    pub fn new() -> Self {
        let mut rng = thread_rng();

        for _ in 0..64 {
            let key: i32 = rng.gen();
            let secret: i32 = rng.gen();

            if secret != 0 {
                return Self { key, secret };
            }
        }

        Self {
            key: rng.gen(),
            secret: rng.gen::<i32>() | 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn keys_are_unique_and_the_secret_is_never_zero() {
        let mut seen = HashSet::new();

        for _ in 0..10_000 {
            let key = SessionKeySecret::new();

            assert_ne!(key.secret, 0, "a zero secret would be guessable");
            assert!(
                seen.insert((key.key, key.secret)),
                "duplicate proxy cancel key: {key:?}"
            );
        }
    }
}
