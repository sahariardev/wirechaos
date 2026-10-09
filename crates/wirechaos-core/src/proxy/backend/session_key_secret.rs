use rand::{thread_rng, Rng};
//todo:: zeroing
#[derive(Hash, PartialEq, Eq, Clone, Copy)]
pub struct SessionKeySecret {
    pub key: i32,
    pub secret: i32,
}

impl SessionKeySecret {
    pub fn new(key: i32) -> Self {
        let mut rng = thread_rng();
        let secret: i32 = rng.gen();
        Self { key, secret }
    }
}
