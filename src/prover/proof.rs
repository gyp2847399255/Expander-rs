use arith::{Field, FieldSerde};

use crate::merkle_tree::HASH_SIZE;

/// Proof. In the serialized mode.
#[derive(Debug, Clone, Default)]
pub struct Proof {
    idx: usize,
    // ZZ: shall we use Vec<[u8; F::SIZE]> so we can remove idx field?
    pub bytes: Vec<u8>,
}

impl Proof {
    // ZZ: may be all the functions here can be pub(crate)?
    #[inline(always)]
    pub fn append_u8_slice(&mut self, buffer: &[u8], size: usize) {
        self.bytes.extend_from_slice(&buffer[..size]);
    }

    #[inline(always)]
    pub fn step(&mut self, size: usize) {
        self.idx += size;
    }

    #[inline(always)]
    pub fn get_next_and_step<F: Field + FieldSerde>(&mut self) -> F {
        let ret = F::deserialize_from(&self.bytes[self.idx..(self.idx + F::SIZE)]);
        self.step(F::SIZE);
        ret
    }

    pub fn get_next_hash(&mut self) -> [u8; HASH_SIZE] {
        let ret = self.bytes[self.idx..(self.idx + HASH_SIZE)]
            .try_into()
            .unwrap();
        self.step(HASH_SIZE);
        ret
    }

    pub fn get_next_slice(&mut self, len: usize) -> Vec<u8> {
        let ret = self.bytes[self.idx..(self.idx + len)].to_vec();
        self.step(len);
        ret
    }
}
