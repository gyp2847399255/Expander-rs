pub mod raw;
use std::fmt::Debug;

use arith::{Field, FieldSerde, MultiLinearPoly};

use crate::Transcript;

pub use self::raw::*;

pub trait CommitmentSerde {
    fn size(&self) -> usize;
    fn serialize_into(&self, buffer: &mut [u8]);
    fn deserialize_from(buffer: &[u8], poly_size: usize) -> Self;
}

pub trait PolyCommitProver<F: Field + FieldSerde> {
    type Param: Clone;
    type Commitment: Clone + Debug + Default + CommitmentSerde;
    type Proof;

    fn new(pp: Self::Param, poly: &MultiLinearPoly<F>) -> Self;
    fn commit(&self) -> Self::Commitment;
    fn open(&self, point: &[F::BaseField], transcript: &mut Transcript) -> (F, Self::Proof);
}

pub trait PolyCommitVerifier<F: Field + FieldSerde> {
    type Param: Clone;
    type Commitment: Clone + Debug + Default + CommitmentSerde;
    type Proof;

    fn new(pp: Self::Param, commit: Self::Commitment) -> Self;
    fn verify(&self, point: &[F::BaseField], eval: F,  proof: Self::Proof) -> bool;
}
