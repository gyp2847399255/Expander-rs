pub mod deepfold;
pub mod raw;
pub mod shuffle;
use std::fmt::Debug;

use arith::{Field, FieldSerde, MultiLinearPoly};

use crate::{Proof, Transcript};

pub trait CommitmentSerde {
    fn size(&self) -> usize;
    fn serialize_into(&self, buffer: &mut [u8]);
    fn deserialize_from(buffer: &[u8], poly_size: usize) -> Self;
}

pub trait PolyCommitProver<F: Field + FieldSerde> {
    type Param: Clone;
    type Commitment: Clone + Debug + Default + CommitmentSerde;

    fn new(pp: &Self::Param, poly: &MultiLinearPoly<F>) -> Self;
    fn commit(&self) -> Self::Commitment;
    fn open(&self, pp: &Self::Param, point: &[F], transcript: &mut Transcript); // -> Self::Proof;
}

pub trait PolyCommitVerifier<F: Field + FieldSerde> {
    type Param: Clone;
    type Commitment: Clone + Debug + Default + CommitmentSerde;

    fn new(pp: Self::Param, commit: Self::Commitment) -> Self;
    fn verify(
        &self,
        pp: &Self::Param,
        point: &[F],
        eval: F,
        transcript: &mut Transcript,
        proof: &mut Proof,
    ) -> bool;
}
