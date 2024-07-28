pub mod raw;
use std::fmt::Debug;

use arith::{Field, MultiLinearPoly};

use crate::Transcript;

pub use self::raw::*;

pub trait CommitmentSerde {}

pub trait PolyCommitProver<F: Field> {
    type Param: Clone;
    type Commitment: Clone + Debug + Default + CommitmentSerde;
    type Proof;

    fn new(pp: Self::Param, poly: &MultiLinearPoly<F>, transcript: &mut Transcript) -> Self;
    fn commit(&self) -> Self::Commitment;
    fn open(&self, point: Vec<F>, transcript: &mut Transcript) -> Self::Proof;
}

pub trait PolyCommitVerifier<F: Field> {
    type Param: Clone;
    type Commitment: Clone + Debug + Default + CommitmentSerde;
    type Proof;

    fn new(pp: Self::Param, commit: Self::Commitment) -> Self;
    fn verify(&self, proof: Self::Proof) -> bool;
}
