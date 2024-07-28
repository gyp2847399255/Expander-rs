//! RAW commitment refers to the case where the prover does not commit to the witness at all.
//! The prover will send the whole witnesses to the verifier.

use arith::{Field, FieldSerde, MultiLinearPoly};

use super::{CommitmentSerde, PolyCommitProver, PolyCommitVerifier};

pub struct RawOpening {}

#[derive(Debug, Clone, Default)]
pub struct RawCommitment<F> {
    pub poly_vals: Vec<F>,
}

impl<F: Field + FieldSerde> CommitmentSerde for RawCommitment<F> {
    fn size(&self) -> usize {
        self.poly_vals.len() * F::SIZE
    }
    fn serialize_into(&self, buffer: &mut [u8]) {
        self.poly_vals
            .iter()
            .enumerate()
            .for_each(|(i, v)| v.serialize_into(&mut buffer[i * F::SIZE..(i + 1) * F::SIZE]));
    }
    fn deserialize_from(buffer: &[u8], poly_size: usize) -> Self {
        let mut poly_vals = Vec::new();
        for i in 0..poly_size {
            poly_vals.push(F::deserialize_from(&buffer[i * F::SIZE..(i + 1) * F::SIZE]));
        }
        RawCommitment { poly_vals }
    }
}

pub struct RawCommitmentProver<F: Field> {
    poly: MultiLinearPoly<F>,
}

impl<F: Field + FieldSerde> PolyCommitProver<F> for RawCommitmentProver<F> {
    type Param = ();
    type Commitment = RawCommitment<F>;
    type Proof = ();

    fn new(_pp: Self::Param, poly: &MultiLinearPoly<F>) -> Self {
        RawCommitmentProver { poly: poly.clone() }
    }

    fn commit(&self) -> Self::Commitment {
        RawCommitment {
            poly_vals: self.poly.evals.clone(),
        }
    }

    fn open(
        &self,
        point: &[F::BaseField],
        _transcript: &mut crate::Transcript,
    ) -> (F, Self::Proof) {
        (
            MultiLinearPoly::eval_multilinear(&self.poly.evals, point),
            (),
        )
    }
}

pub struct RawCommitmentVerifier<F: Field> {
    commit: RawCommitment<F>,
}

impl<F: Field + FieldSerde> PolyCommitVerifier<F> for RawCommitmentVerifier<F> {
    type Param = ();
    type Commitment = RawCommitment<F>;
    type Proof = ();

    fn new(_pp: Self::Param, commit: RawCommitment<F>) -> Self {
        RawCommitmentVerifier { commit }
    }

    fn verify(&self, point: &[<F as Field>::BaseField], eval: F, _proof: Self::Proof) -> bool {
        eval == MultiLinearPoly::eval_multilinear(&self.commit.poly_vals, point)
    }
}
