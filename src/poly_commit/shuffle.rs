use arith::{Field, FieldSerde, MultiLinearPoly};

use super::{raw::RawCommitment, PolyCommitProver};

pub struct ShufflePcProver<F: Field + FieldSerde> {
    poly: MultiLinearPoly<F>,
}

#[derive(Debug, Default)]
struct ShufflePcProof<F: Field + FieldSerde> {
    ex_eval: Vec<F>,
}

impl<F: Field + FieldSerde> PolyCommitProver<F> for ShufflePcProver<F> {
    type Param = ();
    type Commitment = RawCommitment<F>;
    type Proof = ShufflePcProof<F>;

    fn new(pp: Self::Param, poly: &MultiLinearPoly<F>) -> Self {
        ShufflePcProver { poly: poly.clone() }
    }

    fn commit(&self) -> Self::Commitment {
        RawCommitment {
            poly_vals: self.poly.evals.clone(),
        }
    }

    fn open(&self, point: &[<F as Field>::BaseField], transcript: &mut crate::Transcript) -> (F, Self::Proof) {
        (
            MultiLinearPoly::eval_multilinear(&self.poly.evals, point),
            (),
        )
    }
}
