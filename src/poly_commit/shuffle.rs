use arith::{Field, FieldSerde, MultiLinearPoly};

use super::{raw::RawCommitment, PolyCommitProver};

pub struct ShufflePcProver<F: Field + FieldSerde> {
    poly: MultiLinearPoly<F>,
}

#[derive(Debug, Default)]
struct  ShufflePcProof<F: Field + FieldSerde> {
    ex_eval: Vec<F>
}

impl<F: Field + FieldSerde> PolyCommitProver<F> for ShufflePcProver<F> {
    type Param = ();
    type Commitment = RawCommitment<F>;
    type Proof = ShufflePcProof<F>;

    
}
