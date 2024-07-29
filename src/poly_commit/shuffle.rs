use arith::{Field, FieldSerde, MultiLinearPoly};

use crate::{Proof, Transcript};

use super::{raw::RawCommitment, PolyCommitProver, PolyCommitVerifier};

pub struct ShufflePcProver<F: Field + FieldSerde> {
    poly: MultiLinearPoly<F>,
}

impl<F: Field + FieldSerde> PolyCommitProver<F> for ShufflePcProver<F> {
    type Param = ();
    type Commitment = RawCommitment<F>;

    fn new(_pp: Self::Param, poly: &MultiLinearPoly<F>) -> Self {
        ShufflePcProver { poly: poly.clone() }
    }

    fn commit(&self) -> Self::Commitment {
        RawCommitment {
            poly_vals: self.poly.evals.clone(),
        }
    }

    fn open(&self, point: &[<F as Field>::BaseField], transcript: &mut Transcript) {
        let mut poly_evals = self.poly.evals.clone();
        for i in 0..point.len() {
            let mut new_point = point[i..].to_vec();
            new_point[0] += F::BaseField::one();
            let next_eval = MultiLinearPoly::eval_multilinear(&poly_evals, &new_point);
            transcript.append_f(next_eval);
            let r = transcript.challenge_fext::<F>();
            let new_len = poly_evals.len() / 2;
            for j in 0..new_len {
                poly_evals[j] = poly_evals[j * 2] + (poly_evals[j * 2 + 1] - poly_evals[j * 2]) * r;
            }
            poly_evals.truncate(new_len);
        }
    }
}

pub struct ShufflePcVerifier<F: Field + FieldSerde> {
    commit: RawCommitment<F>,
}

impl<F: Field + FieldSerde> PolyCommitVerifier<F> for ShufflePcVerifier<F> {
    type Param = ();
    type Commitment = RawCommitment<F>;

    fn new(_pp: Self::Param, commit: Self::Commitment) -> Self {
        ShufflePcVerifier { commit }
    }

    fn verify(
        &self,
        point: &[<F as Field>::BaseField],
        eval: F,
        transcript: &mut Transcript,
        proof: &mut Proof,
    ) -> bool {
        let mut eval = eval;
        let mut new_point = vec![];
        for i in 0..point.len() {
            let next_eval = proof.get_next_and_step::<F>();
            transcript.append_f(next_eval);
            let r = transcript.challenge_fext::<F>();

            eval += r.add_base_elem(&-point[i]) * (next_eval - eval);
            new_point.push(r);
        }
        eval == MultiLinearPoly::eval_multilinear_ext(&self.commit.poly_vals, &new_point)
    }
}
