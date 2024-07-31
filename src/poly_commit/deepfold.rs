use arith::{
    as_bytes_vec, mul_group::Radix2Group, Field, FieldSerde, MultiLinearPoly, TwoAdicField,
};

use crate::{
    merkle_tree::{MerkleTreeProver, MerkleTreeVerifier, HASH_SIZE},
    Transcript,
};

use super::{CommitmentSerde, PolyCommitProver};

#[derive(Debug, Clone, Default)]
pub struct MerkleRoot([u8; HASH_SIZE]);

impl CommitmentSerde for MerkleRoot {
    fn size(&self) -> usize {
        HASH_SIZE
    }

    fn serialize_into(&self, buffer: &mut [u8]) {
        buffer.copy_from_slice(&self.0);
    }

    fn deserialize_from(buffer: &[u8], _poly_size: usize) -> Self {
        let mut root = [0; 32];
        root.copy_from_slice(&buffer[..32]);
        Self(root)
    }
}

#[derive(Debug, Clone)]
pub struct DeepFoldParam<F: TwoAdicField + FieldSerde> {
    mult_subgroups: Vec<Radix2Group<F>>,
    variable_num: usize,
    query_num: usize,
}

#[derive(Clone)]
pub struct QueryResult<F: TwoAdicField + FieldSerde> {
    pub proof_bytes: Vec<u8>,
    pub proof_values: Vec<F>,
}

impl<F: TwoAdicField + FieldSerde> QueryResult<F> {
    pub fn verify_merkle_tree(
        &self,
        leaf_indices: &Vec<usize>,
        leaf_size: usize,
        merkle_verifier: &MerkleTreeVerifier,
    ) -> bool {
        let len = merkle_verifier.leave_number;
        let leaves: Vec<Vec<u8>> = (0..leaf_indices.len())
            .map(|i| {
                as_bytes_vec(
                    &(0..leaf_size)
                        .map(|j| self.proof_values[i * len + j])
                        .collect::<Vec<_>>(),
                )
            })
            .collect();
        let res = merkle_verifier.verify(self.proof_bytes.clone(), leaf_indices, &leaves);
        assert!(res);
        res
    }
}

#[derive(Clone)]
pub struct InterpolateValue<F: TwoAdicField> {
    pub value: Vec<F>,
    leaf_size: usize,
    merkle_tree: MerkleTreeProver,
}

impl<F: TwoAdicField + FieldSerde> InterpolateValue<F> {
    pub fn new(value: Vec<F>, leaf_size: usize) -> Self {
        let len = value.len() / leaf_size;
        let merkle_tree = MerkleTreeProver::new(
            (0..len)
                .map(|i| {
                    as_bytes_vec::<F>(
                        &(0..leaf_size)
                            .map(|j| value[len * i + j])
                            .collect::<Vec<_>>(),
                    )
                })
                .collect(),
        );
        Self {
            value,
            leaf_size,
            merkle_tree,
        }
    }

    pub fn leave_num(&self) -> usize {
        self.merkle_tree.leave_num()
    }

    pub fn commit(&self) -> [u8; HASH_SIZE] {
        self.merkle_tree.commit()
    }

    pub fn query(&self, leaf_indices: &Vec<usize>) -> QueryResult<F> {
        let len = self.merkle_tree.leave_num();
        assert_eq!(len * self.leaf_size, self.value.len());
        let proof_values = leaf_indices
            .iter()
            .flat_map(|j| {
                (0..self.leaf_size)
                    .map(|i| self.value[j.clone() + len * i])
                    .collect::<Vec<_>>()
            })
            .collect();
        let proof_bytes = self.merkle_tree.open(&leaf_indices);
        QueryResult {
            proof_bytes,
            proof_values,
        }
    }
}

pub struct DeepFoldProver<F: TwoAdicField + FieldSerde> {
    interpolation: InterpolateValue<F>,
    poly: MultiLinearPoly<F>,
}

impl<F: TwoAdicField + FieldSerde> DeepFoldProver<F> {
    fn evaluate_next_domain(
        last_interpolation: &InterpolateValue<F>,
        pp: &DeepFoldParam<F>,
        round: usize,
        challenge: F,
    ) -> Vec<F> {
        let mut res = vec![];
        let len = pp.mult_subgroups[round].size();
        let get_folding_value = &last_interpolation.value;
        let subgroup = &pp.mult_subgroups[round];
        for i in 0..(len / 2) {
            let x = get_folding_value[i];
            let nx = get_folding_value[i + len / 2];
            let sum = x + nx;
            let new_v = sum + challenge * ((x - nx) * subgroup.element_inv_at(i) + sum);
            res.push(new_v.mul_base_elem(&F::BaseField::INV_2));
        }
        res
    }
}

impl<F: TwoAdicField + FieldSerde> PolyCommitProver<F> for DeepFoldProver<F> {
    type Param = DeepFoldParam<F>;
    type Commitment = MerkleRoot;

    fn new(pp: &Self::Param, poly: &arith::MultiLinearPoly<F>) -> Self {
        DeepFoldProver {
            interpolation: InterpolateValue::new(pp.mult_subgroups[0].fft(poly.evals.clone()), 2),
            poly: poly.clone(),
        }
    }

    fn commit(&self) -> Self::Commitment {
        MerkleRoot(self.interpolation.commit())
    }

    fn open(
        &self,
        pp: &DeepFoldParam<F>,
        point: &[<F as Field>::BaseField],
        transcript: &mut Transcript,
    ) {
        let mut poly_evals = self.poly.evals.clone();
        let mut interpolations = vec![];
        for i in 0..pp.variable_num {
            let mut new_point = point[i..].to_vec();
            new_point[0] += F::BaseField::one();
            transcript.append_f(MultiLinearPoly::eval_multilinear(&poly_evals, &new_point));
            let challenge = transcript.challenge_fext();
            let new_len = poly_evals.len() / 2;
            for j in 0..new_len {
                poly_evals[j] =
                    poly_evals[j * 2] + (poly_evals[j * 2 + 1] - poly_evals[j * 2]) * challenge;
            }
            poly_evals.truncate(new_len);
            let next_evaluation = Self::evaluate_next_domain(
                if i == 0 {
                    &self.interpolation
                } else {
                    &interpolations[i - 1]
                },
                pp,
                i,
                challenge,
            );
            if i < pp.variable_num - 1 {
                let new_interpolation = InterpolateValue::new(next_evaluation, 2);
                transcript.append_u8_slice(&new_interpolation.commit(), HASH_SIZE);
                interpolations.push(new_interpolation);
            } else {
                transcript.append_f(next_evaluation[0]);
            }
        }
        let mut leaf_indices = transcript.challenge_usizes(pp.query_num);
        for i in 0..pp.variable_num {
            let len = pp.mult_subgroups[i].size();
            leaf_indices = leaf_indices.iter_mut().map(|v| *v % (len >> 1)).collect();
            leaf_indices.sort();
            leaf_indices.dedup();
            let query = if i == 0 {
                self.interpolation.query(&leaf_indices)
            } else {
                interpolations[i - 1].query(&leaf_indices)
            };
            transcript.append_u8_slice(&query.proof_bytes, query.proof_bytes.len());
            for i in query.proof_values {
                transcript.append_f(i);
            }
        }
    }
}
