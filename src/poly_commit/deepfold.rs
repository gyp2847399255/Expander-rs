use arith::{as_bytes_vec, mul_group::Radix2Group, Field, FieldSerde, TwoAdicField};

use crate::merkle_tree::{MerkleTreeProver, MerkleTreeVerifier, HASH_SIZE};

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
    interpolations: Vec<InterpolateValue<F>>,
    final_value: Option<F>,
}

impl<F: TwoAdicField + FieldSerde> PolyCommitProver<F> for DeepFoldProver<F> {
    type Param = DeepFoldParam<F>;
    type Commitment = MerkleRoot;

    fn new(pp: Self::Param, poly: &arith::MultiLinearPoly<F>) -> Self {
        DeepFoldProver {
            interpolations: vec![InterpolateValue::new(
                pp.mult_subgroups[0].fft(poly.evals.clone()),
                2,
            )],
            final_value: None,
        }
    }

    fn commit(&self) -> Self::Commitment {
        MerkleRoot(self.interpolations[0].commit())
    }

    fn open(&self, point: &[<F as Field>::BaseField], transcript: &mut crate::Transcript) {
        
    }
}
