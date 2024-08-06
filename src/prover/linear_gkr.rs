//! This module implements the whole GKR prover, including the IOP and PCS.

use arith::{Field, FieldSerde, MultiLinearPoly};
use ark_std::{end_timer, start_timer};

use crate::{
    gkr_prove, merge_multilinear_evals, Circuit, CommitmentSerde, Config, GkrScratchpad,
    PolyCommitProver, Proof, Transcript,
};

pub fn grind<F: Field>(transcript: &mut Transcript, config: &Config) {
    let timer = start_timer!(|| format!("grind {} bits", config.grinding_bits));

    let initial_hash = transcript.challenge_fs::<F>(256 / config.field_size);
    let mut hash_bytes = [0u8; 256 / 8];
    let mut offset = 0;
    let step = (config.field_size + 7) / 8;

    for h in initial_hash.iter() {
        h.serialize_into(&mut hash_bytes[offset..]);
        offset += step;
    }

    for _ in 0..(1 << config.grinding_bits) {
        transcript.hasher.hash_inplace(&mut hash_bytes, 256 / 8);
    }
    transcript.append_u8_slice(&hash_bytes, 256 / 8);
    end_timer!(timer);
}

pub struct Prover<F: Field + FieldSerde, PC: PolyCommitProver<F>> {
    config: Config,
    sp: Vec<GkrScratchpad<F>>,
    pp: PC::Param,
}

impl<F: Field + FieldSerde, PC: PolyCommitProver<F>> Prover<F, PC> {
    pub fn new(config: &Config, pp: PC::Param) -> Self {
        // assert_eq!(config.field_type, crate::config::FieldType::M31);
        assert_eq!(config.fs_hash, crate::config::FiatShamirHashType::SHA256);
        assert_eq!(
            config.polynomial_commitment_type,
            crate::config::PolynomialCommitmentType::Raw
        );
        Prover {
            config: config.clone(),
            sp: Vec::new(),
            pp,
        }
    }

    pub fn prepare_mem(&mut self, c: &Circuit<F>) {
        let max_num_input_var = c
            .layers
            .iter()
            .map(|layer| layer.input_var_num)
            .max()
            .unwrap();
        let max_num_output_var = c
            .layers
            .iter()
            .map(|layer| layer.output_var_num)
            .max()
            .unwrap();
        self.sp = (0..self.config.get_num_repetitions())
            .map(|_| GkrScratchpad::new(max_num_input_var, max_num_output_var))
            .collect();
    }

    pub fn prove(&mut self, c: &Circuit<F>) -> (Vec<F>, Proof) {
        let timer = start_timer!(|| "prove");
        // std::thread::sleep(std::time::Duration::from_secs(1)); // TODO

        // PC commit
        let pc_prover = PC::new(
            &self.pp,
            &MultiLinearPoly {
                var_num: c.layers[0].input_var_num,
                evals: c.layers[0].input_vals.evals.clone(),
            },
        );
        let commitment = pc_prover.commit();
        let buffer_v = vec![F::default(); commitment.size() / F::SIZE];
        let buffer = unsafe {
            std::slice::from_raw_parts_mut(buffer_v.as_ptr() as *mut u8, commitment.size())
        };
        commitment.serialize_into(buffer);
        let mut transcript = Transcript::new();
        transcript.append_u8_slice(buffer, commitment.size());

        grind::<F>(&mut transcript, &self.config);

        let (claimed_v, rz0s, rz1s) = gkr_prove(c, &mut self.sp, &mut transcript, &self.config);

        let new_point = merge_multilinear_evals(
            MultiLinearPoly {
                var_num: c.layers[0].input_var_num,
                evals: c.layers[0].input_vals.evals.clone(),
            },
            rz0s.into_iter().chain(rz1s.into_iter()).collect(),
            &mut transcript,
        );

        pc_prover.open(&self.pp, &new_point, &mut transcript);

        end_timer!(timer);
        (claimed_v, transcript.proof)
    }
}
