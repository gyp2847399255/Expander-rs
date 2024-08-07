use std::fs;

use arith::{Field, M31};
use expander_rs::{
    raw::RawCommitmentProver, raw::RawCommitmentVerifier, Circuit, Config, Prover, Verifier,
};
use rand::Rng;

const FILENAME_CIRCUIT: &str = "data/compiler_out/circuit.txt";
const FILENAME_WITNESS: &str = "data/compiler_out/witness.txt";
const FILENAME_PROOF: &str = "data/compiler_out/proof.bin";

type F = M31;

#[test]
fn test_compiler_format_integration() {
    let config = Config::bn254_config();
    println!("Config created.");
    let mut circuit = Circuit::<F>::load_circuit(FILENAME_CIRCUIT);
    println!("Circuit loaded.");
    circuit.load_witness_file(FILENAME_WITNESS);
    println!("Witness loaded.");
    circuit.evaluate();
    println!("Circuit evaluated.");
    // check last layer first output
    let last_layer = circuit.layers.last().unwrap();
    let last_layer_first_output = last_layer.output_vals.evals[0];
    assert_eq!(last_layer_first_output, F::zero());

    let mut prover = Prover::<_, RawCommitmentProver<_>>::new(&config, ());
    prover.prepare_mem(&circuit);
    let (claimed_v, proof) = prover.prove(&circuit);
    println!("Proof generated. Size: {} bytes", proof.bytes.len());
    // write proof to file
    fs::write(FILENAME_PROOF, &proof.bytes).expect("Unable to write proof to file.");

    let verifier = Verifier::<_, RawCommitmentVerifier<_>>::new(&config, ());
    println!("Verifier created.");
    assert!(verifier.verify(&circuit, &claimed_v, &proof));
    println!("Correct proof verified.");
    let mut bad_proof = proof.clone();
    let rng = &mut rand::thread_rng();
    let random_idx = rng.gen_range(0..bad_proof.bytes.len());
    let random_change = rng.gen_range(1..256) as u8;
    bad_proof.bytes[random_idx] ^= random_change;
    assert!(!verifier.verify(&circuit, &claimed_v, &bad_proof));
    println!("Bad proof rejected.");
}
