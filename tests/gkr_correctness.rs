use arith::{mul_group::Radix2Group, Field, FieldSerde, TwoAdicField};
use expander_rs::{
    deepfold::{DeepFoldParam, DeepFoldProver, DeepFoldVerifier},
    Circuit, CircuitLayer, Config, GateAdd, GateMul, Prover, Verifier,
};
use halo2curves::bn256::Fr;
use rand::Rng;
use sha2::Digest;

const FILENAME_MUL: &str = "data/ExtractedCircuitMul.txt";
const FILENAME_ADD: &str = "data/ExtractedCircuitAdd.txt";

#[allow(dead_code)]
fn gen_simple_circuit<F: Field>() -> Circuit<F> {
    let mut circuit = Circuit::default();
    let mut l0 = CircuitLayer::default();
    l0.input_var_num = 2;
    l0.output_var_num = 2;
    l0.add.push(GateAdd {
        i_ids: [0],
        o_id: 0,
        coef: F::BaseField::from(1),
    });
    l0.add.push(GateAdd {
        i_ids: [0],
        o_id: 1,
        coef: F::BaseField::from(1),
    });
    l0.add.push(GateAdd {
        i_ids: [1],
        o_id: 1,
        coef: F::BaseField::from(1),
    });
    l0.mul.push(GateMul {
        i_ids: [0, 2],
        o_id: 2,
        coef: F::BaseField::from(1),
    });
    circuit.layers.push(l0.clone());
    circuit
}

#[test]
fn test_gkr_correctness() {
    // let config = Config::m31_config();
    // test_gkr_correctness_helper::<M31>(&config);
    let config = Config::bn254_config();
    test_gkr_correctness_helper::<Fr>(&config);
    // let config = Config::msn61_config();
    // test_gkr_correctness_helper::<Msn61>(&config);
}

fn test_gkr_correctness_helper<F>(config: &Config)
where
    F: TwoAdicField + FieldSerde,
{
    println!("Config created.");
    let mut circuit = Circuit::<F>::load_extracted_gates(FILENAME_MUL, FILENAME_ADD);
    // circuit.layers = circuit.layers[6..7].to_vec(); //  for only evaluate certain layer
    // let mut circuit = gen_simple_circuit(); // for custom circuit
    println!("Circuit loaded.");

    circuit.set_random_bool_input_for_test();

    // for fixed input
    // for i in 0..(1 << circuit.log_input_size()) {
    //     circuit.layers.first_mut().unwrap().input_vals.evals[i] = F::from((i % 3 == 1) as u32);
    // }

    circuit.evaluate();
    // for i in 0..circuit.layers.len() {
    //     println!("Layer {}:", i);
    //     println!("Input: {:?}", circuit.layers[i].input_vals.evals);
    // }
    // println!("Output: {:?}", circuit.layers.last().unwrap().output_vals.evals);
    println!("Circuit evaluated.");

    let variable_num = circuit.log_input_size();
    let mut mult_subgroups = vec![Radix2Group::<F>::new(variable_num as u32 + 3)];
    for i in 1..variable_num {
        mult_subgroups.push(mult_subgroups[i - 1].exp(2));
    }

    let pp = DeepFoldParam {
        mult_subgroups,
        variable_num,
        query_num: 30,
    };

    let mut prover = Prover::<_, DeepFoldProver<_>>::new(&config, pp.clone());
    prover.prepare_mem(&circuit);
    let (claimed_v, proof) = prover.prove(&circuit);
    println!("Proof generated. Size: {} bytes", proof.bytes.len());
    // first and last 16 proof u8
    println!("Proof bytes: ");
    proof.bytes.iter().take(16).for_each(|b| print!("{} ", b));
    print!("... ");
    proof
        .bytes
        .iter()
        .rev()
        .take(16)
        .rev()
        .for_each(|b| print!("{} ", b));
    println!();

    println!("Proof hash: ");
    sha2::Sha256::digest(&proof.bytes)
        .iter()
        .for_each(|b| print!("{} ", b));
    println!();

    // Verify
    let verifier = Verifier::<_, DeepFoldVerifier<_>>::new(&config, pp);
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
