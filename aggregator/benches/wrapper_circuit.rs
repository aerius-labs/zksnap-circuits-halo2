// use aggregator::utils::generate_wrapper_circuit_input;
// use aggregator::wrapper::common::gen_dummy_snark;
// use aggregator::wrapper::common::gen_pk;
// use aggregator::wrapper::common::gen_proof;
// use aggregator::wrapper::common::gen_snark;
// use aggregator::wrapper::recursion::RecursionCircuit;
// use halo2_base::gates::circuit::BaseCircuitParams;
// use halo2_base::gates::circuit::CircuitBuilderStage;
// use halo2_base::halo2_proofs::dev::MockProver;
// use halo2_base::halo2_proofs::{halo2curves::bn256::Fr, plonk::*};
// use halo2_base::utils::decompose_biguint;
// use halo2_base::utils::fs::gen_srs;

// use criterion::{criterion_group, criterion_main};
// use criterion::{BenchmarkId, Criterion};

// use pprof::criterion::{Output, PProfProfiler};
// use snark_verifier_sdk::CircuitExt;
// use voter::VoterCircuit;

// const K: u32 = 22;

// fn bench(c: &mut Criterion) {
//     let (voter_inputs, state_transition_inputs) = generate_wrapper_circuit_input(1);

//     // Generating voter proof
//     let voter_config = BaseCircuitParams {
//         k: 15,
//         num_advice_per_phase: vec![1],
//         num_lookup_advice_per_phase: vec![1, 0, 0],
//         num_fixed: 1,
//         lookup_bits: Some(14),
//         num_instance_columns: 1,
//     };
//     let voter_params = gen_srs(15);
//     let voter_circuit = VoterCircuit::new(voter_config.clone(), voter_inputs[0].clone());
//     let voter_pk = gen_pk(&voter_params, &voter_circuit);
//     let voter_snark = gen_snark(&voter_params, &voter_pk, voter_circuit);

//     let recursion_config = BaseCircuitParams {
//         k: K as usize,
//         num_advice_per_phase: vec![4],
//         num_lookup_advice_per_phase: vec![1, 0, 0],
//         num_fixed: 1,
//         lookup_bits: Some((K - 1) as usize),
//         num_instance_columns: 1,
//     };
//     let recursion_params = gen_srs(K);

//     let mut init_vote = Vec::<Fr>::new();
//     for x in state_transition_inputs[0].prev_vote.iter() {
//         init_vote.extend(decompose_biguint::<Fr>(x, 4, 88));
//     }

//     // Init Base Instances
//     let mut base_instances = [
//         Fr::zero(),                  // preprocessed_digest
//         voter_snark.instances[0][0], // pk_enc_n
//         voter_snark.instances[0][1],
//         voter_snark.instances[0][2], // pk_enc_g
//         voter_snark.instances[0][3],
//     ]
//     .to_vec();
//     base_instances.extend(init_vote); // init_vote
//     base_instances.extend([
//         state_transition_inputs[0].nullifier_tree.get_old_root(), // nullifier_old_root
//         state_transition_inputs[0].nullifier_tree.get_old_root(), // nullifier_new_root
//         voter_snark.instances[0][28],                             // membership_root
//         voter_snark.instances[0][29],                             // proposal_id
//         Fr::from(0),                                              // round
//     ]);

//     let recursion_circuit = RecursionCircuit::new(
//         CircuitBuilderStage::Keygen,
//         &recursion_params,
//         gen_dummy_snark::<VoterCircuit<Fr>>(&voter_params, Some(voter_pk.get_vk()), voter_config),
//         RecursionCircuit::initial_snark(
//             &recursion_params,
//             None,
//             recursion_config.clone(),
//             base_instances.clone(),
//         ),
//         0,
//         recursion_config,
//         state_transition_inputs[0].clone(),
//     );
//     let pk = gen_pk(&recursion_params, &recursion_circuit);
//     let config_params = recursion_circuit.inner().params();

//     let mut group = c.benchmark_group("plonk-prover");
//     group.sample_size(10);
//     group.bench_with_input(
//         BenchmarkId::new("wrapper circuit", K),
//         &(&recursion_params, &pk, &voter_snark),
//         |bencher, &(params, pk, voter_snark)| {
//             let cloned_voter_snark = voter_snark;
//             bencher.iter(|| {
//                 let cloned_config_params = config_params.clone();
//                 let circuit = RecursionCircuit::new(
//                     CircuitBuilderStage::Prover
//                     ,
//                     &params,
//                     cloned_voter_snark.clone(),
//                     RecursionCircuit::initial_snark(
//                         &params,
//                         None,
//                         cloned_config_params.clone(),
//                         base_instances.clone(),
//                     ),
//                     0,
//                     cloned_config_params,
//                     state_transition_inputs[0].clone(),
//                 );
//                 println!("reached proof generation");
//                 let instances = circuit.inner().instances().clone();
//                 gen_proof(params, pk, circuit, instances);
//                 println!("completed proof generation")
//             })
//         },
//     );
//     group.finish()
// }

// criterion_group! {
//     name = benches;
//     config = Criterion::default().with_profiler(PProfProfiler::new(10, Output::Flamegraph(None)));
//     targets = bench
// }
// criterion_main!(benches);
fn main() {}
