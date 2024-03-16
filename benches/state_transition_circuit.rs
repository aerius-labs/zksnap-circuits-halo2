use ark_std::{end_timer, start_timer};
use halo2_base::gates::circuit::BaseCircuitParams;
use halo2_base::gates::circuit::{builder::RangeCircuitBuilder, CircuitBuilderStage};
use halo2_base::gates::flex_gate::MultiPhaseThreadBreakPoints;
use halo2_base::AssignedValue;
use halo2_base::{
    halo2_proofs::{
        halo2curves::bn256::{Bn256, Fr},
        plonk::*,
        poly::kzg::commitment::ParamsKZG,
    },
    utils::testing::gen_proof,
};
use pprof::criterion::{Output, PProfProfiler};
use rand::rngs::OsRng;

use criterion::{criterion_group, criterion_main};
use criterion::{BenchmarkId, Criterion};

use zksnap_halo2::state_transition_circuit::utils::generate_random_state_transition_circuit_inputs;
use zksnap_halo2::state_transition_circuit::{state_trans_circuit, StateTranInput};
// Thanks to the example provided by @jebbow in his article
// https://www.jibbow.com/posts/criterion-flamegraphs/

const K: u32 = 15;

fn state_transition_circuit_bench(
    stage: CircuitBuilderStage,
    input: StateTranInput<Fr>,
    config_params: Option<BaseCircuitParams>,
    break_points: Option<MultiPhaseThreadBreakPoints>,
) -> RangeCircuitBuilder<Fr> {
    let k = K as usize;
    let lookup_bits = k - 1;
    let mut builder = match stage {
        CircuitBuilderStage::Prover => {
            RangeCircuitBuilder::prover(config_params.unwrap(), break_points.unwrap())
        }
        _ => RangeCircuitBuilder::from_stage(stage)
            .use_k(k)
            .use_lookup_bits(lookup_bits),
    };

    let start0 = start_timer!(|| format!("Witness generation for circuit in {stage:?} stage"));
    let range = builder.range_chip();

    let mut public_inputs = Vec::<AssignedValue<Fr>>::new();
    state_trans_circuit(builder.main(0), &range, input, &mut public_inputs);

    end_timer!(start0);
    if !stage.witness_gen_only() {
        builder.calculate_params(Some(20));
    }
    builder
}

fn bench(c: &mut Criterion) {
    let state_transition_input = generate_random_state_transition_circuit_inputs();
    let circuit = state_transition_circuit_bench(
        CircuitBuilderStage::Keygen,
        state_transition_input.clone(),
        None,
        None,
    );
    let config_params = circuit.params();

    let params = ParamsKZG::<Bn256>::setup(K, OsRng);
    let vk = keygen_vk(&params, &circuit).expect("vk should not fail");
    let pk = keygen_pk(&params, vk, &circuit).expect("pk should not fail");
    let break_points = circuit.break_points();

    let mut group = c.benchmark_group("plonk-prover");
    group.sample_size(10);
    group.bench_with_input(
        BenchmarkId::new("state transition circuit", K),
        &(&params, &pk, &state_transition_input),
        |bencher, &(params, pk, state_transition_input)| {
            let input = state_transition_input.clone();
            bencher.iter(|| {
                let circuit = state_transition_circuit_bench(
                    CircuitBuilderStage::Prover,
                    input.clone(),
                    Some(config_params.clone()),
                    Some(break_points.clone()),
                );

                gen_proof(params, pk, circuit);
            })
        },
    );
    group.finish()
}

criterion_group! {
    name = benches;
    config = Criterion::default().with_profiler(PProfProfiler::new(10, Output::Flamegraph(None)));
    targets = bench
}
criterion_main!(benches);
