use aggregator::state_transition::{state_transition_circuit, StateTransitionInput};
use aggregator::utils::{
    assign_big_uint, compress_native_nullifier, generate_random_state_transition_circuit_inputs,
};
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

const K: u32 = 15;

fn state_transition_circuit_bench(
    stage: CircuitBuilderStage,
    input: StateTransitionInput<Fr>,
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
    let mut state_transition_vec = Vec::<AssignedValue<Fr>>::new();
    let ctx = builder.main(0);

    state_transition_vec.extend(
        compress_native_nullifier(&input.nullifier)
            .iter()
            .map(|&x| ctx.load_witness(x)),
    );

    let enc_g = input.pk_enc.g;
    let enc_h = input.pk_enc.n;

    state_transition_vec.extend(assign_big_uint(ctx, &enc_g));
    state_transition_vec.extend(assign_big_uint(ctx, &enc_h));

    state_transition_vec.extend(
        input
            .incoming_vote
            .iter()
            .flat_map(|x| assign_big_uint(ctx, x)),
    );

    state_transition_vec.extend(input.prev_vote.iter().flat_map(|x| assign_big_uint(ctx, x)));

    state_transition_circuit(
        ctx,
        &range,
        input.nullifier_tree,
        state_transition_vec,
        &mut public_inputs,
    );

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
