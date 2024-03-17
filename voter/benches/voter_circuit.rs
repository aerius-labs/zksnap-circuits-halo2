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
use rand::rngs::OsRng;

use criterion::{criterion_group, criterion_main};
use criterion::{BenchmarkId, Criterion};

use pprof::criterion::{Output, PProfProfiler};
use voter::utils::generate_random_voter_circuit_inputs;
use voter::{voter_circuit, VoterCircuitInput};

const K: u32 = 13;

fn voter_circuit_bench(
    stage: CircuitBuilderStage,
    input: VoterCircuitInput<Fr>,
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
    voter_circuit(builder.main(0), &range, input, &mut public_inputs);

    end_timer!(start0);
    if !stage.witness_gen_only() {
        builder.calculate_params(Some(20));
    }
    builder
}

fn bench(c: &mut Criterion) {
    let voter_input = generate_random_voter_circuit_inputs();
    let circuit = voter_circuit_bench(CircuitBuilderStage::Keygen, voter_input.clone(), None, None);
    let config_params = circuit.params();

    let params = ParamsKZG::<Bn256>::setup(K, OsRng);
    let vk = keygen_vk(&params, &circuit).expect("vk should not fail");
    let pk = keygen_pk(&params, vk, &circuit).expect("pk should not fail");
    let break_points = circuit.break_points();

    let mut group = c.benchmark_group("plonk-prover");
    group.sample_size(10);
    group.bench_with_input(
        BenchmarkId::new("voter circuit", K),
        &(&params, &pk, &voter_input),
        |bencher, &(params, pk, voter_input)| {
            let input = voter_input.clone();
            bencher.iter(|| {
                let circuit = voter_circuit_bench(
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
