use ark_std::{rand::rngs::StdRng, rand::SeedableRng};
use getset::Getters;
use halo2_base::{
    gates::circuit::{builder::BaseCircuitBuilder, CircuitBuilderStage},
    halo2_proofs::{
        halo2curves::{bn256::Bn256, grumpkin::Fq as Fr},
        poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
    },
    AssignedValue,
};
use halo2_ecc::bn254::FpChip;
use itertools::Itertools;
use snark_verifier_sdk::{
    halo2::aggregation::{
        aggregate, AggregationConfigParams, BaseFieldEccChip, Halo2KzgAccumulationScheme,
        Halo2Loader, PreprocessedAndDomainAsWitness, SnarkAggregationWitness, Svk,
        VerifierUniversality,
    },
    halo2::{PoseidonTranscript, POSEIDON_SPEC},
    snark_verifier::{
        pcs::kzg::KzgAccumulator, util::arithmetic::fe_to_limbs, verifier::SnarkVerifier,
    },
    NativeLoader, PlonkSuccinctVerifier, Snark, BITS, LIMBS,
};
use std::mem;

#[derive(Clone, Debug, Getters)]
pub struct AggregationCircuit {
    pub builder: BaseCircuitBuilder<Fr>,
    pub previous_instances: Vec<Vec<AssignedValue<Fr>>>,
    pub preprocessed: Vec<PreprocessedAndDomainAsWitness>,
}

pub fn aggregator<AS>(
    stage: CircuitBuilderStage,
    config_params: AggregationConfigParams,
    params: &ParamsKZG<Bn256>,
    snarks: impl IntoIterator<Item = Snark>,
    universality: VerifierUniversality,
) -> AggregationCircuit
where
    AS: for<'a> Halo2KzgAccumulationScheme<'a>,
{
    // This builder can be used to instantiate the custom circuit and then will be passed to the aggregation circuit.
    let mut builder = BaseCircuitBuilder::<Fr>::from_stage(stage).use_params(config_params.into());

    // TODO: implement the custom circuit.

    let (builder, previous_instances, preprocessed) =
        verify_snarks::<AS>(&mut builder, params, snarks, universality);

    AggregationCircuit {
        builder: builder.clone(),
        previous_instances,
        preprocessed,
    }
}

fn verify_snarks<'v, AS>(
    builder: &'v mut BaseCircuitBuilder<Fr>,
    params: &ParamsKZG<Bn256>,
    snarks: impl IntoIterator<Item = Snark>,
    universality: VerifierUniversality,
) -> (
    &'v mut BaseCircuitBuilder<Fr>,
    Vec<Vec<AssignedValue<Fr>>>,
    Vec<PreprocessedAndDomainAsWitness>,
)
where
    AS: for<'a> Halo2KzgAccumulationScheme<'a>,
{
    let svk: Svk = params.get_g()[0].into();
    let snarks = snarks.into_iter().collect_vec();

    let mut transcript_read =
        PoseidonTranscript::<NativeLoader, &[u8]>::from_spec(&[], POSEIDON_SPEC.clone());
    let accumulators = snarks
        .iter()
        .flat_map(|snark| {
            transcript_read.new_stream(snark.proof());
            let proof = PlonkSuccinctVerifier::<AS>::read_proof(
                &svk,
                &snark.protocol,
                &snark.instances,
                &mut transcript_read,
            )
            .unwrap();
            PlonkSuccinctVerifier::<AS>::verify(&svk, &snark.protocol, &snark.instances, &proof)
                .unwrap()
        })
        .collect_vec();

    let (_accumulator, as_proof) = {
        let mut transcript_write =
            PoseidonTranscript::<NativeLoader, Vec<u8>>::from_spec(vec![], POSEIDON_SPEC.clone());
        let rng = StdRng::from_entropy();
        let accumulator = AS::create_proof(
            &Default::default(),
            &accumulators,
            &mut transcript_write,
            rng,
        )
        .unwrap();
        (accumulator, transcript_write.finalize())
    };

    // create halo2loader
    let range = builder.range_chip();
    let fp_chip = FpChip::<Fr>::new(&range, BITS, LIMBS);
    let ecc_chip = BaseFieldEccChip::new(&fp_chip);
    // Take the phase 0 pool from `builder`; it needs to be owned by loader.
    // We put it back later (below), so it should have same effect as just mutating `builder.pool(0)`.
    let pool = mem::take(builder.pool(0));
    // range_chip has shared reference to LookupAnyManager, with shared CopyConstraintManager
    // pool has shared reference to CopyConstraintManager
    let loader = Halo2Loader::new(ecc_chip, pool);

    // run witness and copy constraint generation
    let SnarkAggregationWitness {
        previous_instances,
        accumulator,
        preprocessed,
    } = aggregate::<AS>(&svk, &loader, &snarks, as_proof.as_slice(), universality);
    let lhs = accumulator.lhs.assigned();
    let rhs = accumulator.rhs.assigned();
    let accumulator = lhs
        .x()
        .limbs()
        .iter()
        .chain(lhs.y().limbs().iter())
        .chain(rhs.x().limbs().iter())
        .chain(rhs.y().limbs().iter())
        .copied()
        .collect_vec();

    #[cfg(debug_assertions)]
    {
        let KzgAccumulator { lhs, rhs } = _accumulator;
        let instances = [lhs.x, lhs.y, rhs.x, rhs.y]
            .map(fe_to_limbs::<_, Fr, LIMBS, BITS>)
            .concat();
        for (lhs, rhs) in instances.iter().zip(accumulator.iter()) {
            assert_eq!(lhs, rhs.value());
        }
    }
    // put back `pool` into `builder`
    *builder.pool(0) = loader.take_ctx();
    assert_eq!(
        builder.assigned_instances.len(),
        1,
        "AggregationCircuit must have exactly 1 instance column"
    );
    // expose accumulator as public instances
    builder.assigned_instances[0] = accumulator;

    (builder, previous_instances, preprocessed)
}
