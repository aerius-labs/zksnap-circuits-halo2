pub mod verifier;

use halo2_base::{
    gates::circuit::{builder::BaseCircuitBuilder, CircuitBuilderStage},
    halo2_proofs::{
        halo2curves::{bn256::Bn256, grumpkin::Fq as Fr},
        poly::kzg::commitment::ParamsKZG,
    },
};
use snark_verifier_sdk::{
    halo2::aggregation::{
        AggregationConfigParams, Halo2KzgAccumulationScheme, VerifierUniversality,
    },
    Snark,
};

use self::verifier::{verify_snarks, AggregationCircuit};

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

#[cfg(test)]
mod tests {
    use ark_std::{end_timer, start_timer};
    use halo2_base::{
        gates::circuit::{builder::BaseCircuitBuilder, CircuitBuilderStage},
        halo2_proofs::halo2curves::grumpkin::Fq as Fr,
        utils::fs::gen_srs,
        AssignedValue,
    };
    use serde::Deserialize;
    use snark_verifier_sdk::{
        gen_pk,
        halo2::{
            aggregation::{AggregationConfigParams, VerifierUniversality},
            gen_snark_shplonk,
        },
        SHPLONK,
    };

    use crate::utils::run;

    use super::aggregator;

    #[derive(Deserialize)]
    struct DummyCircuitInput {
        a: Fr,
        b: Fr,
        c: Fr,
        res: Fr,
    }

    fn dummy_voter_circuit(
        builder: &mut BaseCircuitBuilder<Fr>,
        input: DummyCircuitInput,
        make_public: &mut Vec<AssignedValue<Fr>>,
    ) {
        let ctx = builder.main(0);

        let a = ctx.load_witness(input.a);
        let b = ctx.load_witness(input.b);
        let c = ctx.load_witness(input.c);
        let res = ctx.load_witness(input.res);

        ctx.assign_region([c, a, b, res], [0]);

        make_public.push(res)
    }

    fn dummy_base_circuit(
        builder: &mut BaseCircuitBuilder<Fr>,
        input: DummyCircuitInput,
        make_public: &mut Vec<AssignedValue<Fr>>,
    ) {
        let ctx = builder.main(0);

        let a = ctx.load_witness(input.a);
        let b = ctx.load_witness(input.b);
        let c = ctx.load_witness(input.c);
        let res = ctx.load_witness(input.res);

        ctx.assign_region([a, b, c, res], [0]);

        make_public.push(res)
    }

    #[test]
    fn test_simple_aggregation() {
        let voter_proof = run::<DummyCircuitInput>(
            9,
            0,
            dummy_voter_circuit,
            DummyCircuitInput {
                a: Fr::from(1u64),
                b: Fr::from(2u64),
                c: Fr::from(3u64),
                res: Fr::from(5u64),
            },
        );
        let base_proof = run::<DummyCircuitInput>(
            9,
            0,
            dummy_base_circuit,
            DummyCircuitInput {
                a: Fr::from(1u64),
                b: Fr::from(2u64),
                c: Fr::from(3u64),
                res: Fr::from(7u64),
            },
        );

        let k = 15u32;
        let lookup_bits = (k - 1) as usize;

        let params = gen_srs(k);

        let mut agg_circuit = aggregator::<SHPLONK>(
            CircuitBuilderStage::Keygen,
            AggregationConfigParams {
                degree: k,
                lookup_bits,
                ..Default::default()
            },
            &params,
            vec![voter_proof.clone(), base_proof.clone()],
            VerifierUniversality::Full,
        );
        let agg_config = agg_circuit.calculate_params(Some(10));

        let start0 = start_timer!(|| "gen vk & pk");
        let pk = gen_pk(&params, &agg_circuit, None);
        end_timer!(start0);
        let break_points = agg_circuit.break_points();

        let agg_circuit = aggregator::<SHPLONK>(
            CircuitBuilderStage::Prover,
            agg_config,
            &params,
            vec![voter_proof.clone(), base_proof.clone()],
            VerifierUniversality::Full,
        )
        .use_break_points(break_points.clone());

        let _snark = gen_snark_shplonk(&params, &pk, agg_circuit, None::<&str>);
        println!("snark success");
    }
}
