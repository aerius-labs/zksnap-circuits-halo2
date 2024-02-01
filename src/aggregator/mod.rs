pub mod verifier;

use halo2_base::{
    gates::circuit::{ builder::BaseCircuitBuilder, CircuitBuilderStage },
    halo2_proofs::{
        halo2curves::{ bn256::Bn256, grumpkin::Fq as Fr },
        poly::kzg::commitment::ParamsKZG,
    },
    AssignedValue,
};
use snark_verifier_sdk::{
    halo2::aggregation::{
        AggregationConfigParams,
        Halo2KzgAccumulationScheme,
        VerifierUniversality,
    },
    Snark,
};

use self::verifier::{ verify_snarks, AggregationCircuit };

pub fn aggregator<AS>(
    stage: CircuitBuilderStage,
    config_params: AggregationConfigParams,
    params: &ParamsKZG<Bn256>,
    snarks: impl IntoIterator<Item = Snark>,
    universality: VerifierUniversality
) -> AggregationCircuit
    where AS: for<'a> Halo2KzgAccumulationScheme<'a>
{
    // This builder can be used to instantiate the custom circuit and then will be passed to the aggregation circuit.
    let mut builder = BaseCircuitBuilder::<Fr>::from_stage(stage).use_params(config_params.into());

    // TODO: implement the custom circuit.

    let (builder, previous_instances, preprocessed) = verify_snarks::<AS>(
        &mut builder,
        params,
        snarks,
        universality
    );

    let ctx = builder.main(0);

    ctx.constrain_equal(&previous_instances[0][0], &previous_instances[1][0]);
    ctx.constrain_equal(&previous_instances[0][1], &previous_instances[1][1]);
    let mut make_public: Vec<AssignedValue<Fr>> = vec![];
    make_public.push(previous_instances[0][0].clone());
    make_public.push(previous_instances[1][1].clone());

    builder.assigned_instances[0].append(&mut make_public);

    AggregationCircuit {
        builder: builder.clone(),
        previous_instances,
        preprocessed,
    }
}

#[cfg(test)]
mod tests {
    use ark_std::{ end_timer, start_timer };
    use halo2_base::{
        gates::{ circuit::{ builder::BaseCircuitBuilder, CircuitBuilderStage }, GateInstructions },
        halo2_proofs::halo2curves::{ ff::PrimeField, grumpkin::Fq as Fr },
        utils::fs::gen_srs,
        AssignedValue,
    };
    use serde::Deserialize;
    use snark_verifier_sdk::{
        gen_pk,
        halo2::{
            aggregation::{ AggregationConfigParams, VerifierUniversality },
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
        make_public: &mut Vec<AssignedValue<Fr>>
    ) {
        let a = builder.main(0).load_witness(input.a);
        let b = builder.main(0).load_witness(input.b);
        let c = builder.main(0).load_witness(input.c);
        let res = builder.main(0).load_witness(input.res);

        builder.main(0).assign_region([c, a, b, res], [0]);
        let gate = builder.range_chip().gate;

        let x = gate.mul(builder.main(0), a, b);
        let mul = builder.main(0).load_witness(a.value().mul(b.value()));
        builder.main(0).constrain_equal(&x, &mul);
        make_public.push(a);
        make_public.push(b);
        make_public.push(res)
    }
    //  ctx.assign_region([a, b, c, res], [0]);
    fn dummy_base_circuit(
        builder: &mut BaseCircuitBuilder<Fr>,
        input: DummyCircuitInput,
        make_public: &mut Vec<AssignedValue<Fr>>
    ) {
        let a = builder.main(0).load_witness(input.a);
        let b = builder.main(0).load_witness(input.b);
        let c = builder.main(0).load_witness(input.c);
        let res = builder.main(0).load_witness(input.res);

        builder.main(0).assign_region([a, b, c, res], [0]);
        let gate = builder.range_chip().gate;

        let x = gate.add(builder.main(0), a, b);
        let add = builder.main(0).load_witness(a.value().add(b.value()));
        builder.main(0).constrain_equal(&x, &add);
        let z = gate.mul_add(builder.main(0), c, b, a);
        println!("z_value={:?}", z.value());
        builder.main(0).constrain_equal(&z, &res);
        make_public.push(a);
        make_public.push(b);
        make_public.push(res)
    }

    #[test]
    fn test_simple_aggregation() {
        let voter_proof = run::<DummyCircuitInput>(9, 8, dummy_voter_circuit, DummyCircuitInput {
            a: Fr::from(1u64),
            b: Fr::from(2u64),
            c: Fr::from(3u64),
            res: Fr::from(5u64),
        });
        let base_proof = run::<DummyCircuitInput>(9, 8, dummy_base_circuit, DummyCircuitInput {
            a: Fr::from(1u64),
            b: Fr::from(2u64),
            c: Fr::from(3u64),
            res: Fr::from(7u64),
        });

        let k = 20u32;
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
            VerifierUniversality::Full
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
            VerifierUniversality::Full
        ).use_break_points(break_points.clone());
        let aggr_snark = gen_snark_shplonk(&params, &pk, agg_circuit, None::<&str>);

        let step_agg_circuit = aggregator::<SHPLONK>(
            CircuitBuilderStage::Prover,
            agg_config,
            &params,
            vec![aggr_snark.clone(), base_proof.clone()],
            VerifierUniversality::Full
        ).use_break_points(break_points.clone());
        println!("Step Aggr Ciruit completed");

        let step_aggr_snark = gen_snark_shplonk(&params, &pk, step_agg_circuit, None::<&str>);
    }
}
