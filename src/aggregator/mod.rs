pub mod verifier;

use halo2_base::{
    gates::circuit::{builder::BaseCircuitBuilder, CircuitBuilderStage},
    halo2_proofs::{
        halo2curves::{bn256::Bn256, grumpkin::Fq as Fr},
        poly::kzg::commitment::ParamsKZG,
    },
    AssignedValue,
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
    aggr_bool: bool,
) -> AggregationCircuit
where
    AS: for<'a> Halo2KzgAccumulationScheme<'a>,
{
    // This builder can be used to instantiate the custom circuit and then will be passed to the aggregation circuit.
    let mut builder = BaseCircuitBuilder::<Fr>::from_stage(stage).use_params(config_params.into());

    let (builder, previous_instances, preprocessed) =
        verify_snarks::<AS>(&mut builder, params, snarks, universality);

    let ctx = builder.main(0);
    let mut make_public: Vec<AssignedValue<Fr>> = vec![];

    if aggr_bool == false {
        ctx.constrain_equal(&previous_instances[0][0], &previous_instances[1][0]);
        ctx.constrain_equal(&previous_instances[0][1], &previous_instances[1][1]);
        make_public.push(previous_instances[1][0].clone());
        make_public.push(previous_instances[1][1].clone());
    } else {
        ctx.constrain_equal(&previous_instances[0][12], &previous_instances[1][12]);
        ctx.constrain_equal(&previous_instances[0][13], &previous_instances[1][13]);
        make_public.push(previous_instances[1][12].clone());
        make_public.push(previous_instances[1][13].clone());
    }

    builder.assigned_instances[0].append(&mut make_public);

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
        gates::{
            circuit::{builder::BaseCircuitBuilder, CircuitBuilderStage},
            GateInstructions,
        },
        halo2_proofs::{arithmetic::Field, dev::MockProver, halo2curves::grumpkin::Fq as Fr},
        utils::fs::gen_srs,
        AssignedValue,
    };
    use serde::Deserialize;
    use snark_verifier_sdk::{
        gen_pk,
        halo2::{
            aggregation::{AggregationConfigParams, VerifierUniversality},
            gen_dummy_snark_from_protocol, gen_snark_gwc,
        },
        CircuitExt, SHPLONK,
    };

    use crate::{utils::run, As};

    use super::aggregator;

    #[derive(Deserialize)]
    struct DummyCircuitInput {
        a: Fr,
        b: Fr,
    }
    #[derive(Deserialize)]
    struct DummyAggrInput {
        a: Fr,
        b: Fr,
    }

    fn dummy_voter_circuit(
        builder: &mut BaseCircuitBuilder<Fr>,
        input: DummyCircuitInput,
        make_public: &mut Vec<AssignedValue<Fr>>,
    ) {
        let a = builder.main(0).load_witness(input.a);
        let b = builder.main(0).load_witness(input.b);

        builder.main(0).constrain_equal(&a, &a);
        builder.main(0).constrain_equal(&b, &b);
        make_public.push(a);
        make_public.push(b);
    }
    fn dummy_aggr_circuit(
        builder: &mut BaseCircuitBuilder<Fr>,
        input: DummyAggrInput,
        make_public: &mut Vec<AssignedValue<Fr>>,
    ) {
        let a = builder.main(0).load_witness(input.a);
        let b = builder.main(0).load_witness(input.b);

        builder.main(0).constrain_equal(&a, &a);
        builder.main(0).constrain_equal(&b, &b);
        let mut agg_inst: Vec<AssignedValue<Fr>> = (0..12).map(|_| a.clone()).collect();
        agg_inst.push(a);
        agg_inst.push(b);
        make_public.extend(agg_inst);
        builder.assigned_instances[0].append(make_public);
    }
    // fn dummy_base_circuit(
    //     builder: &mut BaseCircuitBuilder<Fr>,
    //     input: DummyCircuitInput,
    //     make_public: &mut Vec<AssignedValue<Fr>>
    // ) {
    //     let a = builder.main(0).load_witness(input.a);
    //     let b = builder.main(0).load_witness(input.b);
    //     let c = builder.main(0).load_witness(input.c);
    //     let res = builder.main(0).load_witness(input.res);
    //     builder.main(0).assign_region([a, b, c, res], [0]);
    //     let gate = builder.range_chip().gate;
    //     let x = gate.add(builder.main(0), a, b);
    //     let add = builder.main(0).load_witness(a.value().add(b.value()));
    //     builder.main(0).constrain_equal(&x, &add);
    //     let z = gate.mul_add(builder.main(0), c, b, a);
    //     println!("z_value={:?}", z.value());
    //     builder.main(0).constrain_equal(&z, &res);
    //     make_public.push(a);
    //     make_public.push(b);
    //     make_public.push(res)
    // }

    #[test]
    fn test_simple_aggregation() {
        // let voter_proof = run::<DummyCircuitInput>(11, 8, dummy_voter_circuit, DummyCircuitInput {
        //     a: Fr::from(1u64),
        //     b: Fr::from(2u64),
        // });

        let k = 18u32;

        let lookup_bits = 8 as usize;

        let params = gen_srs(k);

        let dummy_aggr_proof = run::<DummyAggrInput>(
            15,
            8,
            dummy_aggr_circuit,
            DummyAggrInput {
                a: Fr::from(1u64),
                b: Fr::from(2u64),
            },
        );

        let dummy_snark = gen_dummy_snark_from_protocol::<As>(dummy_aggr_proof.protocol.clone());
        println!("dumy_snark instances ={:?}", dummy_snark.instances);

        let mut agg_circuit = aggregator::<SHPLONK>(
            CircuitBuilderStage::Keygen,
            AggregationConfigParams {
                degree: k,
                lookup_bits,
                num_advice: 10,
                ..Default::default()
            },
            &params,
            vec![dummy_snark.clone(), dummy_snark.clone()],
            VerifierUniversality::Full,
            true,
        );

        let agg_config = agg_circuit.calculate_params(Some(3));

        println!("agg_config={:?}", agg_config);

        let start0 = start_timer!(|| "gen vk & pk");
        let pk = gen_pk(&params, &agg_circuit, None);
        end_timer!(start0);
        let break_points = agg_circuit.break_points();

        println!("1 st break points={:?}", break_points);

        let mut agg_circuit = aggregator::<SHPLONK>(
            CircuitBuilderStage::Mock,
            agg_config,
            &params,
            vec![dummy_aggr_proof.clone(), dummy_aggr_proof.clone()],
            VerifierUniversality::Full,
            true,
        )
        .use_break_points(break_points.clone());

        let agg_config = agg_circuit.calculate_params(Some(3));
        let break_points = agg_circuit.break_points();

        let aggr_snark = gen_snark_gwc(&params, &pk, agg_circuit, None::<&str>);

        println!("Step Aggr Circuit Started");

        // let dummy_step_aggr = gen_dummy_snark_from_protocol::<As>(aggr_snark.protocol.clone());
        println!("aggr_snark instances={:?}", aggr_snark.instances);
        println!(
            "dummy_aggr_proof instances={:?}",
            dummy_aggr_proof.instances
        );

        let mut step_agg_circuit = aggregator::<SHPLONK>(
            CircuitBuilderStage::Mock,
            agg_config,
            &params,
            vec![aggr_snark.clone(), dummy_aggr_proof.clone()],
            VerifierUniversality::Full,
            true,
        );
        let step_agg_config = step_agg_circuit.calculate_params(Some(3));
        println!("step_agg_config={:?}", step_agg_config);

        println!(
            "step_aggr_circuit instances={:?}",
            step_agg_circuit.instances()
        );

        let x = MockProver::run(k, &step_agg_circuit, step_agg_circuit.instances()).unwrap();
        x.verify().unwrap();

        //         let start0 = start_timer!(|| "gen vk & pk");
        //         let pk = gen_pk(&params, &step_agg_circuit, None);
        //         end_timer!(start0);
        //         let break_points = step_agg_circuit.break_points();

        //         println!("step_agg_config={:?}", step_agg_config);
        //         println!("aggr_snark instances={:?}", aggr_snark.instances);
        //         println!("dummy_aggr_proof instances={:?}", dummy_aggr_proof.instances);

        //         println!("Step Aggr Circuit Started");
        //         let mut step_agg_circuit = aggregator::<SHPLONK>(
        //             CircuitBuilderStage::Mock,
        //             step_agg_config,
        //             &params,
        //             vec![aggr_snark.clone(), dummy_aggr_proof.clone()],
        //             VerifierUniversality::Full,
        //             true
        //         ).use_break_points(break_points.clone());
        //         println!("Step Aggr Ciruit completed");

        //         let step_agg_config = step_agg_circuit.calculate_params(Some(3));
        //         println!("step_agg_config={:?}", step_agg_config);
        //         let break_points = step_agg_circuit.break_points();

        //      let step_aggr_proof=gen_snark_gwc(&params, &pk, step_agg_circuit, None::<&str>);

        //  println!("Step Aggr Circuit-2 Started");
        //         let mut step_agg_circuit = aggregator::<SHPLONK>(
        //             CircuitBuilderStage::Mock,
        //             step_agg_config,
        //             &params,
        //             vec![step_aggr_proof.clone(), dummy_aggr_proof.clone()],
        //             VerifierUniversality::Full,
        //             true
        //         ).use_break_points(break_points.clone());
        //         println!("Step Aggr Ciruit-2 completed");

        //         let step_agg_config = step_agg_circuit.calculate_params(Some(3));
        //         println!("step_agg_config-2={:?}", step_agg_config);
        //         let break_points = step_agg_circuit.break_points();

        //         let x=MockProver::run(k, &step_agg_circuit, step_agg_circuit.instances()).unwrap();
        //         x.verify().unwrap();
    }
}
