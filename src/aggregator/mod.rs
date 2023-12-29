use halo2_base::{
    utils::ScalarField,
    gates::{ circuit::builder::BaseCircuitBuilder, GateChip, GateInstructions },
    AssignedValue,
};
use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
struct CircuitInput {
    a: u64,
    b: u64,
    c: u64,
}

fn dummy_circuit1<F: ScalarField>(
    builder: &mut BaseCircuitBuilder<F>,
    input: CircuitInput,
    make_public: &mut Vec<AssignedValue<F>>
) {
    let ctx = builder.main(0);
    let gate = GateChip::<F>::default();

    let a = ctx.load_witness(F::from(input.a));
    let b = ctx.load_witness(F::from(input.b));

    let c = ctx.load_witness(F::from(input.c));
    make_public.push(c.clone());

    let a2 = gate.mul(ctx, a.clone(), a.clone());
    let b2 = gate.mul(ctx, b.clone(), b.clone());
    let res = gate.mul(ctx, a2, b2);

    let is_equal = gate.is_equal(ctx, res, c);
    assert_eq!(is_equal.value(), &F::from(1));
}

fn dummy_circuit2<F: ScalarField>(
    builder: &mut BaseCircuitBuilder<F>,
    input: CircuitInput,
    make_public: &mut Vec<AssignedValue<F>>
) {
    let ctx = builder.main(0);
    let gate = GateChip::<F>::default();

    let a = ctx.load_witness(F::from(input.a));
    let b = ctx.load_witness(F::from(input.b));
    let c = ctx.load_witness(F::from(input.c));

    make_public.push(a.clone());
    make_public.push(b.clone());
    make_public.push(c.clone());

    let res = gate.mul(ctx, a, b);

    let is_equal = gate.is_equal(ctx, res, c);
    assert_eq!(is_equal.value(), &F::from(1));
}

#[cfg(test)]
mod test {
    use ark_std::{ start_timer, end_timer };
    use halo2_base::{
        gates::circuit::{ BaseCircuitParams, CircuitBuilderStage, builder::BaseCircuitBuilder },
        utils::fs::gen_srs,
        AssignedValue,
        halo2_proofs::halo2curves::grumpkin::Fq as Fr,
    };
    use serde::de::DeserializeOwned;
    use snark_verifier_sdk::{
        Snark,
        halo2::{
            aggregation::{ AggregationCircuit, AggregationConfigParams, VerifierUniversality },
            gen_snark_shplonk,
        },
        SHPLONK,
        gen_pk,
    };

    use crate::utils::run;

    use super::{ dummy_circuit1, dummy_circuit2 };

    fn generate_dummy_snark<T: DeserializeOwned>(
        k: u32,
        input: T,
        circuit: impl FnOnce(&mut BaseCircuitBuilder<Fr>, T, &mut Vec<AssignedValue<Fr>>)
    ) -> Snark {
        let circuit_params = BaseCircuitParams {
            k: k as usize,
            num_advice_per_phase: vec![10],
            num_lookup_advice_per_phase: vec![0],
            num_fixed: 0,
            lookup_bits: None,
            num_instance_columns: 1,
        };

        run(k, circuit_params, circuit, input).unwrap()
    }

    #[test]
    fn test_dummy_circuit() {
        let k = 8 as u32;

        let a = 32;
        let b = 64;
        let c1 = a * a * b * b;
        let c2 = a * b;
        let input1 = super::CircuitInput { a, b, c: c1 };
        let input2 = super::CircuitInput { a, b, c: c2 };

        let _snark1 = generate_dummy_snark(k, input1, dummy_circuit1);
        let _snark2 = generate_dummy_snark(k, input2, dummy_circuit2);
    }

    #[test]
    fn test_aggregation() {
        let k_dummy = 8 as u32;
        let k_agg = 14 as u32;

        let a = 32;
        let b = 64;
        let c1 = a * a * b * b;
        let c2 = a * b;
        let input1 = super::CircuitInput { a, b, c: c1 };
        let input2 = super::CircuitInput { a, b, c: c2 };

        let snark1 = generate_dummy_snark(k_dummy, input1, dummy_circuit1);
        let snark2 = generate_dummy_snark(k_dummy, input2, dummy_circuit2);

        let lookup_bits = (k_agg as usize) - 1;
        let params = gen_srs(k_agg);
        let mut agg_circuit = AggregationCircuit::new::<SHPLONK>(
            CircuitBuilderStage::Keygen,
            AggregationConfigParams { degree: k_agg, lookup_bits, ..Default::default() },
            &params,
            vec![snark1.clone(), snark2.clone()],
            VerifierUniversality::Full
        );
        let agg_config: AggregationConfigParams = agg_circuit.calculate_params(Some(10));

        let start0 = start_timer!(|| "gen vk & pk");
        let pk = gen_pk(&params, &agg_circuit, None);
        end_timer!(start0);
        let break_points = agg_circuit.break_points();

        let agg_circuit = AggregationCircuit::new::<SHPLONK>(
            CircuitBuilderStage::Prover,
            agg_config,
            &params,
            vec![snark1, snark2],
            VerifierUniversality::Full
        ).use_break_points(break_points.clone());
        let _snark = gen_snark_shplonk(&params, &pk, agg_circuit, None::<&str>);
    }
}
