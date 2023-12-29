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

fn dummy_circuit<F: ScalarField>(
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

#[cfg(test)]
mod test {
    use halo2_base::gates::circuit::BaseCircuitParams;

    use crate::utils::run;

    use super::dummy_circuit;

    #[test]
    fn test_dummy_circuit() {
        let k = 8 as u32;

        let a = 32;
        let b = 64;
        let c = a * a * b * b;
        let input = super::CircuitInput { a, b, c };

        let circuit_params = BaseCircuitParams {
            k: k as usize,
            num_advice_per_phase: vec![10],
            num_lookup_advice_per_phase: vec![0],
            num_fixed: 0,
            lookup_bits: None,
            num_instance_columns: 1,
        };

        let _snark = run(k, circuit_params, dummy_circuit, input).unwrap();
    }
}
