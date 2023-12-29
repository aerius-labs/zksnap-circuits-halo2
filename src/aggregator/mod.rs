use halo2_base::{
    utils::ScalarField,
    gates::{ circuit::builder::BaseCircuitBuilder, GateChip, GateInstructions },
    AssignedValue,
};

#[derive(Clone, Debug)]
struct CircuitInput {
    a: u64,
    b: u64,
    c: u64,
}

fn circuit<F: ScalarField>(
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


