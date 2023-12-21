use halo2_base::{
    poseidon::hasher::{ spec::OptimizedPoseidonSpec, PoseidonHasher },
    utils::{ ScalarField, BigPrimeField },
    AssignedValue,
    Context,
    gates::{ GateChip, RangeChip, GateInstructions, RangeInstructions },
    halo2_proofs::plonk::Error,
};

fn dual_mux<F: ScalarField>(
    ctx: &mut Context<F>,
    gate: &GateChip<F>,
    a: &AssignedValue<F>,
    b: &AssignedValue<F>,
    switch: &AssignedValue<F>
) -> [AssignedValue<F>; 2] {
    gate.assert_bit(ctx, *switch);

    let a_sub_b = gate.sub(ctx, *a, *b);
    let b_sub_a = gate.sub(ctx, *b, *a);

    let left = gate.mul_add(ctx, b_sub_a, *switch, *a); // left = (b-a)*s + a;
    let right = gate.mul_add(ctx, a_sub_b, *switch, *b); // right = (a-b)*s + b;
    [left, right]
}

pub fn verify_merkle_proof<F: BigPrimeField, const T: usize, const RATE: usize>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    root: &AssignedValue<F>,
    leaf: &AssignedValue<F>,
    proof: &[AssignedValue<F>],
    helper: &[AssignedValue<F>]
) -> Result<AssignedValue<F>, Error> {
    let gate = range.gate();
    let spec = OptimizedPoseidonSpec::<F, T, RATE>::new::<8, 57, 0>();
    let mut hasher = PoseidonHasher::<F, T, RATE>::new(spec);
    hasher.initialize_consts(ctx, gate);

    let two = ctx.load_constant(F::from(2u64));

    let mut computed_hash = leaf.clone();
    for (_, (proof_element, helper)) in proof.iter().zip(helper.iter()).enumerate() {
        let input = dual_mux(ctx, gate, &computed_hash, proof_element, helper);
        computed_hash = hasher.hash_var_len_array(ctx, range, &input, two);
    }

    Ok(gate.is_equal(ctx, computed_hash, *root))
}

