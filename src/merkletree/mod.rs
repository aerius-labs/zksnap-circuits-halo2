pub mod utils;

use halo2_base::{
    gates::{
        circuit::{
            builder::{self, BaseCircuitBuilder},
            CircuitBuilderStage,
        },
        range, GateChip, GateInstructions, RangeChip, RangeInstructions,
    },
    halo2_proofs::plonk::Error,
    poseidon::hasher::{spec::OptimizedPoseidonSpec, PoseidonHasher},
    utils::{BigPrimeField, ScalarField},
    AssignedValue, Context,
};

pub struct MerkleInput<'a, F: BigPrimeField> {
    root: &'a AssignedValue<F>,
    leaf: &'a AssignedValue<F>,
    proof: &'a [AssignedValue<F>],
    helper: &'a [AssignedValue<F>],
}

fn dual_mux<F: ScalarField>(
    ctx: &mut Context<F>,
    gate: &GateChip<F>,
    a: &AssignedValue<F>,
    b: &AssignedValue<F>,
    switch: &AssignedValue<F>,
) -> [AssignedValue<F>; 2] {
    gate.assert_bit(ctx, *switch);

    let a_sub_b = gate.sub(ctx, *a, *b);
    let b_sub_a = gate.sub(ctx, *b, *a);

    let left = gate.mul_add(ctx, b_sub_a, *switch, *a); // left = (b-a)*s + a;
    let right = gate.mul_add(ctx, a_sub_b, *switch, *b); // right = (a-b)*s + b;
    [left, right]
}

pub fn verify_merkle_proof<F: BigPrimeField, const T: usize, const RATE: usize>(
    builder: &mut BaseCircuitBuilder<F>,
    range: &RangeChip<F>,
    input: MerkleInput<F>,
    make_public: &mut Vec<AssignedValue<F>>,
) {
    let ctx = builder.main(0);
    let gate = range.gate();
    let spec = OptimizedPoseidonSpec::<F, T, RATE>::new::<8, 56, 0>();
    let mut hasher = PoseidonHasher::<F, T, RATE>::new(spec);
    hasher.initialize_consts(ctx, gate);

    let two = ctx.load_constant(F::from(2u64));

    let mut computed_hash = *input.leaf;
    for (_, (proof_element, helper)) in input.proof.iter().zip(input.helper.iter()).enumerate() {
        let input = dual_mux(ctx, gate, &computed_hash, proof_element, helper);
        computed_hash = hasher.hash_var_len_array(ctx, range, &input, two);
    }
    ctx.constrain_equal(&computed_hash, input.root);
    make_public.push(computed_hash);
}

#[cfg(test)]
mod test {
    #[test]
    fn test_merkle_verify() {}
}
