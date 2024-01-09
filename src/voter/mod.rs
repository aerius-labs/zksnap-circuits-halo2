use halo2_base::{
    gates::{GateChip, GateInstructions, RangeChip, RangeInstructions},
    halo2_proofs::plonk::Error,
    poseidon::hasher::{spec::OptimizedPoseidonSpec, PoseidonHasher},
    utils::{BigPrimeField, ScalarField},
    AssignedValue, Context,
};
use num_bigint::BigUint;

use pallier_chip::{
    big_uint::{chip::BigUintChip, AssignedBigUint, Fresh},
    paillier::{paillier_enc, PaillierChip},
};

pub struct VoterInp<'a, F: BigPrimeField> {
    vote: Vec<BigUint>,
    vote_enc: Vec<AssignedBigUint<F, Fresh>>,
    r_enc: Vec<BigUint>,
    n: BigUint,
    g: BigUint,
    mer_inp: Merkleinput<'a, F>,
}
pub struct Merkleinput<'a, F: BigPrimeField> {
    range: &'a RangeChip<F>,
    root: &'a AssignedValue<F>,
    leaf: &'a AssignedValue<F>,
    proof: &'a [AssignedValue<F>],
    helper: &'a [AssignedValue<F>],
}
pub fn check_vote_enc<F: BigPrimeField>(
    ctx: &mut Context<F>,
    input: VoterInp<F>,
    range: &RangeChip<F>,
    limb_bit_len: usize,
    enc_bit_len: usize,
) {
    let biguint_chip = BigUintChip::construct(range, limb_bit_len);
    let paillier_chip = PaillierChip::construct(&biguint_chip, enc_bit_len, &input.n, &input.g);
    let verify_mer_inp = Merkleinput {
        range,
        root: input.mer_inp.root,
        leaf: input.mer_inp.leaf,
        proof: input.mer_inp.proof,
        helper: input.mer_inp.helper,
    };

    for i in 0..input.vote.len() {
        let cir_enc = paillier_chip
            .encrypt(ctx, &input.vote[i], &input.r_enc[i])
            .unwrap();
        biguint_chip
            .assert_equal_fresh(ctx, &cir_enc, &input.vote_enc[i])
            .unwrap();
    }

    verify_merkle_proof::<F, 3, 2>(ctx, verify_mer_inp);
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

    let left = gate.mul_add(ctx, a_sub_b, *switch, *b); // left = (a-b)*s + b;
    let right = gate.mul_add(ctx, b_sub_a, *switch, *a); // right = (b-a)*s + a;

    [left, right]
}

pub fn verify_merkle_proof<F: BigPrimeField, const T: usize, const RATE: usize>(
    ctx: &mut Context<F>,
    input: Merkleinput<'_, F>,
) {
    let mut hasher = PoseidonHasher::<F, T, RATE>::new(OptimizedPoseidonSpec::new::<8, 57, 0>());
    let gate = input.range.gate();

    hasher.initialize_consts(ctx, gate);

    let mut computed_hash = ctx.load_witness(*input.leaf.value());

    for (proof_element, helper) in input.proof.iter().zip(input.helper.iter()) {
        let inp = dual_mux(ctx, gate, &computed_hash, proof_element, helper);
        computed_hash = hasher.hash_fix_len_array(ctx, gate, &inp);
    }
    ctx.constrain_equal(&computed_hash, input.root);
}
