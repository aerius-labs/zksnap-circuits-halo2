use halo2_base::{
    gates::{GateChip, GateInstructions, RangeChip, RangeInstructions},
    halo2_proofs::{circuit::Value, plonk::Error},
    poseidon::hasher::{self, spec::OptimizedPoseidonSpec, PoseidonHasher},
    utils::{biguint_to_fe, BigPrimeField, ScalarField},
    AssignedValue, Context,
};
use num_bigint::BigUint;

use halo2_base::halo2_proofs::{
    arithmetic::CurveAffine,
    halo2curves::secp256k1::{Fq, Secp256k1Affine},
};
use halo2_ecc::ecc::{fixed_base, scalar_multiply, EcPoint, EccChip};
use halo2_ecc::fields::{fp::FpChip, FieldChip};
use pallier_chip::{
    big_uint::{chip::BigUintChip, AssignedBigUint, Fresh},
    paillier::PaillierChip,
};
use pse_poseidon::Poseidon;
use rand::thread_rng;

pub(crate) fn merkle_help<F: BigPrimeField, const T: usize, const RATE: usize>(
    hasher: &mut Poseidon<F, 3, 2>,
    leavess: Vec<F>,
) -> Vec<Vec<F>> {
    let mut leaves = leavess.clone();
    let mut help_sib: Vec<Vec<F>> = vec![];
    help_sib.push(leaves.clone());

    while leaves.len() > 1 {
        let mut nxtlevel = Vec::<F>::new();
        for (i, _) in leaves.iter().enumerate().step_by(2) {
            let left = leaves[i];
            let right = leaves[i + 1];
            hasher.update(&[left, right]);
            nxtlevel.push(hasher.squeeze_and_reset());
        }
        help_sib.push(nxtlevel.clone());
        leaves = nxtlevel;
    }

    help_sib
}
pub(crate) fn get_proof<F: BigPrimeField>(index: usize, helper: Vec<Vec<F>>) -> (Vec<F>, Vec<F>) {
    let mut proof = Vec::<F>::new();
    let mut proof_helper = Vec::<F>::new();
    let mut cur_idx = index as u32;

    for i in 0..helper.len() {
        let level = helper[i].clone();
        let isleftleaf = cur_idx % 2 == 0;
        let sibling_idx = if isleftleaf { cur_idx + 1 } else { cur_idx - 1 };
        let sibling = level[sibling_idx as usize];
        proof.push(sibling);
        proof_helper.push(if isleftleaf { F::ONE } else { F::ZERO });

        cur_idx = cur_idx / 2 as u32;
    }

    (proof, proof_helper)
}
pub(crate) fn enc_help(n: &BigUint, g: &BigUint, m: &BigUint, r: &BigUint) -> BigUint {
    let n2 = n * n;
    let gm = g.modpow(m, &n2);
    let rn = r.modpow(n, &n2);
    (gm * rn) % n2
}

pub(crate) fn dual_mux<F: ScalarField>(
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

pub(crate) fn verify_proof<F: BigPrimeField>(
    hasher: &mut Poseidon<F, 3, 2>,
    leaf: &F,
    index: usize,
    root: &F,
    proof: &[F],
) -> bool {
    let mut computed_hash = *leaf;
    let mut current_index = index;

    for i in 0..proof.len() {
        let proof_element = &proof[i];
        let is_left_node = current_index % 2 == 0;

        computed_hash = if is_left_node {
            hasher.update(&[computed_hash, *proof_element]);
            hasher.squeeze_and_reset()
        } else {
            hasher.update(&[*proof_element, computed_hash]);
            hasher.squeeze_and_reset()
        };

        current_index /= 2;
    }

    computed_hash == *root
}
