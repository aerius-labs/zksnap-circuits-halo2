use halo2_base::halo2_proofs::arithmetic::Field;
use halo2_base::halo2_proofs::halo2curves::ff::WithSmallOrderMulGroup;
use halo2_base::utils::testing::base_test;

use halo2_base::halo2_proofs::halo2curves::bn256;
use halo2_base::{
    gates::{
        circuit::{builder::BaseCircuitBuilder, BaseCircuitParams, CircuitBuilderStage},
        GateChip, RangeChip, RangeInstructions,
    },
    halo2_proofs::halo2curves::grumpkin::Fq as Fr,
    halo2_proofs::{circuit::Value, halo2curves::bn256::Bn256},
    poseidon::hasher::{spec::OptimizedPoseidonSpec, PoseidonHasher},
    utils::{fs::gen_srs, BigPrimeField},
    AssignedValue, Context,
};
use num_bigint::{BigUint, RandBigInt};
use num_traits::One;
use pallier_chip::{
    big_uint::{chip::BigUintChip, AssignedBigUint, Fresh},
    paillier::{paillier_enc, PaillierChip},
};
use rand::thread_rng;

pub fn merkle_help<F: BigPrimeField, const T: usize, const RATE: usize>(
    leavess: Vec<AssignedValue<F>>,
    ctx: &mut Context<F>,
) -> Vec<Vec<AssignedValue<F>>> {
    let mut leaves = leavess.clone();
    let mut help_sib: Vec<Vec<AssignedValue<F>>> = vec![];
    help_sib.push(leaves.clone());

    while leaves.len() > 1 {
        let mut nxtlevel: Vec<AssignedValue<F>> = vec![];
        for (i, _) in leaves.iter().enumerate().step_by(2) {
            let left = leaves[i];
            let right = leaves[i + 1];
            let gate = GateChip::<F>::default();
            let mut poseidon =
                PoseidonHasher::<F, T, RATE>::new(OptimizedPoseidonSpec::new::<8, 57, 0>());

            poseidon.initialize_consts(ctx, &gate);
            nxtlevel.push(poseidon.hash_fix_len_array(ctx, &gate, &[left, right]));
        }
        help_sib.push(nxtlevel.clone());
        leaves = nxtlevel;
    }

    help_sib
}
pub fn get_proof<F: BigPrimeField>(
    index: usize,
    helper: Vec<Vec<AssignedValue<F>>>,
    f_zero: AssignedValue<F>,
    f_one: AssignedValue<F>,
) -> (Vec<AssignedValue<F>>, Vec<AssignedValue<F>>) {
    let mut proof: Vec<AssignedValue<F>> = vec![];
    let mut proof_helper: Vec<AssignedValue<F>> = vec![];
    let mut cur_idx = index as u32;

    for i in 0..helper.len() {
        let level = helper[i].clone();
        let isleftleaf = cur_idx % 2 == 0;
        let sibling_idx = if isleftleaf { cur_idx + 1 } else { cur_idx - 1 };
        let sibling = level[sibling_idx as usize];
        proof.push(sibling);
        proof_helper.push(if isleftleaf { f_one } else { f_zero });

        cur_idx = cur_idx / 2 as u32;
    }

    (proof, proof_helper)
}
pub fn enc_help(n: &BigUint, g: &BigUint, m: &BigUint, r: &BigUint) -> BigUint {
    let n2 = n * n;
    let gm = g.modpow(m, &n2);
    let rn = r.modpow(n, &n2);
    (gm * rn) % n2
}
