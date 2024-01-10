use halo2_base::{
    gates::{GateChip, GateInstructions, RangeChip, RangeInstructions},
    halo2_proofs::plonk::Error,
    poseidon::hasher::{spec::OptimizedPoseidonSpec, PoseidonHasher},
    utils::{biguint_to_fe, BigPrimeField, ScalarField},
    AssignedValue, Context,
};
use num_bigint::BigUint;

use pallier_chip::{
    big_uint::{chip::BigUintChip, AssignedBigUint, Fresh},
    paillier::PaillierChip,
};

//doubt
//whether to constrain r_enc

pub struct VoterInp<F: BigPrimeField> {
    vote: Vec<BigUint>,
    vote_enc: Vec<AssignedBigUint<F, Fresh>>,
    r_enc: Vec<BigUint>,
    n_b: BigUint,
    g: BigUint,
    root: F,
    leaf: F,
    proof: Vec<F>,
    helper: Vec<F>,
}
pub struct Merkleinput<'a, F: BigPrimeField> {
    root: &'a AssignedValue<F>,
    leaf: &'a AssignedValue<F>,
    proof: &'a [AssignedValue<F>],
    helper: &'a [AssignedValue<F>],
}
pub fn check_vote_enc<F: BigPrimeField, const T: usize, const RATE: usize>(
    ctx: &mut Context<F>,
    input: VoterInp<F>,
    range: &RangeChip<F>,
    limb_bit_len: usize,
    enc_bit_len: usize,
) {
    let biguint_chip = BigUintChip::construct(range, limb_bit_len);
    let n = biguint_chip
        .assign_constant(ctx, input.n_b.clone())
        .unwrap();
    let g = biguint_chip.assign_constant(ctx, input.g.clone()).unwrap();
    let paillier_chip =
        PaillierChip::construct(&biguint_chip, enc_bit_len, &n, input.n_b.clone(), &g);
    let root = ctx.load_constant(input.root);
    let leaf = ctx.load_constant(input.leaf);
    let proof = ctx.load_constants(&input.proof);
    let helper = ctx.load_constants(&input.helper);
    let verify_mer_inp = Merkleinput {
        root: &root,
        leaf: &leaf,
        proof: &proof,
        helper: &helper,
    };

    for i in 0..input.vote.len() {
        let r = biguint_chip
            .assign_constant(ctx, input.r_enc[i].clone())
            .unwrap();
        let cir_enc = paillier_chip
            .encrypt(ctx, input.vote[i].clone(), &r)
            .unwrap();

        biguint_chip
            .assert_equal_fresh(ctx, &cir_enc, &input.vote_enc[i])
            .unwrap();
    }

    verify_merkle_proof::<F, T, RATE>(ctx, verify_mer_inp, range);
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
    range: &RangeChip<F>,
) {
    let mut hasher = PoseidonHasher::<F, T, RATE>::new(OptimizedPoseidonSpec::new::<8, 57, 0>());
    let gate = range.gate();

    hasher.initialize_consts(ctx, gate);

    let mut computed_hash = ctx.load_witness(*input.leaf.value());

    for (proof_element, helper) in input.proof.iter().zip(input.helper.iter()) {
        let inp = dual_mux(ctx, gate, &computed_hash, proof_element, helper);
        computed_hash = hasher.hash_fix_len_array(ctx, gate, &inp);
    }
    ctx.constrain_equal(&computed_hash, input.root);
}

#[cfg(test)]
mod test {

    use halo2_base::halo2_proofs::arithmetic::Field;
    use halo2_base::halo2_proofs::halo2curves::ff::WithSmallOrderMulGroup;
    use halo2_base::utils::testing::base_test;

    use super::{check_vote_enc, verify_merkle_proof, Merkleinput, VoterInp};
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

    #[warn(dead_code)]
    const T: usize = 3;
    const RATE: usize = 2;
    const R_F: usize = 8;
    const R_P: usize = 57;

    pub fn merkle_help<F: BigPrimeField>(
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
                    PoseidonHasher::<F, T, RATE>::new(OptimizedPoseidonSpec::new::<R_F, R_P, 0>());

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
    #[test]
    fn test_vote_circuit() {
        const ENC_BIT_LEN: usize = 128;
        const LIMB_BIT_LEN: usize = 64;
        let mut rng = thread_rng();
        let treesize = u32::pow(2, 3);

        let vote = [
            BigUint::one(),
            BigUint::default(),
            BigUint::default(),
            BigUint::default(),
            BigUint::default(),
        ]
        .to_vec();

        let n_b = rng.gen_biguint(ENC_BIT_LEN as u64);
        let g_b = rng.gen_biguint(ENC_BIT_LEN as u64);
        let mut r_enc: Vec<BigUint> = vec![];
        let mut vote_enc: Vec<AssignedBigUint<Fr, Fresh>> = vec![];

        base_test()
            .k(16)
            .lookup_bits(15)
            .expect_satisfied(true)
            .run(|ctx, range| {
                let biguint_chip = BigUintChip::construct(range, LIMB_BIT_LEN);

                let f_one = ctx.load_constant(Fr::ONE);
                let f_zero = ctx.load_constant(Fr::ZERO);

                for i in 0..5 {
                    r_enc.push(rng.gen_biguint(ENC_BIT_LEN as u64));
                    let val = enc_help(&n_b, &g_b, &vote[i], &r_enc[i]);
                    vote_enc.push(
                        biguint_chip
                            .assign_integer(ctx, Value::known(val), ENC_BIT_LEN * 2)
                            .unwrap(),
                    );
                }

                let mut poseidon =
                    PoseidonHasher::<Fr, T, RATE>::new(OptimizedPoseidonSpec::new::<R_F, R_P, 0>());
                let gate = range.gate();
                poseidon.initialize_consts(ctx, gate);
                let mut leaves: Vec<AssignedValue<Fr>> = vec![];

                for i in 0..treesize {
                    let inp: AssignedValue<Fr> = if i == 0 {
                        ctx.load_constant(Fr::ONE)
                    } else {
                        ctx.load_constant(Fr::ZERO)
                    };
                    leaves.push(poseidon.hash_var_len_array(ctx, range, &[inp], f_one));
                }
                let mut helper = merkle_help::<Fr>(leaves.clone(), ctx);
                let root = helper.pop().unwrap()[0];

                let (leaf_proof, leaf_helper) = get_proof(0, helper, f_zero, f_one);
                let mut proof: Vec<Fr> = vec![];
                let mut helper: Vec<Fr> = vec![];

                for i in 0..leaf_proof.len() {
                    proof.push(*leaf_proof[i].value());
                    helper.push(*leaf_helper[i].value());
                }
                let input = VoterInp {
                    vote,
                    vote_enc,
                    r_enc,
                    n_b,
                    g: g_b,
                    root: *root.value(),
                    leaf: *leaves[0].value(),
                    proof,
                    helper,
                };

                check_vote_enc::<Fr, T, RATE>(ctx, input, range, LIMB_BIT_LEN, ENC_BIT_LEN);
                let mer_input = Merkleinput::<Fr> {
                    root: &root,
                    leaf: &leaves[0],
                    proof: &leaf_proof,
                    helper: &leaf_helper,
                };
                verify_merkle_proof::<Fr, T, RATE>(ctx, mer_input, range);
            });
    }
}
