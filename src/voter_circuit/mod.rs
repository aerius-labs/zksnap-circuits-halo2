use halo2_base::{
    gates::{GateChip, GateInstructions, RangeChip, RangeInstructions},
    halo2_proofs::{circuit::Value, plonk::Error},
    poseidon::hasher::{spec::OptimizedPoseidonSpec, PoseidonHasher},
    utils::{biguint_to_fe, BigPrimeField, ScalarField},
    AssignedValue, Context,
};
use num_bigint::BigUint;

use pallier_chip::{
    big_uint::{chip::BigUintChip, AssignedBigUint, Fresh},
    paillier::PaillierChip,
};
mod utils;

pub struct EncryptionPublicKey {
    n:BigUint,
    g:BigUint
}

pub struct VoterInput<F: BigPrimeField> {
    vote: Vec<BigUint>,
    vote_enc: Vec<BigUint>,
    r_enc: Vec<BigUint>,
    pk_enc:EncryptionPublicKey,
    membership_root: F,
    leaf: F,
    membership_proof: Vec<F>,
    membership_proof_helper: Vec<F>,
}

pub fn voter_circuit<F: BigPrimeField, const T: usize, const RATE: usize>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    input: VoterInput<F>,
    limb_bit_len: usize,
    enc_bit_len: usize,
) {
    let biguint_chip = BigUintChip::construct(range, limb_bit_len);
    let n_assign = biguint_chip
        .assign_integer(ctx, Value::known(input.pk_enc.n.clone()), enc_bit_len)
        .unwrap();
    let g = biguint_chip
        .assign_integer(ctx, Value::known(input.pk_enc.g.clone()), enc_bit_len)
        .unwrap();
    let pallier_chip =
        PaillierChip::construct(&biguint_chip, enc_bit_len, &n_assign, input.pk_enc.n.clone(), &g);
    let mut membership_proof = Vec::<AssignedValue<F>>::new();
    let mut membership_proof_helper = Vec::<AssignedValue<F>>::new();
    let membership_root = ctx.load_witness(input.membership_root);
    let leaf = ctx.load_witness(input.leaf);
    for i in 0..input.membership_proof.len() {
        membership_proof.push(ctx.load_witness(input.membership_proof[i]));
        membership_proof_helper.push(ctx.load_witness(input.membership_proof_helper[i]));
    }

    for i in 0..input.vote.len() {
        let r = biguint_chip
            .assign_integer(ctx, Value::known(input.r_enc[i].clone()), enc_bit_len)
            .unwrap();
        let cir_enc = pallier_chip
            .encrypt(ctx, input.vote[i].clone(), &r)
            .unwrap();
        let vote_enc = biguint_chip
            .assign_integer(
                ctx,
                Value::known(input.vote_enc[i].clone()),
                enc_bit_len * 2,
            )
            .unwrap();

        biguint_chip
            .assert_equal_fresh(ctx, &cir_enc, &vote_enc)
            .unwrap();
    }
    let mut hasher = PoseidonHasher::<F, T, RATE>::new(OptimizedPoseidonSpec::new::<8, 57, 0>());
    let gate = range.gate();

    hasher.initialize_consts(ctx, gate);
    //To verify whether the voter public key is whitelisted
    verify_membership_proof(
        ctx,
        &membership_root,
        &leaf,
        &membership_proof,
        &membership_proof_helper,
        range,
        &hasher,
    );
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

pub fn verify_membership_proof<F: BigPrimeField, const T: usize, const RATE: usize>(
    ctx: &mut Context<F>,
    root: &AssignedValue<F>,
    leaf: &AssignedValue<F>,
    proof: &[AssignedValue<F>],
    helper: &[AssignedValue<F>],
    range: &RangeChip<F>,
    hasher: &PoseidonHasher<F, T, RATE>,
) {
    let gate = range.gate();

    let mut computed_hash = ctx.load_witness(*leaf.value());

    for (proof_element, helper) in proof.iter().zip(helper.iter()) {
        let inp = dual_mux(ctx, gate, &computed_hash, proof_element, helper);
        computed_hash = hasher.hash_fix_len_array(ctx, gate, &inp);
    }
    ctx.constrain_equal(&computed_hash, root);
}

#[cfg(test)]
mod test {

    use halo2_base::halo2_proofs::arithmetic::Field;
    use halo2_base::halo2_proofs::halo2curves::ff::WithSmallOrderMulGroup;
    use halo2_ecc::*;
    use halo2_base::utils::testing::base_test;

    use super::utils::{enc_help, get_proof, merkle_help};
    use super::{verify_membership_proof, voter_circuit, VoterInput,EncryptionPublicKey};
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
        let mut vote_enc: Vec<BigUint> = vec![];

        base_test()
            .k(16)
            .lookup_bits(15)
            .expect_satisfied(true)
            .run(|ctx, range| {
                let f_one = ctx.load_constant(Fr::ONE);
                let f_zero = ctx.load_constant(Fr::ZERO);

                for i in 0..5 {
                    r_enc.push(rng.gen_biguint(ENC_BIT_LEN as u64));
                    let val = enc_help(&n_b, &g_b, &vote[i], &r_enc[i]);
                    vote_enc.push(val);
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
                let mut helper = merkle_help::<Fr, T, RATE>(leaves.clone(), ctx);
                let root = helper.pop().unwrap()[0];

                let (leaf_sibling, leaf_bit_idx) = get_proof(0, helper, f_zero, f_one);
                let mut sibling: Vec<Fr> = vec![];
                let mut bit_idx: Vec<Fr> = vec![];

                for i in 0..leaf_sibling.len() {
                    sibling.push(*leaf_sibling[i].value());
                    bit_idx.push(*leaf_bit_idx[i].value());
                }
                let pk_enc=EncryptionPublicKey{
                    n:n_b,
                    g:g_b
                };
                let input = VoterInput {
                    vote,
                    vote_enc,
                    r_enc,
                    pk_enc,
                    membership_root: *root.value(),
                    leaf: *leaves[0].value(),
                    membership_proof: sibling,
                    membership_proof_helper: bit_idx,
                };

                voter_circuit::<Fr, T, RATE>(ctx, range, input, LIMB_BIT_LEN, ENC_BIT_LEN);

            });
    }
}
