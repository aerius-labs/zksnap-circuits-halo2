use halo2_base::{
    gates::{GateChip, GateInstructions, RangeChip, RangeInstructions},
    halo2_proofs::{plonk::Error,circuit::Value},
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



pub struct VoterInput<F: BigPrimeField> {
    vote: Vec<BigUint>,
    vote_enc: Vec<BigUint>,
    r_enc: Vec<BigUint>,
    n_b: BigUint,
    g: BigUint,
    root: F,
    leaf: F,
    sibling: Vec<F>,
    bit_idx: Vec<F>,
}

pub struct Merkleinput<'a, F: BigPrimeField> {
    root: &'a AssignedValue<F>,
    leaf: &'a AssignedValue<F>,
    sibling: &'a [AssignedValue<F>],
    bit_idx: &'a [AssignedValue<F>],
}

pub fn voter_circuit<F: BigPrimeField, const T: usize, const RATE: usize>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    input: VoterInput<F>,
    limb_bit_len: usize,
    enc_bit_len: usize,
) {
    let biguint_chip = BigUintChip::construct(range, limb_bit_len);
    let n = biguint_chip
        .assign_constant(ctx, input.n_b.clone())
        .unwrap();
    let g = biguint_chip.assign_constant(ctx, input.g.clone()).unwrap();
    let pallier_chip =
        PaillierChip::construct(&biguint_chip, enc_bit_len, &n, input.n_b.clone(), &g);
    let mut siblings:Vec<AssignedValue<F>>=vec![];
    let mut bit_idx:Vec<AssignedValue<F>>=vec![];
    let root = ctx.load_witness(input.root);
    let leaf = ctx.load_witness(input.leaf);
    for i in 0..input.sibling.len(){
     siblings.push(ctx.load_witness(input.sibling[i]));
     bit_idx.push(ctx.load_witness(input.bit_idx[i]));
    }
    
    let verify_mer_inp = Merkleinput {
        root: &root,
        leaf: &leaf,
        sibling: &siblings,
        bit_idx: &bit_idx,
    };

    for i in 0..input.vote.len() {
        let r = biguint_chip
            .assign_integer(ctx, Value::known(input.r_enc[i].clone()), enc_bit_len).unwrap();
        let cir_enc = pallier_chip
            .encrypt(ctx, input.vote[i].clone(), &r)
            .unwrap();
        let vote_enc=biguint_chip.assign_integer(ctx, Value::known(input.vote_enc[i].clone()), enc_bit_len*2).unwrap();

        biguint_chip
            .assert_equal_fresh(ctx, &cir_enc, &vote_enc)
            .unwrap();
    }
//To verify whether the voter public key is whitelisted
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

    for (proof_element, helper) in input.sibling.iter().zip(input.bit_idx.iter()) {
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

    use super::{voter_circuit, verify_merkle_proof, Merkleinput, VoterInput};
    use super::utils::{merkle_help,get_proof,enc_help};
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
                let mut helper = merkle_help::<Fr,T,RATE>(leaves.clone(), ctx);
                let root = helper.pop().unwrap()[0];

                let (leaf_sibling, leaf_bit_idx) = get_proof(0, helper, f_zero, f_one);
                let mut sibling: Vec<Fr> = vec![];
                let mut bit_idx: Vec<Fr> = vec![];

                for i in 0..leaf_sibling.len() {
                    sibling.push(*leaf_sibling[i].value());
                    bit_idx.push(*leaf_bit_idx[i].value());
                }
                let input = VoterInput {
                    vote,
                    vote_enc,
                    r_enc,
                    n_b,
                    g: g_b,
                    root: *root.value(),
                    leaf: *leaves[0].value(),
                    sibling,
                    bit_idx,
                };

                voter_circuit::<Fr, T, RATE>(ctx,range, input,  LIMB_BIT_LEN, ENC_BIT_LEN);
                let mer_input = Merkleinput::<Fr> {
                    root: &root,
                    leaf: &leaves[0],
                    sibling: &leaf_sibling,
                    bit_idx: &leaf_bit_idx,
                };
                verify_merkle_proof::<Fr, T, RATE>(ctx, mer_input, range);
            });
    }
}
