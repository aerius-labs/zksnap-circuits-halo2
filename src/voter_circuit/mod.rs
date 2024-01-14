pub mod utils;

use halo2_base::{
    gates::{GateChip, GateInstructions, RangeChip, RangeInstructions},
    halo2_proofs::{circuit::Value, plonk::Error},
    poseidon::hasher::{spec::OptimizedPoseidonSpec, PoseidonHasher},
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

use self::utils::*;
/*
PUBLIC INPUTS
->membership_root
->vote_enc
->pk_enc

PRIVATE INPUT
->pubkey
->vote
*/

pub struct EncryptionPublicKey {
    n: BigUint,
    g: BigUint,
}

pub struct VoterInput<F: BigPrimeField> {
    vote: Vec<BigUint>,
    vote_enc: Vec<BigUint>,
    r_enc: Vec<BigUint>,
    pk_enc: EncryptionPublicKey,
    membership_root: F,
    pubkey: EcPoint<F, F>,
    membership_proof: Vec<F>,
    membership_proof_helper: Vec<F>,
}

pub fn voter_circuit<F: BigPrimeField, const T: usize, const RATE: usize>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    hasher: &PoseidonHasher<F, T, RATE>,
    input: VoterInput<F>,
    limb_bit_len: usize,
    enc_bit_len: usize,
) {
    let gate = range.gate();
    let biguint_chip = BigUintChip::construct(range, limb_bit_len);
    let n_assigned = biguint_chip
        .assign_integer(ctx, Value::known(input.pk_enc.n.clone()), enc_bit_len)
        .unwrap();
    let g_assigned = biguint_chip
        .assign_integer(ctx, Value::known(input.pk_enc.g.clone()), enc_bit_len)
        .unwrap();
    let pallier_chip = PaillierChip::construct(
        &biguint_chip,
        enc_bit_len,
        &n_assigned,
        input.pk_enc.n,
        &g_assigned,
    );

    let membership_root = ctx.load_witness(input.membership_root);

    let leaf_assign = ctx.load_witness(input.pubkey.x);

    let leaf = hasher.hash_fix_len_array(ctx, gate, &[leaf_assign]);

    let membership_proof: Vec<_> = input
        .membership_proof
        .iter()
        .map(|&proof| ctx.load_witness(proof))
        .collect();
    let membership_proof_helper: Vec<_> = input
        .membership_proof_helper
        .iter()
        .map(|&helper| ctx.load_witness(helper))
        .collect();
    let r: Vec<_> = input
        .r_enc
        .iter()
        .map(|x| {
            biguint_chip
                .assign_integer(ctx, Value::known(x.clone()), enc_bit_len)
                .unwrap()
        })
        .collect();
    for i in 0..input.vote.len() {
        let cir_enc = pallier_chip
            .encrypt(ctx, input.vote[i].clone(), &r[i])
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

    //To verify whether the voter public key is whitelisted
    verify_membership_proof(
        ctx,
        range,
        hasher,
        &membership_root,
        &leaf,
        &membership_proof,
        &membership_proof_helper,
    );
}

pub fn verify_membership_proof<F: BigPrimeField, const T: usize, const RATE: usize>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    hasher: &PoseidonHasher<F, T, RATE>,
    root: &AssignedValue<F>,
    leaf: &AssignedValue<F>,
    proof: &[AssignedValue<F>],
    helper: &[AssignedValue<F>],
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
    use halo2_base::utils::testing::base_test;
    use halo2_ecc::ecc::EcPoint;
    use halo2_ecc::*;

    use crate::voter_circuit::utils::verify_proof;

    use super::utils::{enc_help, get_proof, merkle_help};
    use super::{verify_membership_proof, voter_circuit, EncryptionPublicKey, VoterInput};

    use halo2_base::halo2_proofs::{
        arithmetic::CurveAffine,
        halo2curves::secp256k1::{Fq, Secp256k1Affine},
    };
    use halo2_base::{
        gates::{
            circuit::{builder::BaseCircuitBuilder, BaseCircuitParams, CircuitBuilderStage},
            GateChip, RangeChip, RangeInstructions,
        },
        halo2_proofs::halo2curves::grumpkin::Fq as Fr,
        halo2_proofs::{circuit::Value, halo2curves::bn256::G1Affine},
        poseidon::hasher::{spec::OptimizedPoseidonSpec, PoseidonHasher},
        utils::{fe_to_biguint, BigPrimeField, ScalarField},
        AssignedValue, Context,
    };
    use num_bigint::{BigUint, RandBigInt};
    use num_traits::One;
    use pallier_chip::{
        big_uint::{chip::BigUintChip, AssignedBigUint, Fresh},
        paillier::{paillier_enc, PaillierChip},
    };
    use pse_poseidon::Poseidon;
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
        for i in 0..5 {
            r_enc.push(rng.gen_biguint(ENC_BIT_LEN as u64));
            vote_enc.push(enc_help(&n_b, &g_b, &vote[i], &r_enc[i]));
        }

        let mut native_hasher = Poseidon::<Fr, T, RATE>::new(R_F, R_P);
        let mut leaves = Vec::<Fr>::new();
        let pubkey = EcPoint::new(Fr::random(rng.clone()), Fr::random(rng));
        for i in 0..treesize {
            if i == 0 {
                native_hasher.update(&[pubkey.x])
            } else {
                native_hasher.update(&[Fr::ZERO])
            }
            leaves.push(native_hasher.squeeze_and_reset());
        }
        let mut helper = merkle_help::<Fr, 3, 2>(&mut native_hasher, leaves.clone());
        let root = helper.pop().unwrap()[0];
        let (leaf_sibling, leaf_bit_idx) = get_proof(0, helper);
        verify_proof(&mut native_hasher, &leaves[0], 0, &root, &leaf_sibling);

        let pk_enc = EncryptionPublicKey { n: n_b, g: g_b };

        let input = VoterInput {
            vote,
            vote_enc,
            r_enc,
            pk_enc,
            membership_root: root,
            pubkey,
            membership_proof: leaf_sibling,
            membership_proof_helper: leaf_bit_idx,
        };

        base_test()
            .k(16)
            .lookup_bits(15)
            .expect_satisfied(true)
            .run(|ctx, range| {
                let gate = range.gate();
                let mut hasher =
                    PoseidonHasher::<Fr, T, RATE>::new(OptimizedPoseidonSpec::new::<R_F, R_P, 0>());
                hasher.initialize_consts(ctx, gate);
                voter_circuit::<Fr, T, RATE>(ctx, range, &hasher, input, LIMB_BIT_LEN, ENC_BIT_LEN);
            });
    }
}
