pub mod utils;

use halo2_base::{
    gates::{ RangeChip, RangeInstructions, GateChip },
    halo2_proofs::circuit::Value,
    poseidon::hasher::PoseidonHasher,
    utils::BigPrimeField,
    AssignedValue,
    Context,
};
use num_bigint::BigUint;
use paillier_chip::{ big_uint::chip::BigUintChip, paillier::PaillierChip };

use self::utils::*;

pub struct EncryptionPublicKey {
    n: BigUint,
    g: BigUint,
}

pub struct VoterCircuitInput<F: BigPrimeField> {
    // Public inputs
    membership_root: F,
    pk_enc: EncryptionPublicKey,
    vote_enc: Vec<BigUint>,
    nullifier: Vec<F>,
    proposal_id: F,
    // Private inputs
    vote: Vec<BigUint>,
    r_enc: Vec<BigUint>,
    pk_voter: Vec<F>,
    membership_proof: Vec<F>,
    membership_proof_helper: Vec<F>,
}

pub fn voter_circuit<F: BigPrimeField, const T: usize, const RATE: usize>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    hasher: &PoseidonHasher<F, T, RATE>,
    input: VoterCircuitInput<F>,
    limb_bit_len: usize,
    enc_bit_len: usize
) {
    let gate = range.gate();

    let biguint_chip = BigUintChip::construct(range, limb_bit_len);

    let n_assigned = biguint_chip
        .assign_integer(ctx, Value::known(input.pk_enc.n.clone()), enc_bit_len)
        .unwrap();
    let g_assigned = biguint_chip
        .assign_integer(ctx, Value::known(input.pk_enc.g.clone()), enc_bit_len)
        .unwrap();

    let paillier_chip = PaillierChip::construct(
        &biguint_chip,
        enc_bit_len,
        &n_assigned,
        input.pk_enc.n,
        &g_assigned
    );

    let r_assigned = input.r_enc
        .iter()
        .map(|x| {
            biguint_chip.assign_integer(ctx, Value::known(x.clone()), enc_bit_len).unwrap()
        })
        .collect::<Vec<_>>();

    // 1. Verify correct vote encryption
    for i in 0..input.vote.len() {
        let _vote_enc = paillier_chip.encrypt(ctx, input.vote[i].clone(), &r_assigned[i]).unwrap();
        let vote_enc = biguint_chip
            .assign_integer(ctx, Value::known(input.vote_enc[i].clone()), enc_bit_len * 2)
            .unwrap();

        biguint_chip.assert_equal_fresh(ctx, &_vote_enc, &vote_enc).unwrap();
    }

    let membership_root = ctx.load_witness(input.membership_root);

    let leaf_preimage = input.pk_voter
        .iter()
        .map(|&x| ctx.load_witness(x))
        .collect::<Vec<_>>();

    let leaf = hasher.hash_fix_len_array(ctx, gate, &leaf_preimage[..]);
    let membership_proof = input.membership_proof
        .iter()
        .map(|&proof| ctx.load_witness(proof))
        .collect::<Vec<_>>();
    let membership_proof_helper = input.membership_proof_helper
        .iter()
        .map(|&helper| ctx.load_witness(helper))
        .collect::<Vec<_>>();

    // 2. Verify if the voter is in the membership tree
    verify_membership_proof(
        ctx,
        gate,
        hasher,
        &membership_root,
        &leaf,
        &membership_proof,
        &membership_proof_helper
    );
}

pub fn verify_membership_proof<F: BigPrimeField, const T: usize, const RATE: usize>(
    ctx: &mut Context<F>,
    gate: &GateChip<F>,
    hasher: &PoseidonHasher<F, T, RATE>,
    root: &AssignedValue<F>,
    leaf: &AssignedValue<F>,
    proof: &[AssignedValue<F>],
    helper: &[AssignedValue<F>]
) {
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
    use halo2_base::utils::testing::base_test;
    use halo2_ecc::*;
    use crate::voter_circuit::{ MerkleTree, paillier_enc_native };
    use super::{ voter_circuit, EncryptionPublicKey, VoterCircuitInput };
    use halo2_base::{
        gates::RangeInstructions,
        halo2_proofs::halo2curves::grumpkin::Fq as Fr,
        poseidon::hasher::{ spec::OptimizedPoseidonSpec, PoseidonHasher },
    };
    use num_bigint::{ BigUint, RandBigInt };
    use num_traits::One;
    use pse_poseidon::Poseidon;
    use rand::thread_rng;

    #[test]
    fn test_vote_circuit() {
        const T: usize = 3;
        const RATE: usize = 2;
        const R_F: usize = 8;
        const R_P: usize = 57;
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
        ].to_vec();

        let n = rng.gen_biguint(ENC_BIT_LEN as u64);
        let g = rng.gen_biguint(ENC_BIT_LEN as u64);

        let mut r_enc = Vec::<BigUint>::new();
        let mut vote_enc = Vec::<BigUint>::new();

        for i in 0..5 {
            r_enc.push(rng.gen_biguint(ENC_BIT_LEN as u64));
            vote_enc.push(paillier_enc_native(&n, &g, &vote[i], &r_enc[i]));
        }

        let mut native_hasher = Poseidon::<Fr, T, RATE>::new(R_F, R_P);

        let mut leaves = Vec::<Fr>::new();
        let pk_voter = vec![Fr::random(rng.clone()), Fr::random(rng.clone())];

        for i in 0..treesize {
            if i == 0 {
                native_hasher.update(&[pk_voter[0], pk_voter[1]]);
            } else {
                native_hasher.update(&[Fr::ZERO]);
            }
            leaves.push(native_hasher.squeeze_and_reset());
        }

        let mut membership_tree = MerkleTree::<Fr, T, RATE>
            ::new(&mut native_hasher, leaves.clone())
            .unwrap();

        let membership_root = membership_tree.get_root();
        let (membership_proof, membership_proof_helper) = membership_tree.get_proof(0);
        assert_eq!(
            membership_tree.verify_proof(&leaves[0], 0, &membership_root, &membership_proof),
            true
        );

        let pk_enc = EncryptionPublicKey { n, g };

        let input = VoterCircuitInput {
            membership_root,
            pk_enc,
            vote_enc,
            nullifier: vec![Fr::random(rng.clone()), Fr::random(rng.clone())],
            proposal_id: Fr::random(rng.clone()),
            vote,
            r_enc,
            pk_voter,
            membership_proof,
            membership_proof_helper,
        };

        base_test()
            .k(16)
            .lookup_bits(15)
            .expect_satisfied(true)
            .run(|ctx, range| {
                let gate = range.gate();

                let mut hasher = PoseidonHasher::<Fr, T, RATE>::new(
                    OptimizedPoseidonSpec::new::<R_F, R_P, 0>()
                );
                hasher.initialize_consts(ctx, gate);

                voter_circuit::<Fr, T, RATE>(ctx, range, &hasher, input, LIMB_BIT_LEN, ENC_BIT_LEN);
            });
    }
}
