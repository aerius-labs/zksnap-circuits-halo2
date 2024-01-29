use halo2_base::{
    gates::{ RangeChip, RangeInstructions },
    halo2_proofs::circuit::Value,
    poseidon::hasher::PoseidonHasher,
    utils::BigPrimeField,
    AssignedValue,
    Context,
};
use num_bigint::BigUint;

use biguint_halo2::big_uint::chip::BigUintChip;
use paillier_chip::paillier::{ EncryptionPublicKeyAssigned, PaillierChip };
use serde::Deserialize;
use snark_verifier_sdk::halo2::OptimizedPoseidonSpec;

use crate::merkletree::verify_membership_proof;

// Paillier encryption parameters
const ENC_BIT_LEN: usize = 176;
const LIMB_BIT_LEN: usize = 88;

// Poseidon hash parameters
const T: usize = 3;
const RATE: usize = 2;
const R_F: usize = 8;
const R_P: usize = 57;

#[derive(Debug, Clone, Deserialize)]
pub struct EncryptionPublicKey {
    pub n: BigUint,
    pub g: BigUint,
}

#[derive(Debug, Clone, Deserialize)]
pub struct VoterCircuitInput<F: BigPrimeField> {
    // Public inputs
    membership_root: F,
    pk_enc: EncryptionPublicKey,
    // TODO: this can be removed
    vote_enc: Vec<BigUint>,
    // nullifier,
    proposal_id: F,

    // Private inputs
    vote: Vec<BigUint>,
    r_enc: Vec<BigUint>,
    pk_voter: Vec<F>,
    membership_proof: Vec<F>,
    membership_proof_helper: Vec<F>,
}

fn voter_circuit<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    input: VoterCircuitInput<F>,
    public_inputs: &mut Vec<AssignedValue<F>>
) {
    let gate = range.gate();

    let mut hasher = PoseidonHasher::<F, T, RATE>::new(OptimizedPoseidonSpec::new::<R_F, R_P, 0>());
    hasher.initialize_consts(ctx, gate);

    let biguint_chip = BigUintChip::construct(&range, LIMB_BIT_LEN);
    let paillier_chip = PaillierChip::construct(&biguint_chip, ENC_BIT_LEN);

    let membership_root = ctx.load_witness(input.membership_root);
    public_inputs.push(membership_root.clone());

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

    let proposal_id = ctx.load_witness(input.proposal_id);
    public_inputs.push(proposal_id.clone());

    let n_assigned = biguint_chip
        .assign_integer(ctx, Value::known(input.pk_enc.n.clone()), ENC_BIT_LEN)
        .unwrap();
    public_inputs.append(&mut n_assigned.limbs().to_vec());

    let g_assigned = biguint_chip
        .assign_integer(ctx, Value::known(input.pk_enc.g.clone()), ENC_BIT_LEN)
        .unwrap();
    public_inputs.append(&mut g_assigned.limbs().to_vec());

    let pk_enc = EncryptionPublicKeyAssigned {
        n: n_assigned,
        g: g_assigned,
    };

    // 1. Verify if the voter is in the membership tree
    verify_membership_proof(
        ctx,
        gate,
        &hasher,
        &membership_root,
        &leaf,
        &membership_proof,
        &membership_proof_helper
    );

    // TODO: add a check to verify correct votes have been passed.

    let vote_assigned = input.vote
        .iter()
        .map(|x| {
            biguint_chip.assign_integer(ctx, Value::known(x.clone()), ENC_BIT_LEN).unwrap()
        })
        .collect::<Vec<_>>();

    let r_assigned = input.r_enc
        .iter()
        .map(|x| {
            biguint_chip.assign_integer(ctx, Value::known(x.clone()), ENC_BIT_LEN).unwrap()
        })
        .collect::<Vec<_>>();

    // 2. Verify correct vote encryption
    for i in 0..input.vote.len() {
        let _vote_enc = paillier_chip
            .encrypt(ctx, &pk_enc, &vote_assigned[i], &r_assigned[i])
            .unwrap();
        let vote_enc = biguint_chip
            .assign_integer(ctx, Value::known(input.vote_enc[i].clone()), ENC_BIT_LEN * 2)
            .unwrap();

        biguint_chip.assert_equal_fresh(ctx, &_vote_enc, &vote_enc).unwrap();

        public_inputs.append(&mut vote_enc.limbs().to_vec());
    }
}

#[cfg(test)]
mod test {
    use halo2_base::halo2_proofs::arithmetic::Field;
    use halo2_base::halo2_proofs::halo2curves::grumpkin::Fq as Fr;
    use halo2_base::utils::testing::base_test;
    use halo2_base::AssignedValue;
    use halo2_ecc::*;
    use num_bigint::{ BigUint, RandBigInt };
    use num_traits::One;
    use paillier_chip::paillier::paillier_enc_native;
    use pse_poseidon::Poseidon;
    use rand::thread_rng;

    use crate::merkletree::native::MerkleTree;
    use crate::voter_circuit::{
        voter_circuit,
        EncryptionPublicKey,
        VoterCircuitInput,
        ENC_BIT_LEN,
        RATE,
        R_F,
        R_P,
        T,
    };

    #[test]
    fn test_voter_circuit() {
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
            proposal_id: Fr::random(rng.clone()),
            vote,
            r_enc,
            pk_voter,
            membership_proof,
            membership_proof_helper,
        };

        base_test()
            .k(15)
            .lookup_bits(14)
            .expect_satisfied(true)
            .run_builder(|pool, range| {
                let ctx = pool.main();

                let mut public_inputs = Vec::<AssignedValue<Fr>>::new();

                voter_circuit(ctx, &range, input, &mut public_inputs);
            })
    }
}
