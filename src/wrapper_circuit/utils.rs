use halo2_base::halo2_proofs::arithmetic::{CurveAffine, Field};
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::halo2_proofs::halo2curves::ff::PrimeField;
use halo2_base::halo2_proofs::halo2curves::group::Curve;
use halo2_base::halo2_proofs::halo2curves::secp256k1::{Fp, Fq, Secp256k1, Secp256k1Affine};
use halo2_base::utils::{fe_to_biguint, ScalarField};
use halo2_ecc::*;
use k256::elliptic_curve::hash2curve::GroupDigest;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{
    elliptic_curve::hash2curve::ExpandMsgXmd, sha2::Sha256 as K256Sha256,
    Secp256k1 as K256Secp256k1,
};
use num_bigint::{BigUint, RandBigInt};
use num_traits::pow;
use paillier_chip::paillier::{paillier_add_native, paillier_enc_native};
use pse_poseidon::Poseidon;
use rand::rngs::OsRng;
use rand::thread_rng;
use sha2::{Digest, Sha256};

use crate::merkletree::native::MerkleTree;
use crate::state_transition_circuit::utils::compress_native_nullifier;
use crate::state_transition_circuit::{IndexTreeInput, StateTranInput};
use crate::voter_circuit::utils::{gen_test_nullifier, verify_nullifier};
use crate::voter_circuit::{EncryptionPublicKey, VoterCircuitInput};
use indexed_merkle_tree_halo2::utils::{IndexedMerkleTree, IndexedMerkleTreeLeaf as IMTLeaf};

const ENC_BIT_LEN: usize = 176;
const T: usize = 3;
const RATE: usize = 2;
const R_F: usize = 8;
const R_P: usize = 57;

pub fn generate_random_voter_circuit_inputs(
    pk_enc: EncryptionPublicKey,
    nullifier: Secp256k1Affine,
    s: Fq,
    c: Fq,
    pk_voter: Secp256k1Affine,
    vote: Vec<Fr>,
    r_enc: Vec<BigUint>,
    leaves: Vec<Fr>,
) -> VoterCircuitInput<Fr> {
    let treesize = u32::pow(2, 3);

    let mut native_hasher = Poseidon::<Fr, T, RATE>::new(R_F, R_P);

    let mut membership_tree =
        MerkleTree::<Fr, T, RATE>::new(&mut native_hasher, leaves.clone()).unwrap();

    let membership_root = membership_tree.get_root();
    let (membership_proof, membership_proof_helper) = membership_tree.get_proof(0);
    assert_eq!(
        membership_tree.verify_proof(&leaves[0], 0, &membership_root, &membership_proof),
        true
    );

    let mut vote_enc = Vec::<BigUint>::with_capacity(vote.len());
    for i in 0..vote.len() {
        vote_enc[i] =
            paillier_enc_native(&pk_enc.n, &pk_enc.g, &fe_to_biguint(&vote[i]), &r_enc[i]);
    }

    verify_nullifier(&[1u8, 0u8], &nullifier, &pk_voter, &s, &c);

    let input = VoterCircuitInput::new(
        membership_root,
        pk_enc,
        nullifier,
        Fr::from(1u64),
        vote_enc,
        s,
        vote,
        r_enc,
        pk_voter,
        c,
        membership_proof.clone(),
        membership_proof_helper.clone(),
    );

    input
}

pub fn generate_random_state_transition_circuit_inputs(
    pk_enc: EncryptionPublicKey,
    nullifier_affine: Secp256k1Affine,
    incoming_vote: Vec<BigUint>,
    prev_vote: Vec<BigUint>,
) -> StateTranInput<Fr> {
    let tree_size = pow(2, 3);
    //  let mut leaves = (0..tree_size).map(|_|  Fr::from(0u64)).collect::<Vec<_>>();
    let mut leaves = Vec::<Fr>::new();

    let mut native_hasher = Poseidon::<Fr, T, RATE>::new(R_F, R_P);
    // Filling leaves with default values.
    for i in 0..tree_size {
        if i == 0 {
            native_hasher.update(&[Fr::from(0u64), Fr::from(0u64), Fr::from(0u64)]);
            leaves.push(native_hasher.squeeze_and_reset());
        } else {
            leaves.push(Fr::from(0u64));
        }
    }

    let nullifier_compress = compress_native_nullifier(&nullifier_affine);
    native_hasher.update(&nullifier_compress);
    let new_val = native_hasher.squeeze_and_reset();

    let mut tree =
        IndexedMerkleTree::<Fr, T, RATE>::new(&mut native_hasher, leaves.clone()).unwrap();

    let old_root = tree.get_root();
    let low_leaf = IMTLeaf::<Fr> {
        val: Fr::from(0u64),
        next_val: Fr::from(0u64),
        next_idx: Fr::from(0u64),
    };
    let (low_leaf_proof, low_leaf_proof_helper) = tree.get_proof(0);
    assert_eq!(
        tree.verify_proof(&leaves[0], 0, &tree.get_root(), &low_leaf_proof),
        true
    );

    let new_low_leaf = IMTLeaf::<Fr> {
        val: low_leaf.val,
        next_val: new_val,
        next_idx: Fr::from(1u64),
    };
    native_hasher.update(&[
        new_low_leaf.val,
        new_low_leaf.next_val,
        new_low_leaf.next_idx,
    ]);
    leaves[0] = native_hasher.squeeze_and_reset();
    tree = IndexedMerkleTree::<Fr, T, RATE>::new(&mut native_hasher, leaves.clone()).unwrap();
    let (new_leaf_proof, new_leaf_proof_helper) = tree.get_proof(1);
    assert_eq!(
        tree.verify_proof(&leaves[1], 1, &tree.get_root(), &new_leaf_proof),
        true
    );

    native_hasher.update(&[new_val, Fr::from(0u64), Fr::from(0u64)]);
    leaves[1] = native_hasher.squeeze_and_reset();
    tree = IndexedMerkleTree::<Fr, T, RATE>::new(&mut native_hasher, leaves.clone()).unwrap();

    let new_root = tree.get_root();
    let new_leaf = IMTLeaf::<Fr> {
        val: new_val,
        next_val: Fr::from(0u64),
        next_idx: Fr::from(0u64),
    };
    let new_leaf_index = Fr::from(1u64);
    let is_new_leaf_largest = Fr::from(true);

    let idx_input = IndexTreeInput::new(
        old_root,
        low_leaf,
        low_leaf_proof,
        low_leaf_proof_helper,
        new_root,
        new_leaf,
        new_leaf_index,
        new_leaf_proof,
        new_leaf_proof_helper,
        is_new_leaf_largest,
    );

    let input = StateTranInput::new(
        pk_enc,
        incoming_vote,
        prev_vote,
        idx_input,
        nullifier_affine,
    );

    input
}

fn generate_randown_wrapper_circuit(no_round: usize) {
    let mut rng = thread_rng();
    let n = rng.gen_biguint(ENC_BIT_LEN as u64);
    let g = rng.gen_biguint(ENC_BIT_LEN as u64);
    let pk_enc = EncryptionPublicKey {
        n: n.clone(),
        g: g.clone(),
    };

    let mut leaves = Vec::<Fr>::new();
    let mut native_hasher = Poseidon::<Fr, T, RATE>::new(R_F, R_P);

    let sk = (0..no_round).map(|_| Fq::random(OsRng)).collect::<Vec<_>>();
    let pk_voter = sk
        .iter()
        .map(|sk| (Secp256k1::generator() * (*sk)).to_affine())
        .collect::<Vec<_>>();

    let pk_voter_x = pk_voter
        .iter()
        .map(|pk_v| {
            pk_v.x
                .to_bytes()
                .to_vec()
                .chunks(11)
                .into_iter()
                .map(|chunk| Fr::from_bytes_le(chunk))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    let pk_voter_y = pk_voter
        .iter()
        .map(|pk_v| {
            pk_v.y
                .to_bytes()
                .to_vec()
                .chunks(11)
                .into_iter()
                .map(|chunk| Fr::from_bytes_le(chunk))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    for (x, y) in pk_voter_x.iter().zip(pk_voter_y.clone()) {
        native_hasher.update(x.as_slice());
        native_hasher.update(y.as_slice());
        leaves.push(native_hasher.squeeze_and_reset());
    }

    for i in no_round..8 {
        native_hasher.update(&[Fr::ZERO]);
        leaves.push(native_hasher.squeeze_and_reset());
    }

    let mut vote = [Fr::one(), Fr::zero(), Fr::zero(), Fr::zero(), Fr::zero()].to_vec();
    let mut prev_vote = Vec::<BigUint>::new();

    for i in 0..no_round {
        let (nullifier, s, c) = gen_test_nullifier(&sk[i], &[1u8, 0u8]);
        verify_nullifier(&[1u8, 0u8], &nullifier, &pk_voter[i], &s, &c);

        let r_enc = (0..5)
            .map(|_| rng.gen_biguint(ENC_BIT_LEN as u64))
            .collect::<Vec<_>>();

        if i == 0 {
            prev_vote = (0..5)
                .map(|_| {
                    paillier_enc_native(&n, &g, &rng.gen_biguint(ENC_BIT_LEN as u64), &r_enc[i])
                })
                .collect::<Vec<_>>();
        }

        let voter_input = generate_random_voter_circuit_inputs(
            pk_enc.clone(),
            nullifier,
            s,
            c,
            pk_voter[i],
            vote.clone(),
            r_enc.clone(),
            leaves.clone(),
        );
        let mut vote_enc = Vec::<BigUint>::with_capacity(5);
        for i in 0..5 {
            vote_enc.push(paillier_enc_native(
                &n,
                &g,
                &fe_to_biguint(&vote[i]),
                &r_enc[i],
            ));
        }
        let state_input = generate_random_state_transition_circuit_inputs(
            pk_enc.clone(),
            nullifier,
            vote_enc.clone(),
            prev_vote.clone(),
        );

        prev_vote = prev_vote
            .iter()
            .zip(vote_enc)
            .map(|(x, y)| paillier_add_native(&n, &x, &y))
            .collect::<Vec<_>>();

        vote[i] = Fr::zero();
        if i != no_round {
            vote[i + 1] = Fr::one();
        }
    }
    // let input = VoterCircuitInput {
    //     membership_root,
    //   1  pk_enc,
    //   3  nullifier,
    //     proposal_id: Fr::from(1u64),
    //   -  s_nullifier: s,
    //   -  vote,
    //     r_enc,
    //   -  pk_voter,
    //   -  c_nullifier: c,
    //     membership_proof: membership_proof.clone(),
    //     membership_proof_helper: membership_proof_helper.clone(),
    // };

    // let input = StateTranInput {
    //   1  pk_enc,
    //   -  incoming_vote,
    //   -   prev_vote,
    //      nullifier_tree: idx_input,
    //   3  nullifier: nullifier_affine,
    // };
    // let idx_input = IndexTreeInput {
    //     old_root,
    //     low_leaf,
    //     low_leaf_proof,
    //     low_leaf_proof_helper,
    //     new_root,
    //     new_leaf,
    //     new_leaf_index,
    //     new_leaf_proof,
    //     new_leaf_proof_helper,
    //     is_new_leaf_largest,
    // };
}
