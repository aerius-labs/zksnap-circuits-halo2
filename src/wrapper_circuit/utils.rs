use halo2_base::halo2_proofs::arithmetic::Field;
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::halo2_proofs::halo2curves::group::Curve;
use halo2_base::halo2_proofs::halo2curves::secp256k1::{Fq, Secp256k1, Secp256k1Affine};
use halo2_base::utils::{fe_to_biguint, ScalarField};
use halo2_ecc::*;
use num_bigint::{BigUint, RandBigInt};
use num_traits::pow;
use paillier_chip::paillier::{paillier_add_native, paillier_enc_native};
use pse_poseidon::Poseidon;
use rand::rngs::OsRng;
use rand::thread_rng;

use crate::merkletree::native::MerkleTree;
use crate::state_transition_circuit::utils::{
    compress_native_nullifier, generate_random_state_transition_circuit_inputs,
};
use crate::state_transition_circuit::{IndexTreeInput, StateTranInput};
use crate::voter_circuit::utils::{
    gen_test_nullifier, generate_random_voter_circuit_inputs, verify_nullifier,
};
use crate::voter_circuit::{EncryptionPublicKey, VoterCircuitInput};
use indexed_merkle_tree_halo2::utils::{IndexedMerkleTree, IndexedMerkleTreeLeaf as IMTLeaf};

const ENC_BIT_LEN: usize = 176;
const T: usize = 3;
const RATE: usize = 2;
const R_F: usize = 8;
const R_P: usize = 57;

fn generate_voter_circuit_inputs(
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
        vote_enc.push(paillier_enc_native(
            &pk_enc.n,
            &pk_enc.g,
            &fe_to_biguint(&vote[i]),
            &r_enc[i],
        ))
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

fn update_idx_leaf(leaves: Vec<IMTLeaf<Fr>>, new_val: Fr, new_val_idx: u64) -> (Vec<IMTLeaf<Fr>> ,usize){
    let mut idx_leaves = leaves.clone();
    let mut low_leaf_idx=0;
    for (i, node) in leaves.iter().enumerate() {
        if node.next_val == Fr::zero() && i == 0 {
            idx_leaves[i + 1].val = new_val;
            idx_leaves[i].next_val = new_val;
            idx_leaves[i].next_idx = Fr::from(i as u64 + 1);
            low_leaf_idx=i;
            break;
        }
        if node.val < new_val && (node.next_val > new_val || node.next_val==Fr::zero()){
            idx_leaves[new_val_idx as usize].val = new_val;
            idx_leaves[new_val_idx as usize].next_val = idx_leaves[i].next_val;
            idx_leaves[new_val_idx as usize].next_idx = idx_leaves[i].next_idx;
            idx_leaves[i].next_val = new_val;
            idx_leaves[i].next_idx = Fr::from(new_val_idx);
            low_leaf_idx=i;
        }
    }
    (idx_leaves,low_leaf_idx)
}

fn generate_state_transition_circuit_inputs(
    pk_enc: EncryptionPublicKey,
    nullifier_affine: Secp256k1Affine,
    incoming_vote: Vec<BigUint>,
    prev_vote: Vec<BigUint>,
    idx_tree_leaf:Vec<IMTLeaf<Fr>>,
    new_val: Fr,
    round:u64
) -> StateTranInput<Fr> {
    let tree_size = pow(2, 3);
    let mut leaves = Vec::<Fr>::new();
    let mut native_hasher = Poseidon::<Fr, T, RATE>::new(R_F, R_P);

    for i in 0..tree_size {
            native_hasher.update(&[idx_tree_leaf[i].val, idx_tree_leaf[i].next_idx, idx_tree_leaf[i].next_val]);
            leaves.push(native_hasher.squeeze_and_reset());
        
    }

    let nullifier_compress = compress_native_nullifier(&nullifier_affine);
    native_hasher.update(&nullifier_compress);
    let new_val = native_hasher.squeeze_and_reset();

    let mut tree =
        IndexedMerkleTree::<Fr, T, RATE>::new(&mut native_hasher, leaves.clone()).unwrap();

    let old_root = tree.get_root();

    
    let (updated_idx_leaves,low_leaf_idx)=update_idx_leaf(idx_tree_leaf, new_val, round);
    let low_leaf=idx_tree_leaf[low_leaf_idx];
    let (low_leaf_proof, low_leaf_proof_helper) = tree.get_proof(low_leaf_idx);
    assert_eq!(
        tree.verify_proof(&leaves[low_leaf_idx], low_leaf_idx, &tree.get_root(), &low_leaf_proof),
        true
    );

    let new_low_leaf = updated_idx_leaves[low_leaf_idx];
    native_hasher.update(&[
        new_low_leaf.val,
        new_low_leaf.next_val,
        new_low_leaf.next_idx,
    ]);
    leaves[low_leaf_idx] = native_hasher.squeeze_and_reset();
    tree = IndexedMerkleTree::<Fr, T, RATE>::new(&mut native_hasher, leaves.clone()).unwrap();
    let (new_leaf_proof, new_leaf_proof_helper) = tree.get_proof(round as usize);
    assert_eq!(
        tree.verify_proof(&leaves[round as usize], round as usize, &tree.get_root(), &new_leaf_proof),
        true
    );

    native_hasher.update(&[updated_idx_leaves[round as usize].val, updated_idx_leaves[round as usize].next_idx,updated_idx_leaves[round as usize].next_val]);
    leaves[round as usize] = native_hasher.squeeze_and_reset();
    tree = IndexedMerkleTree::<Fr, T, RATE>::new(&mut native_hasher, leaves.clone()).unwrap();

    let new_root = tree.get_root();
    let new_leaf = IMTLeaf::<Fr> {
        val: updated_idx_leaves[round as usize].val,
        next_val:updated_idx_leaves[round as usize].next_idx,
        next_idx:updated_idx_leaves[round as usize].next_val,
    };
    let new_leaf_index = Fr::from(round);
    let is_new_leaf_largest = if new_leaf.next_val==Fr::zero(){Fr::one()}else {Fr::zero()};

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

pub(crate) fn generate_wrapper_circuit_input(
    num_round: usize,
) -> (VoterCircuitInput<Fr>, StateTranInput<Fr>) {
    let mut rng = thread_rng();
    let n = rng.gen_biguint(ENC_BIT_LEN as u64);
    let g = rng.gen_biguint(ENC_BIT_LEN as u64);
    let pk_enc = EncryptionPublicKey {
        n: n.clone(),
        g: g.clone(),
    };

    let mut leaves = Vec::<Fr>::new();
    let mut native_hasher = Poseidon::<Fr, T, RATE>::new(R_F, R_P);

    let sk = (0..num_round)
        .map(|_| Fq::random(OsRng))
        .collect::<Vec<_>>();
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

    for _ in num_round..8 {
        native_hasher.update(&[Fr::ZERO]);
        leaves.push(native_hasher.squeeze_and_reset());
    }

    let mut vote = [Fr::one(), Fr::zero(), Fr::zero(), Fr::zero(), Fr::zero()].to_vec();
    let mut prev_vote = Vec::<BigUint>::new();

    let mut voter_input: VoterCircuitInput<Fr> = generate_random_voter_circuit_inputs();
    let mut state_input: StateTranInput<Fr> = generate_random_state_transition_circuit_inputs();

    for i in 0..num_round {
        let (nullifier, s, c) = gen_test_nullifier(&sk[i], &[1u8, 0u8]);
        verify_nullifier(&[1u8, 0u8], &nullifier, &pk_voter[i], &s, &c);

        let r_enc = (0..5)
            .map(|_| rng.gen_biguint(ENC_BIT_LEN as u64))
            .collect::<Vec<_>>();

        if i == 0 {
            prev_vote = (0..5)
                .map(|_| paillier_enc_native(&n, &g, &BigUint::from(0u64), &r_enc[i]))
                .collect::<Vec<_>>();
        }

        voter_input = generate_voter_circuit_inputs(
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

        state_input = generate_state_transition_circuit_inputs(
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
        if i != num_round {
            vote[i + 1] = Fr::one();
        }
    }

    (voter_input, state_input)
}

#[test]
fn test_update_idx_leaf() {
    let mut leaves = (0..8)
        .map(|_| IMTLeaf::<Fr> {
            val: Fr::from(0u64),
            next_val: Fr::from(0u64),
            next_idx: Fr::from(0u64),
        })
        .collect::<Vec<_>>();

    leaves = update_idx_leaf(leaves, Fr::from(30), 1);

    println!("--------------test 1 -------------");

    println!("leave 1 ={:?}", leaves[0].val);
    println!("leave 1 ={:?}", leaves[0].next_idx);
    println!("leave 1 ={:?}\n", leaves[0].next_val);

    println!("leave 2 ={:?}", leaves[1].val);
    println!("leave 2 ={:?}", leaves[1].next_idx);
    println!("leave 2 ={:?}\n", leaves[1].next_val);

    leaves = update_idx_leaf(leaves, Fr::from(10), 2);
    println!("--------------test 2 -------------");

    println!("leave 1 ={:?}", leaves[0].val);
    println!("leave 1 ={:?}", leaves[0].next_idx);
    println!("leave 1 ={:?}\n", leaves[0].next_val);

    println!("leave 2 ={:?}", leaves[1].val);
    println!("leave 2 ={:?}", leaves[1].next_idx);
    println!("leave 2 ={:?}\n", leaves[1].next_val);

    println!("leave 3 ={:?}", leaves[2].val);
    println!("leave 3 ={:?}", leaves[2].next_idx);
    println!("leave 3 ={:?}\n", leaves[2].next_val);

    leaves = update_idx_leaf(leaves, Fr::from(20), 3);
    println!("--------------test 3 -------------");

    println!("leave 1 ={:?}", leaves[0].val);
    println!("leave 1 ={:?}", leaves[0].next_idx);
    println!("leave 1 ={:?}\n", leaves[0].next_val);

    println!("leave 2 ={:?}", leaves[1].val);
    println!("leave 2 ={:?}", leaves[1].next_idx);
    println!("leave 2 ={:?}\n", leaves[1].next_val);

    println!("leave 3 ={:?}", leaves[2].val);
    println!("leave 3 ={:?}", leaves[2].next_idx);
    println!("leave 3 ={:?}\n", leaves[2].next_val);

    println!("leave 4 ={:?}", leaves[3].val);
    println!("leave 4 ={:?}", leaves[3].next_idx);
    println!("leave 4 ={:?}\n", leaves[3].next_val);

    leaves = update_idx_leaf(leaves, Fr::from(50), 4);
    println!("--------------test 4 -------------");

    println!("leave 1 ={:?}", leaves[0].val);
    println!("leave 1 ={:?}", leaves[0].next_idx);
    println!("leave 1 ={:?}\n", leaves[0].next_val);

    println!("leave 2 ={:?}", leaves[1].val);
    println!("leave 2 ={:?}", leaves[1].next_idx);
    println!("leave 2 ={:?}\n", leaves[1].next_val);

    println!("leave 3 ={:?}", leaves[2].val);
    println!("leave 3 ={:?}", leaves[2].next_idx);
    println!("leave 3 ={:?}\n", leaves[2].next_val);

    println!("leave 4 ={:?}", leaves[3].val);
    println!("leave 4 ={:?}", leaves[3].next_idx);
    println!("leave 4 ={:?}\n", leaves[3].next_val);

    println!("leave 5 ={:?}", leaves[4].val);
    println!("leave 5 ={:?}", leaves[4].next_idx);
    println!("leave 5 ={:?}\n", leaves[4].next_val);
}
