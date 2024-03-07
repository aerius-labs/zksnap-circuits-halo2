use crate::{
    state_transition_circuit::{ StateTranInput, ENC_BIT_LEN },
    voter_circuit::EncryptionPublicKey,
};

use super::IndexTreeInput;
use halo2_base::{
    halo2_proofs::{
        arithmetic::Field,
        halo2curves::{ bn256::Fr, secp256k1::Secp256k1Affine, secq256k1::Fp },
    },
    utils::ScalarField,
};
use indexed_merkle_tree_halo2::utils::{ IndexedMerkleTree, IndexedMerkleTreeLeaf as IMTLeaf };
use num_bigint::{ BigUint, RandBigInt };
use num_traits::pow;
use paillier_chip::paillier::paillier_enc_native;
use pse_poseidon::Poseidon;
use rand::{ rngs::OsRng, thread_rng };

pub fn compress_native_nullifier(point: &Secp256k1Affine) -> [Fr; 4] {
    let y_is_odd = BigUint::from_bytes_le(&point.y.to_bytes_le()) % 2u64;
    let tag = if y_is_odd == BigUint::from(0u64) { Fr::from(2u64) } else { Fr::from(3u64) };

    let x_limbs = point.x
        .to_bytes_le()
        .chunks(11)
        .map(|chunk| Fr::from_bytes_le(chunk))
        .collect::<Vec<_>>();

    [tag, x_limbs[0], x_limbs[1], x_limbs[2]]
}

pub fn generate_random_state_transition_circuit_inputs() -> StateTranInput<Fr> {
    const T: usize = 3;
    const RATE: usize = 2;
    const R_F: usize = 8;
    const R_P: usize = 57;

    let tree_size = pow(2, 3);
    let mut leaves = Vec::<Fr>::new();

    let mut native_hasher = Poseidon::<Fr, T, RATE>::new(R_F, R_P);

    // Filling leaves with dfault values.
    for i in 0..tree_size {
        if i == 0 {
            native_hasher.update(&[Fr::from(0u64), Fr::from(0u64), Fr::from(0u64)]);
            leaves.push(native_hasher.squeeze_and_reset());
        } else {
            leaves.push(Fr::from(0u64));
        }
    }
    let mut tree = IndexedMerkleTree::<Fr, T, RATE>
        ::new(&mut native_hasher, leaves.clone())
        .unwrap();

    let new_val = Fr::from(69u64);

    let old_root = tree.get_root();
    let low_leaf = IMTLeaf::<Fr> {
        val: Fr::from(0u64),
        next_val: Fr::from(0u64),
        next_idx: Fr::from(0u64),
    };
    let (low_leaf_proof, low_leaf_proof_helper) = tree.get_proof(0);
    assert_eq!(tree.verify_proof(&leaves[0], 0, &tree.get_root(), &low_leaf_proof), true);

    // compute interim state change
    let new_low_leaf = IMTLeaf::<Fr> {
        val: low_leaf.val,
        next_val: new_val,
        next_idx: Fr::from(1u64),
    };
    native_hasher.update(&[new_low_leaf.val, new_low_leaf.next_val, new_low_leaf.next_idx]);
    leaves[0] = native_hasher.squeeze_and_reset();
    tree = IndexedMerkleTree::<Fr, T, RATE>::new(&mut native_hasher, leaves.clone()).unwrap();
    let (new_leaf_proof, new_leaf_proof_helper) = tree.get_proof(1);
    assert_eq!(tree.verify_proof(&leaves[1], 1, &tree.get_root(), &new_leaf_proof), true);

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

    let idx_input = IndexTreeInput {
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
    };

    let sk = Fp::random(OsRng);
    let nullifier_affine = Secp256k1Affine::from(Secp256k1Affine::generator() * sk);

    let mut rng = thread_rng();

    let n = rng.gen_biguint(ENC_BIT_LEN as u64);
    let g = rng.gen_biguint(ENC_BIT_LEN as u64);
    let pk_enc = EncryptionPublicKey { n: n.clone(), g: g.clone() };
    let incoming_vote = (0..5)
        .map(|_|
            paillier_enc_native(
                &n,
                &g,
                &rng.gen_biguint(ENC_BIT_LEN as u64),
                &rng.gen_biguint(ENC_BIT_LEN as u64)
            )
        )
        .collect::<Vec<_>>();
    let prev_vote = (0..5)
        .map(|_|
            paillier_enc_native(
                &n,
                &g,
                &rng.gen_biguint(ENC_BIT_LEN as u64),
                &rng.gen_biguint(ENC_BIT_LEN as u64)
            )
        )
        .collect::<Vec<_>>();

    let input = StateTranInput {
        pk_enc,
        incoming_vote,
        prev_vote,
        nullifier_tree: idx_input,
        nullifier: nullifier_affine,
    };

    input
}
