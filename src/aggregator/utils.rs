use halo2_ecc::bigint::OverflowInteger;
use num_bigint::BigUint;

use crate::merkletree::native::MerkleTree;
use crate::aggregator::{ AggregatorCircuitInput, IndexedMerkleLeaf };
use halo2_base::halo2_proofs::arithmetic::Field;
use halo2_base::halo2_proofs::halo2curves::grumpkin::Fq as Fr;
use halo2_base::utils::{ fe_to_biguint, BigPrimeField };

use num_traits::Zero;
use pse_poseidon::Poseidon;

pub(crate) fn paillier_enc_native(n: &BigUint, g: &BigUint, m: &BigUint, r: &BigUint) -> BigUint {
    let n2 = n * n;
    let gm = g.modpow(m, &n2);
    let rn = r.modpow(n, &n2);
    (gm * rn) % n2
}

pub(crate) fn to_biguint<F: BigPrimeField>(int: OverflowInteger<F>, limb_bits: usize) -> BigUint {
    int.limbs
        .iter()
        .rev()
        .fold(BigUint::zero(), |acc, acell| { (acc << limb_bits) + fe_to_biguint(acell.value()) })
}

pub(crate) fn generate_idx_input(n: BigUint, g: BigUint) -> AggregatorCircuitInput {
    const T: usize = 3;
    const RATE: usize = 2;
    const R_F: usize = 8;
    const R_P: usize = 57;

    let tree_size = u32::pow(2, 3);
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
    let mut tree = MerkleTree::<Fr, T, RATE>::new(&mut native_hasher, leaves.clone()).unwrap();

    let new_val = Fr::from(69u64);

    let low_leaf = IndexedMerkleLeaf::<Fr> {
        val: Fr::from(0u64),
        next_val: Fr::from(0u64),
        next_idx: Fr::from(0u64),
    };
    let (low_leaf_proof, low_leaf_proof_helper) = tree.get_proof(0);
    assert_eq!(tree.verify_proof(&leaves[0], 0, &tree.get_root(), &low_leaf_proof), true);

    // compute interim state change
    let new_low_leaf = IndexedMerkleLeaf::<Fr> {
        val: low_leaf.val,
        next_val: new_val,
        next_idx: Fr::from(1u64),
    };
    native_hasher.update(&[new_low_leaf.val, new_low_leaf.next_val, new_low_leaf.next_idx]);
    leaves[0] = native_hasher.squeeze_and_reset();
    tree = MerkleTree::<Fr, T, RATE>::new(&mut native_hasher, leaves.clone()).unwrap();
    let (new_leaf_proof, new_leaf_proof_helper) = tree.get_proof(1);
    assert_eq!(tree.verify_proof(&leaves[1], 1, &tree.get_root(), &new_leaf_proof), true);

    native_hasher.update(&[new_val, Fr::from(0u64), Fr::from(0u64)]);
    leaves[1] = native_hasher.squeeze_and_reset();
    tree = MerkleTree::<Fr, T, RATE>::new(&mut native_hasher, leaves.clone()).unwrap();

    let new_root = tree.get_root();
    let new_leaf = IndexedMerkleLeaf::<Fr> {
        val: new_val,
        next_val: Fr::from(0u64),
        next_idx: Fr::from(0u64),
    };

    AggregatorCircuitInput {
        low_leaf,
        low_leaf_proof,
        low_leaf_proof_helper,
        new_root,
        new_leaf,
        new_leaf_index: Fr::ONE,
        new_leaf_proof,
        new_leaf_proof_helper,
        is_new_leaf_largest: Fr::ONE,
        limb_bit_len: 88,
        enc_bit_len: 176,
    }
}
