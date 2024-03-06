use std::str::FromStr;

use elliptic_curve::Field;
use halo2_base::poseidon::hasher::{spec::OptimizedPoseidonSpec, PoseidonHasher};
use halo2_base::utils::{fe_to_biguint, ScalarField};
use halo2_base::{
    gates::{RangeChip, RangeInstructions},
    halo2_proofs::{circuit::Value, halo2curves::bn256::Fr},
    utils::{testing::base_test, BigPrimeField},
    AssignedValue, Context,
};
use halo2_ecc::ecc::EccChip;
use halo2_ecc::fields::fp::FpChip;
use indexed_merkle_tree_halo2::indexed_merkle_tree::{insert_leaf, IndexedMerkleTreeLeaf};
use indexed_merkle_tree_halo2::utils::{IndexedMerkleTree, IndexedMerkleTreeLeaf as IMTLeaf};
use num_bigint::{BigUint, RandBigInt};
use num_traits::pow;
use pse_poseidon::Poseidon;
use rand::rngs::OsRng;
use rand::thread_rng;

use crate::voter_circuit::EncryptionPublicKey;
use biguint_halo2::big_uint::chip::BigUintChip;
use halo2_base::halo2_proofs::halo2curves::secp256k1::{Fp, Fq, Secp256k1, Secp256k1Affine};
use paillier_chip::paillier::{EncryptionPublicKeyAssigned, PaillierChip};

const ENC_BIT_LEN: usize = 264;
const LIMB_BIT_LEN: usize = 88;

//TODO: Constrain the nullifier hash using x and y limbs

#[derive(Debug, Clone)]
pub struct IndexTreeInput<F: BigPrimeField> {
    old_root: F,
    low_leaf: IMTLeaf<F>,
    low_leaf_proof: Vec<F>,
    low_leaf_proof_helper: Vec<F>,
    new_root: F,
    new_leaf: IMTLeaf<F>,
    new_leaf_index: F,
    new_leaf_proof: Vec<F>,
    new_leaf_proof_helper: Vec<F>,
    is_new_leaf_largest: F,
}

#[derive(Debug, Clone)]
pub struct StateTranInput<F: BigPrimeField> {
    pk_enc: EncryptionPublicKey,
    inc_enc_vote: Vec<BigUint>,
    prev_enc_vote: Vec<BigUint>,
    indx_tree: IndexTreeInput<F>,
    nullifier: Secp256k1Affine,
}
pub fn state_trans_circuit<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    input: StateTranInput<F>,
    public_inputs: &mut Vec<AssignedValue<F>>,
) {
    let mut output = Vec::<AssignedValue<F>>::new();

    let gate = range.gate();
    let mut hasher = PoseidonHasher::<F, 3, 2>::new(OptimizedPoseidonSpec::new::<8, 57, 0>());
    hasher.initialize_consts(ctx, gate);

    let biguint_chip = BigUintChip::construct(range, LIMB_BIT_LEN);
    let paillier_chip = PaillierChip::construct(&biguint_chip, ENC_BIT_LEN);

    let fp_chip = FpChip::<F, Fp>::new(range, LIMB_BIT_LEN, 3);
    let ecc_chip = EccChip::<F, FpChip<F, Fp>>::new(&fp_chip);
    let null_clone = input.nullifier.clone();
    let nullifier = ecc_chip.load_private_unchecked(ctx, (input.nullifier.x, input.nullifier.y));
    let nulli_x = nullifier.x().limbs();
    let nulli_y = nullifier.y().limbs();
    nulli_x.to_vec().extend(nulli_y.to_vec());
    //let nullifier_hash = hasher.hash_fix_len_array(ctx, gate, nulli_x);

    let nullifier_fr = null_clone
        .x
        .to_bytes()
        .to_vec()
        .chunks(11)
        .into_iter()
        .map(|chunk| F::from_bytes_le(chunk))
        .collect::<Vec<_>>();
    let nullifier_assign = nullifier_fr
        .iter()
        .map(|x| ctx.load_witness(*x))
        .collect::<Vec<_>>();
    let nullifier_hash = hasher.hash_fix_len_array(ctx, gate, &nullifier_assign);

    println!("nullifier_hash: {:?}", nullifier_hash);

    let n_assigned = biguint_chip
        .assign_integer(ctx, Value::known(input.pk_enc.n.clone()), ENC_BIT_LEN)
        .unwrap();

    let g_assigned = biguint_chip
        .assign_integer(ctx, Value::known(input.pk_enc.g.clone()), ENC_BIT_LEN)
        .unwrap();

    let pk_enc = EncryptionPublicKeyAssigned {
        n: n_assigned,
        g: g_assigned,
    };

    let inc_enc_vote = input
        .inc_enc_vote
        .iter()
        .map(|x| {
            biguint_chip
                .assign_integer(ctx, Value::known(x.clone()), ENC_BIT_LEN)
                .unwrap()
        })
        .collect::<Vec<_>>();
    let prev_enc_vote = input
        .prev_enc_vote
        .iter()
        .map(|x| {
            biguint_chip
                .assign_integer(ctx, Value::known(x.clone()), ENC_BIT_LEN)
                .unwrap()
        })
        .collect::<Vec<_>>();

    let aggr_vote = inc_enc_vote
        .iter()
        .zip(prev_enc_vote)
        .map(|(x, y)| paillier_chip.add(ctx, &pk_enc, x, &y).unwrap())
        .collect::<Vec<_>>();

    //nullifier
    let val = ctx.load_witness(input.indx_tree.low_leaf.val);
    let next_val = ctx.load_witness(input.indx_tree.low_leaf.next_val);
    let next_idx = ctx.load_witness(input.indx_tree.low_leaf.next_idx);

    let old_root = ctx.load_witness(input.indx_tree.old_root);
    let low_leaf = IndexedMerkleTreeLeaf::new(val, next_val, next_idx);

    let new_root = ctx.load_witness(input.indx_tree.new_root);

    let val = ctx.load_witness(input.indx_tree.new_leaf.val);
    ctx.constrain_equal(&val, &nullifier_hash);
    let next_val = ctx.load_witness(input.indx_tree.new_leaf.next_val);
    let next_idx = ctx.load_witness(input.indx_tree.new_leaf.next_idx);

    let new_leaf = IndexedMerkleTreeLeaf::new(val, next_val, next_idx);

    let new_leaf_index = ctx.load_witness(input.indx_tree.new_leaf_index);
    let is_new_leaf_largest = ctx.load_witness(input.indx_tree.is_new_leaf_largest);

    let low_leaf_proof = input
        .indx_tree
        .low_leaf_proof
        .iter()
        .map(|x| ctx.load_witness(*x))
        .collect::<Vec<_>>();
    let low_leaf_proof_helper = input
        .indx_tree
        .low_leaf_proof_helper
        .iter()
        .map(|x| ctx.load_witness(*x))
        .collect::<Vec<_>>();
    let new_leaf_proof = input
        .indx_tree
        .new_leaf_proof
        .iter()
        .map(|x| ctx.load_witness(*x))
        .collect::<Vec<_>>();
    let new_leaf_proof_helper = input
        .indx_tree
        .new_leaf_proof_helper
        .iter()
        .map(|x| ctx.load_witness(*x))
        .collect::<Vec<_>>();

    //TODO: works for 252 num_bits ,make it working for 254 num_bits

    insert_leaf::<F, 3, 2>(
        ctx,
        range,
        &hasher,
        &old_root,
        &low_leaf,
        &low_leaf_proof,
        &low_leaf_proof_helper,
        &new_root,
        &new_leaf,
        &new_leaf_index,
        &new_leaf_proof,
        &new_leaf_proof_helper,
        &is_new_leaf_largest,
    );

    //TODO: Output the public outputs
}

#[test]
fn test_state_trans_circuit() {
    const T: usize = 3;
    const RATE: usize = 2;
    const R_F: usize = 8;
    const R_P: usize = 57;
    type F = Fr;

    let tree_size = pow(2, 3);
    let mut leaves = Vec::<F>::new();
    let mut native_hasher = Poseidon::<F, T, RATE>::new(R_F, R_P);
    let mut rng = thread_rng();

    // Filling leaves with dfault values.
    for i in 0..tree_size {
        if i == 0 {
            native_hasher.update(&[F::from(0u64), F::from(0u64), F::from(0u64)]);
            leaves.push(native_hasher.squeeze_and_reset());
        } else {
            leaves.push(F::from(0u64));
        }
    }
    let sk = Fq::random(OsRng);
    let nullifier_affine = Secp256k1Affine::from(Secp256k1::generator() * sk);
    let nullifier_fr = nullifier_affine
        .x
        .to_bytes()
        .to_vec()
        .chunks(11)
        .into_iter()
        .map(|chunk| F::from_bytes_le(chunk))
        .collect::<Vec<_>>();

    native_hasher.update(&nullifier_fr);
    let new_val = native_hasher.squeeze_and_reset();
    println!("nullifier hash test: {:?}", new_val);
    let new_val_biguint = fe_to_biguint(&new_val);

    // let str = "103220197667183618101663170908058135042116436";
    // let new_val_biguint = BigUint::from_str(str).unwrap();
    // let new_val = Fr::from_u64_digits(&new_val_biguint.to_u64_digits());

    let mut tree =
        IndexedMerkleTree::<F, T, RATE>::new(&mut native_hasher, leaves.clone()).unwrap();
    println!("num_val: {:?}", new_val);

    let old_root = tree.get_root();
    let low_leaf = IMTLeaf::<F> {
        val: F::from(0u64),
        next_val: F::from(0u64),
        next_idx: F::from(0u64),
    };
    let (low_leaf_proof, low_leaf_proof_helper) = tree.get_proof(0);
    assert_eq!(
        tree.verify_proof(&leaves[0], 0, &tree.get_root(), &low_leaf_proof),
        true
    );

    // compute interim state change
    let new_low_leaf = IMTLeaf::<F> {
        val: low_leaf.val,
        next_val: new_val,
        next_idx: F::from(1u64),
    };
    native_hasher.update(&[
        new_low_leaf.val,
        new_low_leaf.next_val,
        new_low_leaf.next_idx,
    ]);
    leaves[0] = native_hasher.squeeze_and_reset();
    tree = IndexedMerkleTree::<F, T, RATE>::new(&mut native_hasher, leaves.clone()).unwrap();
    let (new_leaf_proof, new_leaf_proof_helper) = tree.get_proof(1);
    assert_eq!(
        tree.verify_proof(&leaves[1], 1, &tree.get_root(), &new_leaf_proof),
        true
    );

    native_hasher.update(&[new_val, F::from(0u64), F::from(0u64)]);
    leaves[1] = native_hasher.squeeze_and_reset();
    tree = IndexedMerkleTree::<F, T, RATE>::new(&mut native_hasher, leaves.clone()).unwrap();

    let new_root = tree.get_root();
    let new_leaf = IMTLeaf::<F> {
        val: new_val,
        next_val: F::from(0u64),
        next_idx: F::from(0u64),
    };
    let new_leaf_index = F::from(1u64);
    let is_new_leaf_largest = F::from(true);

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
    let n = rng.gen_biguint(ENC_BIT_LEN as u64);
    let g = rng.gen_biguint(ENC_BIT_LEN as u64);
    let pk_enc = EncryptionPublicKey { n, g };
    let inc_enc_vote = (0..5)
        .map(|_| rng.gen_biguint(ENC_BIT_LEN as u64))
        .collect::<Vec<_>>();
    let prev_enc_vote = (0..5)
        .map(|_| rng.gen_biguint(ENC_BIT_LEN as u64))
        .collect::<Vec<_>>();

    let input = StateTranInput {
        pk_enc,
        inc_enc_vote,
        prev_enc_vote,
        indx_tree: idx_input,
        nullifier: nullifier_affine,
    };
    base_test()
        .k(19)
        .lookup_bits(18)
        .expect_satisfied(true)
        .run(|ctx, range| {
            let mut public_inputs = Vec::<AssignedValue<F>>::new();

            state_trans_circuit(ctx, range, input, &mut public_inputs)
        });
}
