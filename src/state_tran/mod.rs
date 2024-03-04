use halo2_base::poseidon::hasher::{spec::OptimizedPoseidonSpec, PoseidonHasher};
use halo2_base::{
    gates::{RangeChip, RangeInstructions},
    halo2_proofs::{circuit::Value, halo2curves::bn256::Fr},
    utils::{testing::base_test, BigPrimeField, ScalarField},
    AssignedValue, Context,
};
use indexed_merkle_tree_halo2::indexed_merkle_tree::{insert_leaf, IndexedMerkleTreeLeaf};
use indexed_merkle_tree_halo2::utils::{IndexedMerkleTree, IndexedMerkleTreeLeaf as IMTLeaf};
use num_bigint::{BigUint, RandBigInt};
use num_traits::pow;
use pse_poseidon::Poseidon;
use rand::thread_rng;

use crate::voter_circuit::EncryptionPublicKey;
use biguint_halo2::big_uint::chip::BigUintChip;
use halo2_base::halo2_proofs::halo2curves::secp256k1::{Fq, Secp256k1Affine};
use paillier_chip::paillier::{EncryptionPublicKeyAssigned, PaillierChip};

const ENC_BIT_LEN: usize = 264;
const LIMB_BIT_LEN: usize = 88;

//TODO: Deserialize,Clone and Default for IndexedMerkleTreeLeaf

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
    proposal_id: F,
    inc_enc_vote: Vec<BigUint>,
    prev_enc_vote: Vec<BigUint>,
    indx_tree: IndexTreeInput<F>,
}
pub fn state_trans_circuit(
    ctx: &mut Context<Fr>,
    range: &RangeChip<Fr>,
    input: StateTranInput<Fr>,
    public_inputs: &mut Vec<AssignedValue<Fr>>,
) {
    let biguint_chip = BigUintChip::construct(range, LIMB_BIT_LEN);
    let paillier_chip = PaillierChip::construct(&biguint_chip, ENC_BIT_LEN);
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

    let gate = range.gate();
    let mut hasher = PoseidonHasher::<Fr, 3, 2>::new(OptimizedPoseidonSpec::new::<8, 57, 0>());
    hasher.initialize_consts(ctx, gate);

    println!("Inserting leaf");

    insert_leaf::<Fr, 3, 2>(
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
    )
}
// #[test]
// fn test_voter_add() {
//     let mut rng = thread_rng();

//     let n = rng.gen_biguint(ENC_BIT_LEN as u64);
//     let g = rng.gen_biguint(ENC_BIT_LEN as u64);
//     let pk_enc = EncryptionPublicKey { n, g };
//     let inc_enc_vote = (0..5).map(|_| { rng.gen_biguint(ENC_BIT_LEN as u64) }).collect::<Vec<_>>();
//     let prev_enc_vote = (0..5).map(|_| { rng.gen_biguint(ENC_BIT_LEN as u64) }).collect::<Vec<_>>();

//     let input = StateTranInput {
//         pk_enc,
//         proposal_id: Fr::from(1u64),
//         inc_enc_vote,
//         prev_enc_vote,
//         Default::default(),
//     };

//     base_test()
//         .k(16)
//         .lookup_bits(15)
//         .expect_satisfied(true)
//         .run(|ctx, range| {
//             let mut public_inputs = Vec::<AssignedValue<Fr>>::new();

//             state_trans_circuit(ctx, range, input, &mut public_inputs)
//         });
// }
#[test]
fn test_state_trans_circuit() {
    const T: usize = 3;
    const RATE: usize = 2;
    const R_F: usize = 8;
    const R_P: usize = 57;

    let tree_size = pow(2, 3);
    let mut leaves = Vec::<Fr>::new();
    let mut native_hasher = Poseidon::<Fr, T, RATE>::new(R_F, R_P);
    let mut rng = thread_rng();

    // Filling leaves with dfault values.
    for i in 0..tree_size {
        if i == 0 {
            native_hasher.update(&[Fr::from(0u64), Fr::from(0u64), Fr::from(0u64)]);
            leaves.push(native_hasher.squeeze_and_reset());
        } else {
            leaves.push(Fr::from(0u64));
        }
    }
    let mut tree =
        IndexedMerkleTree::<Fr, T, RATE>::new(&mut native_hasher, leaves.clone()).unwrap();

    let new_val = Fr::from(69u64);

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

    // compute interim state change
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

    let IDX_input = IndexTreeInput {
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
        proposal_id: Fr::from(1u64),
        inc_enc_vote,
        prev_enc_vote,
        indx_tree: IDX_input,
    };
    base_test()
        .k(16)
        .lookup_bits(15)
        .expect_satisfied(true)
        .run(|ctx, range| {
            let mut public_inputs = Vec::<AssignedValue<Fr>>::new();

            state_trans_circuit(ctx, range, input, &mut public_inputs)
        });
}
