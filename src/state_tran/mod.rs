use halo2_base::{
    gates::RangeChip, halo2_proofs::{ circuit::Value, halo2curves::bn256::Fr }, utils::{ testing::base_test, BigPrimeField, ScalarField }, AssignedValue, Context
};
//use indexed_merkle_tree_halo2::indexed_merkle_tree::IndexedMerkleTreeLeaf;
use num_bigint::{ BigUint, RandBigInt };
use rand::thread_rng;
use halo2_base::halo2_proofs::halo2curves::secp256k1::{ Fq, Secp256k1Affine };
use paillier_chip::paillier::{ EncryptionPublicKeyAssigned, PaillierChip };
use biguint_halo2::big_uint::chip::BigUintChip;
use crate::voter_circuit::EncryptionPublicKey;

const ENC_BIT_LEN: usize = 264;
const LIMB_BIT_LEN: usize = 88;

//TODO: Deserialize,Clone and Default for IndexedMerkleTreeLeaf

#[derive(Debug, Clone)]
pub struct IndexTreeInput<F: BigPrimeField> {
    old_root: F,
    // low_leaf: IndexedMerkleTreeLeaf<F>,
    low_leaf_val: F,
    low_leaf_next_val: F,
    low_leaf_next_idx: F,

    low_leaf_proof: Vec<F>,
    low_leaf_proof_helper: Vec<F>,
    new_root: F,
    //IndexedMerkleTreeLeaf<F>,
    new_leaf_val: F,
    new_leaf_next_val: F,
    new_leaf_next_idx: F,
    // new_leaf: IndexedMerkleTreeLeaf<F>,
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
    //indx_tree: IndexTreeInput<F>
}
pub fn state_trans_circuit<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    input: StateTranInput<F>,
    public_inputs: &mut Vec<AssignedValue<F>>
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

    let inc_enc_vote = input.inc_enc_vote
        .iter()
        .map(|x| {
            biguint_chip.assign_integer(ctx, Value::known(x.clone()), ENC_BIT_LEN).unwrap()
        })
        .collect::<Vec<_>>();
    let prev_enc_vote = input.prev_enc_vote
        .iter()
        .map(|x| {
            biguint_chip.assign_integer(ctx, Value::known(x.clone()), ENC_BIT_LEN).unwrap()
        })
        .collect::<Vec<_>>();

    let aggr_vote = inc_enc_vote
        .iter()
        .zip(prev_enc_vote)
        .map(|(x, y)| { paillier_chip.add(ctx, &pk_enc, x, &y).unwrap() })
        .collect::<Vec<_>>();

    //nullifier
    // let val=ctx.load_witness(input.indx_tree.low_leaf_val);
    // let next_val=ctx.load_witness(input.indx_tree.low_leaf_next_val);
    // let next_idx=ctx.load_witness(input.indx_tree.low_leaf_next_idx);

    // let low_leaf=IndexedMerkleTreeLeaf::new(val,next_val,next_idx);

    //                 let old_root = ctx.load_witness(input.indx_tree.old_root);
    //                 let val=
    //                 let low_leaf = IndexedMerkleTreeLeaf {
    //                     val: ctx.load_witness(input.indx_tree.low_leaf_val),
    //                     next_val: ctx.load_witness(input.indx_tree.low_leaf.next_val),
    //                     next_idx: ctx.load_witness(input.indx_tree.low_leaf.next_idx),
    //                 };
    //                 let new_root = ctx.load_witness(input.indx_tree.new_root);
    //                 let new_leaf = IndexedMerkleTreeLeaf {
    //                     val: ctx.load_witness(new_leaf.val),
    //                     next_val: ctx.load_witness(new_leaf.next_val),
    //                     next_idx: ctx.load_witness(new_leaf.next_idx),
    //                 };
    //                 let new_leaf_index = ctx.load_witness(input.indx_tree.new_leaf_index);
    //                 let is_new_leaf_largest = ctx.load_witness(input.indx_tree.is_new_leaf_largest);

    //                 let low_leaf_proof = input.indx_tree.low_leaf_proof
    //                     .iter()
    //                     .map(|x| ctx.load_witness(*x))
    //                     .collect::<Vec<_>>();
    //                 let low_leaf_proof_helper = input.indx_tree.low_leaf_proof_helper
    //                     .iter()
    //                     .map(|x| ctx.load_witness(*x))
    //                     .collect::<Vec<_>>();
    //                 let new_leaf_proof = input.indx_tree.new_leaf_proof
    //                     .iter()
    //                     .map(|x| ctx.load_witness(*x))
    //                     .collect::<Vec<_>>();
    //                 let new_leaf_proof_helper = input.indx_tree.new_leaf_proof_helper
    //                     .iter()
    //                     .map(|x| ctx.load_witness(*x))
    //                     .collect::<Vec<_>>();
}
#[test]
fn test_state_trans_circuit() {
    let mut rng = thread_rng();

    let n = rng.gen_biguint(ENC_BIT_LEN as u64);
    let g = rng.gen_biguint(ENC_BIT_LEN as u64);
    let pk_enc = EncryptionPublicKey { n, g };
    let inc_enc_vote = (0..5).map(|_| { rng.gen_biguint(ENC_BIT_LEN as u64) }).collect::<Vec<_>>();
    let prev_enc_vote = (0..5).map(|_| { rng.gen_biguint(ENC_BIT_LEN as u64) }).collect::<Vec<_>>();

    let input = StateTranInput {
        pk_enc,
        proposal_id: Fr::from(1u64),
        inc_enc_vote,
        prev_enc_vote,
    };

    base_test()
        .k(16)
        .lookup_bits(15)
        .expect_satisfied(true)
        .run(|ctx, range| {
            let mut public_inputs = Vec::<AssignedValue<Fr>>::new();

            state_trans_circuit(ctx, range, input,&mut public_inputs)
        });
}
