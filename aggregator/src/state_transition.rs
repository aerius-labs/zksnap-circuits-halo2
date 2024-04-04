use biguint_halo2::big_uint::chip::BigUintChip;
use biguint_halo2::big_uint::{AssignedBigUint, Fresh};
use halo2_base::halo2_proofs::halo2curves::secp256k1::Secp256k1Affine;
use halo2_base::poseidon::hasher::{spec::OptimizedPoseidonSpec, PoseidonHasher};
use halo2_base::utils::fe_to_biguint;
use halo2_base::{
    gates::{RangeChip, RangeInstructions},
    halo2_proofs::circuit::Value,
    utils::BigPrimeField,
    AssignedValue, Context,
};
use halo2_ecc::bigint::OverflowInteger;
use indexed_merkle_tree_halo2::indexed_merkle_tree::{insert_leaf, IndexedMerkleTreeLeaf};
use indexed_merkle_tree_halo2::utils::IndexedMerkleTreeLeaf as IMTLeaf;
use num_bigint::BigUint;
use paillier_chip::paillier::{EncryptionPublicKeyAssigned, PaillierChip};
use serde::{Deserialize, Serialize};
use voter::EncryptionPublicKey;

const ENC_BIT_LEN: usize = 176;
const LIMB_BIT_LEN: usize = 88;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexedMerkleTreeInput<F: BigPrimeField> {
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

impl<F: BigPrimeField> IndexedMerkleTreeInput<F> {
    pub fn new(
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
    ) -> Self {
        Self {
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
        }
    }
    pub fn get_old_root(&self) -> F {
        self.old_root
    }
    pub fn get_new_root(&self) -> F {
        self.new_root
    }
}
fn limbs_to_biguint<F: BigPrimeField>(x: Vec<F>) -> BigUint {
    x.iter()
        .enumerate()
        .map(|(i, limb)| fe_to_biguint(limb) * BigUint::from(2u64).pow(88 * (i as u32)))
        .sum()
}
#[derive(Debug, Clone)]
pub struct StateTransitionInput<F: BigPrimeField> {
    pub pk_enc: EncryptionPublicKey,
    pub incoming_vote: Vec<BigUint>,
    pub prev_vote: Vec<BigUint>,
    pub nullifier_tree: IndexedMerkleTreeInput<F>,
    pub nullifier: Secp256k1Affine,
}
impl<F: BigPrimeField> StateTransitionInput<F> {
    pub fn new(
        pk_enc: EncryptionPublicKey,
        incoming_vote: Vec<BigUint>,
        prev_vote: Vec<BigUint>,
        nullifier_tree: IndexedMerkleTreeInput<F>,
        nullifier: Secp256k1Affine,
    ) -> Self {
        Self {
            pk_enc,
            incoming_vote,
            prev_vote,
            nullifier_tree,
            nullifier,
        }
    }
}

pub fn state_transition_circuit<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    nullifier_tree: IndexedMerkleTreeInput<F>,
    input_vec: Vec<AssignedValue<F>>,
    public_inputs: &mut Vec<AssignedValue<F>>,
) {
    let gate = range.gate();
    let mut hasher = PoseidonHasher::<F, 3, 2>::new(OptimizedPoseidonSpec::new::<8, 57, 0>());
    hasher.initialize_consts(ctx, gate);

    let biguint_chip = BigUintChip::construct(range, LIMB_BIT_LEN);
    let paillier_chip = PaillierChip::construct(&biguint_chip, ENC_BIT_LEN);

    let nullifier_hash = hasher.hash_fix_len_array(ctx, gate, &input_vec[0..4]);

    let n_fr = input_vec[4..6]
        .iter()
        .map(|vote| *vote.value())
        .collect::<Vec<F>>();
    let n_assigned = AssignedBigUint::<F, Fresh>::new(
        OverflowInteger::new(input_vec[4..6].to_vec(), 88),
        Value::known(limbs_to_biguint(n_fr)),
    );
    let g_fr = input_vec[6..8]
        .iter()
        .map(|vote| *vote.value())
        .collect::<Vec<F>>();
    let g_assigned = AssignedBigUint::<F, Fresh>::new(
        OverflowInteger::new(input_vec[6..8].to_vec(), 88),
        Value::known(limbs_to_biguint(g_fr)),
    );

    let pk_enc = EncryptionPublicKeyAssigned {
        n: n_assigned,
        g: g_assigned,
    };
    let incoming_vote_fr: Vec<F> = input_vec[8..28].iter().map(|x| *x.value()).collect();
    let incoming_vote_biguint = incoming_vote_fr
        .chunks(4)
        .into_iter()
        .map(|chunk| limbs_to_biguint(chunk.to_vec()))
        .collect::<Vec<BigUint>>();
    let incoming_vote_overflow_int = input_vec[8..28]
        .chunks(4)
        .into_iter()
        .map(|chunk| OverflowInteger::new(chunk.to_vec(), 88))
        .collect::<Vec<OverflowInteger<F>>>();
    let incoming_vote = incoming_vote_overflow_int
        .iter()
        .enumerate()
        .map(|(i, over_flow)| {
            AssignedBigUint::new(
                over_flow.clone(),
                Value::known(incoming_vote_biguint[i].clone()),
            )
        })
        .collect::<Vec<AssignedBigUint<F, Fresh>>>();

    let prev_vote_fr: Vec<F> = input_vec[28..48].iter().map(|x| *x.value()).collect();
    let prev_vote_biguint = prev_vote_fr
        .chunks(4)
        .into_iter()
        .map(|chunk| limbs_to_biguint(chunk.to_vec()))
        .collect::<Vec<BigUint>>();
    let prev_vote_overflow_int = input_vec[28..48]
        .chunks(4)
        .into_iter()
        .map(|chunk| OverflowInteger::new(chunk.to_vec(), 88))
        .collect::<Vec<OverflowInteger<F>>>();
    let prev_vote = prev_vote_overflow_int
        .iter()
        .enumerate()
        .map(|(i, over_flow)| {
            AssignedBigUint::new(
                over_flow.clone(),
                Value::known(prev_vote_biguint[i].clone()),
            )
        })
        .collect::<Vec<AssignedBigUint<F, Fresh>>>();

    // Step 1: Aggregate the votes
    let aggr_vote = incoming_vote
        .iter()
        .zip(prev_vote.iter())
        .map(|(x, y)| paillier_chip.add(ctx, &pk_enc, x, y).unwrap())
        .collect::<Vec<_>>();

    // Step 2: Update the nullifier tree
    let val = ctx.load_witness(nullifier_tree.low_leaf.val);
    let next_val = ctx.load_witness(nullifier_tree.low_leaf.next_val);
    let next_idx = ctx.load_witness(nullifier_tree.low_leaf.next_idx);

    let old_root = ctx.load_witness(nullifier_tree.old_root);
    let low_leaf = IndexedMerkleTreeLeaf::new(val, next_val, next_idx);

    let new_root = ctx.load_witness(nullifier_tree.new_root);

    let val = ctx.load_witness(nullifier_tree.new_leaf.val);
    //assert_eq!(val.value(), nullifier_hash.value());
    ctx.constrain_equal(&val, &nullifier_hash);
    let next_val = ctx.load_witness(nullifier_tree.new_leaf.next_val);
    let next_idx = ctx.load_witness(nullifier_tree.new_leaf.next_idx);

    let new_leaf = IndexedMerkleTreeLeaf::new(val, next_val, next_idx);

    let new_leaf_index = ctx.load_witness(nullifier_tree.new_leaf_index);
    let is_new_leaf_largest = ctx.load_witness(nullifier_tree.is_new_leaf_largest);

    let low_leaf_proof = nullifier_tree
        .low_leaf_proof
        .iter()
        .map(|x| ctx.load_witness(*x))
        .collect::<Vec<_>>();
    let low_leaf_proof_helper = nullifier_tree
        .low_leaf_proof_helper
        .iter()
        .map(|x| ctx.load_witness(*x))
        .collect::<Vec<_>>();
    let new_leaf_proof = nullifier_tree
        .new_leaf_proof
        .iter()
        .map(|x| ctx.load_witness(*x))
        .collect::<Vec<_>>();
    let new_leaf_proof_helper = nullifier_tree
        .new_leaf_proof_helper
        .iter()
        .map(|x| ctx.load_witness(*x))
        .collect::<Vec<_>>();

    // insert_leaf::<F, 3, 2>(
    //     ctx,
    //     range,
    //     &hasher,
    //     &old_root,
    //     &low_leaf,
    //     &low_leaf_proof,
    //     &low_leaf_proof_helper,
    //     &new_root,
    //     &new_leaf,
    //     &new_leaf_index,
    //     &new_leaf_proof,
    //     &new_leaf_proof_helper,
    //     &is_new_leaf_largest,
    // );

    for enc_vote in aggr_vote {
        public_inputs.extend(enc_vote.limbs());
    }

    // NULLIFIER_OLD_ROOT
    public_inputs.extend([old_root]);

    // NULLIFIER_NEW_ROOT
    public_inputs.extend([new_root]);
}
