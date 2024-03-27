use halo2_base::gates::circuit::builder::BaseCircuitBuilder;
use halo2_base::gates::circuit::{ BaseCircuitParams, BaseConfig };
use halo2_base::gates::GateInstructions;
use halo2_base::halo2_proofs::circuit::{ Layouter, SimpleFloorPlanner };
use halo2_base::halo2_proofs::plonk::{ Circuit, ConstraintSystem, Error };
use halo2_base::poseidon::hasher::{ spec::OptimizedPoseidonSpec, PoseidonHasher };
use halo2_base::{
    gates::{ RangeChip, RangeInstructions },
    halo2_proofs::circuit::Value,
    utils::BigPrimeField,
    AssignedValue,
    Context,
};
use halo2_ecc::ecc::EccChip;
use halo2_ecc::fields::fp::FpChip;
use indexed_merkle_tree_halo2::indexed_merkle_tree::{ insert_leaf, IndexedMerkleTreeLeaf };
use indexed_merkle_tree_halo2::utils::IndexedMerkleTreeLeaf as IMTLeaf;
use num_bigint::BigUint;

use biguint_halo2::big_uint::chip::BigUintChip;
use halo2_base::halo2_proofs::halo2curves::secp256k1::{ Fp, Secp256k1Affine };
use paillier_chip::paillier::{ EncryptionPublicKeyAssigned, PaillierChip };
use serde::{ Deserialize, Serialize };
use voter::{ compress_nullifier, CircuitExt, EncryptionPublicKey };

const ENC_BIT_LEN: usize = 176;
const LIMB_BIT_LEN: usize = 88;

//TODO: Constrain the nullifier hash using x and y limbs

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
        is_new_leaf_largest: F
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
        nullifier: Secp256k1Affine
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
    input: StateTransitionInput<F>,
    public_inputs: &mut Vec<AssignedValue<F>>
) {
    let gate = range.gate();
    let mut hasher = PoseidonHasher::<F, 3, 2>::new(OptimizedPoseidonSpec::new::<8, 57, 0>());
    hasher.initialize_consts(ctx, gate);

    let biguint_chip = BigUintChip::construct(range, LIMB_BIT_LEN);
    let paillier_chip = PaillierChip::construct(&biguint_chip, ENC_BIT_LEN);

    let fp_chip = FpChip::<F, Fp>::new(range, LIMB_BIT_LEN, 3);
    let ecc_chip = EccChip::<F, FpChip<F, Fp>>::new(&fp_chip);

    let nullifier = ecc_chip.load_private_unchecked(ctx, (input.nullifier.x, input.nullifier.y));
    let compressed_nullifier = compress_nullifier(ctx, range, &nullifier);
    let nullifier_hash = hasher.hash_fix_len_array(ctx, gate, &compressed_nullifier);

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

    let incoming_vote = input.incoming_vote
        .iter()
        .map(|x| {
            biguint_chip.assign_integer(ctx, Value::known(x.clone()), ENC_BIT_LEN * 2).unwrap()
        })
        .collect::<Vec<_>>();
    let prev_vote = input.prev_vote
        .iter()
        .map(|x| {
            biguint_chip.assign_integer(ctx, Value::known(x.clone()), ENC_BIT_LEN * 2).unwrap()
        })
        .collect::<Vec<_>>();

    // Step 1: Aggregate the votes
    let aggr_vote = incoming_vote
        .iter()
        .zip(prev_vote.iter())
        .map(|(x, y)| paillier_chip.add(ctx, &pk_enc, x, y).unwrap())
        .collect::<Vec<_>>();

    // Step 2: Update the nullifier tree
    let val = ctx.load_witness(input.nullifier_tree.low_leaf.val);
    let next_val = ctx.load_witness(input.nullifier_tree.low_leaf.next_val);
    let next_idx = ctx.load_witness(input.nullifier_tree.low_leaf.next_idx);

    let old_root = ctx.load_witness(input.nullifier_tree.old_root);
    let low_leaf = IndexedMerkleTreeLeaf::new(val, next_val, next_idx);

    let new_root = ctx.load_witness(input.nullifier_tree.new_root);

    let val = ctx.load_witness(input.nullifier_tree.new_leaf.val);
    assert_eq!(val.value(), nullifier_hash.value());
    ctx.constrain_equal(&val, &nullifier_hash);
    let next_val = ctx.load_witness(input.nullifier_tree.new_leaf.next_val);
    let next_idx = ctx.load_witness(input.nullifier_tree.new_leaf.next_idx);

    let new_leaf = IndexedMerkleTreeLeaf::new(val, next_val, next_idx);

    let new_leaf_index = ctx.load_witness(input.nullifier_tree.new_leaf_index);
    let is_new_leaf_largest = ctx.load_witness(input.nullifier_tree.is_new_leaf_largest);

    let low_leaf_proof = input.nullifier_tree.low_leaf_proof
        .iter()
        .map(|x| ctx.load_witness(*x))
        .collect::<Vec<_>>();
    let low_leaf_proof_helper = input.nullifier_tree.low_leaf_proof_helper
        .iter()
        .map(|x| ctx.load_witness(*x))
        .collect::<Vec<_>>();
    let new_leaf_proof = input.nullifier_tree.new_leaf_proof
        .iter()
        .map(|x| ctx.load_witness(*x))
        .collect::<Vec<_>>();
    let new_leaf_proof_helper = input.nullifier_tree.new_leaf_proof_helper
        .iter()
        .map(|x| ctx.load_witness(*x))
        .collect::<Vec<_>>();

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
        &is_new_leaf_largest
    );

    // PK_ENC N
    public_inputs.extend(pk_enc.n.limbs());

    // PK_ENC G
    public_inputs.extend(pk_enc.g.limbs());

    // PREV_VOTE
    for enc_vote in prev_vote {
        public_inputs.extend(enc_vote.limbs());
    }

    // INCOMING_VOTE
    for enc_vote in incoming_vote {
        public_inputs.extend(enc_vote.limbs());
    }

    // AGGR_VOTE
    for enc_vote in aggr_vote {
        public_inputs.extend(enc_vote.limbs());
    }

    // NULLIFIER
    public_inputs.extend(compressed_nullifier);

    // NULLIFIER_OLD_ROOT
    public_inputs.extend([old_root]);

    // NULLIFIER_NEW_ROOT
    public_inputs.extend([new_root]);
}

pub struct StateTransitionCircuit<F: BigPrimeField> {
    input: StateTransitionInput<F>,
    pub inner: BaseCircuitBuilder<F>,
}

impl<F: BigPrimeField> StateTransitionCircuit<F> {
    pub fn new(config: BaseCircuitParams, input: StateTransitionInput<F>) -> Self {
        let mut inner = BaseCircuitBuilder::default();
        inner.set_params(config);

        let range = inner.range_chip();
        let ctx = inner.main(0);

        let mut public_inputs = Vec::<AssignedValue<F>>::new();
        state_transition_circuit(ctx, &range, input.clone(), &mut public_inputs);
        inner.assigned_instances[0].extend(public_inputs);
        inner.calculate_params(Some(10));
        Self { input, inner }
    }
}

impl<F: BigPrimeField> Circuit<F> for StateTransitionCircuit<F> {
    type Config = BaseConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = BaseCircuitParams;

    fn params(&self) -> Self::Params {
        self.inner.params()
    }

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure_with_params(meta: &mut ConstraintSystem<F>, params: Self::Params) -> Self::Config {
        BaseCircuitBuilder::configure_with_params(meta, params)
    }

    fn configure(_: &mut ConstraintSystem<F>) -> Self::Config {
        unreachable!()
    }

    fn synthesize(&self, config: Self::Config, layouter: impl Layouter<F>) -> Result<(), Error> {
        self.inner.synthesize(config, layouter)
    }
}

impl<F: BigPrimeField> CircuitExt<F> for StateTransitionCircuit<F> {
    fn num_instance() -> Vec<usize> {
        vec![70]
    }

    fn instances(&self) -> Vec<Vec<F>> {
        vec![
            self.inner.assigned_instances[0]
                .iter()
                .map(|instance| *instance.value())
                .collect()
        ]
    }
}

#[cfg(test)]
mod test {
    use halo2_base::{
        gates::circuit::BaseCircuitParams,
        halo2_proofs::{ dev::MockProver, halo2curves::bn256::Fr },
        utils::testing::base_test,
        AssignedValue,
    };
    use voter::CircuitExt;

    use crate::utils::generate_wrapper_circuit_input;

    use super::{ state_transition_circuit, StateTransitionCircuit };

    #[test]
    fn test_state_transition_circuit() {
        let (_, multiple_input) = generate_wrapper_circuit_input(4);

        let config = BaseCircuitParams {
            k: 15,
            num_advice_per_phase: vec![3],
            num_lookup_advice_per_phase: vec![1, 0, 0],
            num_fixed: 1,
            lookup_bits: Some(14),
            num_instance_columns: 1,
        };

        for (round, input) in multiple_input.iter().enumerate() {
            println!("------round[{}]--------", round);

            let circuit = StateTransitionCircuit::new(config.clone(), input.clone());
            let prover = MockProver::run(15, &circuit, circuit.instances()).unwrap();
            prover.verify().unwrap();
        }

        base_test()
            .k(19)
            .lookup_bits(18)
            .expect_satisfied(true)
            .run(|ctx, range| {
                let mut public_inputs = Vec::<AssignedValue<Fr>>::new();
                state_transition_circuit(ctx, range, multiple_input[0].clone(), &mut public_inputs)
            });
    }
}
