pub mod utils;

use halo2_base::{
    gates::{
        circuit::{
            builder::BaseCircuitBuilder, BaseCircuitParams, BaseConfig, CircuitBuilderStage,
        },
        GateInstructions, RangeChip, RangeInstructions,
    },
    halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        halo2curves::secp256k1::{Fq, Secp256k1Affine},
        plonk::{Circuit, ConstraintSystem, Error},
    },
    poseidon::hasher::{spec::OptimizedPoseidonSpec, PoseidonHasher},
    utils::{fe_to_biguint, BigPrimeField},
    AssignedValue, Context, QuantumCell,
};
use halo2_ecc::{
    ecc::EccChip,
    fields::FieldChip,
    secp256k1::{sha256::Sha256Chip, FpChip, FqChip},
};
use itertools::Itertools;
use num_bigint::BigUint;
use plume_halo2::plume::{compress_point, verify_plume, PlumeInput};

use biguint_halo2::big_uint::chip::BigUintChip;
use paillier_chip::paillier::{EncryptionPublicKeyAssigned, PaillierChip};
use serde::Deserialize;

use crate::state_transition_circuit::compress_nullifier;
use crate::{merkletree::verify_membership_proof, wrapper_circuit::common::CircuitExt};

const ENC_BIT_LEN: usize = 176;
const LIMB_BIT_LEN: usize = 88;
const NUM_LIMBS: usize = 3;

const T: usize = 3;
const RATE: usize = 2;
const R_F: usize = 8;
const R_P: usize = 57;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct EncryptionPublicKey {
    pub n: BigUint,
    pub g: BigUint,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct VoterCircuitInput<F: BigPrimeField> {
    // * Public inputs
    membership_root: F,
    pk_enc: EncryptionPublicKey,
    nullifier: Secp256k1Affine,
    // ? This will be 2 bytes for performance, can change this
    // ? to accomodate more bytes later based on requirement.
    proposal_id: F,
    vote_enc: Vec<BigUint>,

    // * Private inputs

    // * s = r + sk * c
    s_nullifier: Fq,

    vote: Vec<F>,
    r_enc: Vec<BigUint>,
    pk_voter: Secp256k1Affine,
    c_nullifier: Fq,
    membership_proof: Vec<F>,
    membership_proof_helper: Vec<F>,
}

impl<F: BigPrimeField> VoterCircuitInput<F> {
    pub fn new(
        membership_root: F,
        pk_enc: EncryptionPublicKey,
        nullifier: Secp256k1Affine,
        proposal_id: F,
        vote_enc: Vec<BigUint>,
        s_nullifier: Fq,
        vote: Vec<F>,
        r_enc: Vec<BigUint>,
        pk_voter: Secp256k1Affine,
        c_nullifier: Fq,
        membership_proof: Vec<F>,
        membership_proof_helper: Vec<F>,
    ) -> Self {
        Self {
            membership_root,
            pk_enc,
            nullifier,
            proposal_id,
            vote_enc,
            s_nullifier,
            vote,
            r_enc,
            pk_voter,
            c_nullifier,
            membership_proof,
            membership_proof_helper,
        }
    }
}

pub fn voter_circuit<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    input: VoterCircuitInput<F>,
    public_inputs: &mut Vec<AssignedValue<F>>,
) {
    // Initializing required chips for the circuit.
    let gate = range.gate();
    let mut hasher = PoseidonHasher::<F, T, RATE>::new(OptimizedPoseidonSpec::new::<R_F, R_P, 0>());
    hasher.initialize_consts(ctx, gate);
    let biguint_chip = BigUintChip::construct(range, LIMB_BIT_LEN);
    let paillier_chip = PaillierChip::construct(&biguint_chip, ENC_BIT_LEN);
    let fp_chip = FpChip::<F>::new(range, LIMB_BIT_LEN, NUM_LIMBS);
    let fq_chip = FqChip::new(range, LIMB_BIT_LEN, NUM_LIMBS);
    let ecc_chip = EccChip::<F, FpChip<F>>::new(&fp_chip);
    let sha256_chip = Sha256Chip::new(range);

    // Assigning inputs to the circuit.
    let pk_voter = ecc_chip.load_private_unchecked(ctx, (input.pk_voter.x, input.pk_voter.y));
    let nullifier = ecc_chip.load_private_unchecked(ctx, (input.nullifier.x, input.nullifier.y));
    let s_nullifier = fq_chip.load_private(ctx, input.s_nullifier);
    let c_nullifier = fq_chip.load_private(ctx, input.c_nullifier);
    let membership_root = ctx.load_witness(input.membership_root);
    let leaf_preimage = [pk_voter.x().limbs(), pk_voter.y().limbs()].concat();
    let leaf = hasher.hash_fix_len_array(ctx, gate, &leaf_preimage[..]);
    let membership_proof = input
        .membership_proof
        .iter()
        .map(|&proof| ctx.load_witness(proof))
        .collect::<Vec<_>>();
    let membership_proof_helper = input
        .membership_proof_helper
        .iter()
        .map(|&helper| ctx.load_witness(helper))
        .collect::<Vec<_>>();
    let proposal_id = ctx.load_witness(input.proposal_id);
    let n_assigned = biguint_chip
        .assign_integer(ctx, Value::known(input.pk_enc.n.clone()), ENC_BIT_LEN)
        .unwrap();
    let g_assigned = biguint_chip
        .assign_integer(ctx, Value::known(input.pk_enc.g.clone()), ENC_BIT_LEN)
        .unwrap();
    let vote_assigned_fe = input
        .vote
        .iter()
        .map(|x| ctx.load_witness(*x))
        .collect::<Vec<_>>();
    let vote_assigned_big = input
        .vote
        .iter()
        .map(fe_to_biguint)
        .map(|x| {
            biguint_chip
                .assign_integer(ctx, Value::known(x), ENC_BIT_LEN * 2)
                .unwrap()
        })
        .collect_vec();
    let vote_enc_assigned_big = input
        .vote_enc
        .iter()
        .map(|x| {
            biguint_chip
                .assign_integer(ctx, Value::known(x.clone()), ENC_BIT_LEN * 2)
                .unwrap()
        })
        .collect_vec();
    let r_assigned = input
        .r_enc
        .iter()
        .map(|x| {
            biguint_chip
                .assign_integer(ctx, Value::known(x.clone()), ENC_BIT_LEN)
                .unwrap()
        })
        .collect::<Vec<_>>();

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
        &membership_proof_helper,
    );

    // Check to verify correct votes have been passed.
    let _ = vote_assigned_fe.iter().map(|x| gate.assert_bit(ctx, *x));
    let zero = ctx.load_zero();
    let one = ctx.load_constant(F::ONE);
    let vote_sum_assigned = vote_assigned_fe
        .iter()
        .fold(zero, |zero, x| gate.add(ctx, zero, *x));
    ctx.constrain_equal(&vote_sum_assigned, &one);

    //PK_ENC_n
    public_inputs.extend(pk_enc.n.limbs().to_vec());

    //PK_ENC_g
    public_inputs.extend(pk_enc.g.limbs().to_vec());

    // 2. Verify correct vote encryption
    for i in 0..input.vote.len() {
        let _vote_enc = paillier_chip
            .encrypt(ctx, &pk_enc, &vote_assigned_big[i], &r_assigned[i])
            .unwrap();

        biguint_chip
            .assert_equal_fresh(ctx, &vote_enc_assigned_big[i], &_vote_enc)
            .unwrap();

        //ENC_VOTE
        public_inputs.append(&mut vote_enc_assigned_big[i].limbs().to_vec());
    }

    // 3. Verify nullifier
    let message = proposal_id.value().to_bytes_le()[..2]
        .iter()
        .map(|v| ctx.load_witness(F::from(*v as u64)))
        .collect::<Vec<_>>();
    {
        let mut _proposal_id = ctx.load_zero();
        for i in 0..2 {
            _proposal_id = gate.mul_add(
                ctx,
                message[i],
                QuantumCell::Constant(F::from(1u64 << (8 * i))),
                _proposal_id,
            );
        }
        ctx.constrain_equal(&_proposal_id, &proposal_id);
    }

    let compressed_nullifier = compress_nullifier(ctx, range, &nullifier);

    let plume_input = PlumeInput::new(
        nullifier,
        s_nullifier.clone(),
        c_nullifier,
        pk_voter,
        message,
    );
    verify_plume(ctx, &ecc_chip, &sha256_chip, 4, 4, plume_input);

    //NULLIFIER
    public_inputs.extend(compressed_nullifier.to_vec());

    //MERKLE_ROOT
    public_inputs.extend([membership_root].to_vec());

    //PROPOSAL_ID
    public_inputs.extend([proposal_id].to_vec());
}

#[derive(Clone, Default)]
pub struct VoterCircuit<F: BigPrimeField> {
    input: VoterCircuitInput<F>,
    pub inner: BaseCircuitBuilder<F>,
}

impl<F: BigPrimeField> VoterCircuit<F> {
    pub fn new(config: BaseCircuitParams, input: VoterCircuitInput<F>) -> Self {
        let mut inner = BaseCircuitBuilder::default();
        inner.set_params(config);

        let mut public_inputs = Vec::<AssignedValue<F>>::new();
        let range = inner.range_chip();
        let ctx = inner.main(0);
        voter_circuit(ctx, &range, input.clone(), &mut public_inputs);
        inner.assigned_instances[0].extend(public_inputs);
        inner.calculate_params(Some(10));
        println!("voter params: {:?}", inner.params());
        Self { input, inner }
    }
}

impl<F: BigPrimeField> Circuit<F> for VoterCircuit<F> {
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

impl<F: BigPrimeField> CircuitExt<F> for VoterCircuit<F> {
    fn num_instance() -> Vec<usize> {
        vec![30]
    }

    fn instances(&self) -> Vec<Vec<F>> {
        vec![self.inner.assigned_instances[0]
            .iter()
            .map(|instance| *instance.value())
            .collect()]
    }
}

#[cfg(test)]
mod test {
    use halo2_base::{
        gates::circuit::{BaseCircuitParams, CircuitBuilderStage},
        halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr},
        utils::testing::base_test,
        AssignedValue,
    };

    use crate::wrapper_circuit::common::CircuitExt;

    use super::{utils::generate_random_voter_circuit_inputs, voter_circuit, VoterCircuit};

    #[test]
    fn test_voter_circuit() {
        let input = generate_random_voter_circuit_inputs();

        // let config = BaseCircuitParams {
        //     k: 15 as usize,
        //     num_advice_per_phase: vec![8],
        //     num_lookup_advice_per_phase: vec![1],
        //     num_fixed: 1,
        //     lookup_bits: Some(14),
        //     num_instance_columns: 1,
        // };

        // let circuit = VoterCircuit::new(config, input.clone());
        // let prover = MockProver::run(15, &circuit, circuit.instances()).unwrap();
        // prover.verify().unwrap();

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
