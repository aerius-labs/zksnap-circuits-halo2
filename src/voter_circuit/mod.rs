pub mod utils;

use halo2_base::{
    gates::{
        circuit::{
            builder::BaseCircuitBuilder,
            BaseCircuitParams,
            BaseConfig,
            CircuitBuilderStage,
        },
        GateInstructions,
        RangeChip,
        RangeInstructions,
    },
    halo2_proofs::{
        circuit::{ Layouter, SimpleFloorPlanner, Value },
        halo2curves::secp256k1::{ Fq, Secp256k1Affine },
        plonk::{ Circuit, ConstraintSystem, Error },
    },
    poseidon::hasher::{ spec::OptimizedPoseidonSpec, PoseidonHasher },
    utils::BigPrimeField,
    AssignedValue,
    Context,
    QuantumCell,
};
use halo2_ecc::{
    ecc::EccChip,
    fields::FieldChip,
    secp256k1::{ sha256::Sha256Chip, FpChip, FqChip },
};
use num_bigint::BigUint;
use plume_halo2::plume::{ compress_point, verify_plume, PlumeInput };

use biguint_halo2::big_uint::chip::BigUintChip;
use paillier_chip::paillier::{ EncryptionPublicKeyAssigned, PaillierChip };
use serde::Deserialize;

use crate::{ merkletree::verify_membership_proof, wrapper_circuit::common::CircuitExt };
use crate::state_transition_circuit::compress_nullifier;

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

    // * Private inputs

    // * s = r + sk * c
    s_nullifier: Fq,

    vote: Vec<BigUint>,
    r_enc: Vec<BigUint>,
    pk_voter: Secp256k1Affine,
    c_nullifier: Fq,
    membership_proof: Vec<F>,
    membership_proof_helper: Vec<F>,
}

pub fn voter_circuit<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    input: VoterCircuitInput<F>,
    public_inputs: &mut Vec<AssignedValue<F>>
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
    let membership_proof = input.membership_proof
        .iter()
        .map(|&proof| ctx.load_witness(proof))
        .collect::<Vec<_>>();
    let membership_proof_helper = input.membership_proof_helper
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
    let vote_assigned = input.vote
        .iter()
        .map(|x| {
            biguint_chip.assign_integer(ctx, Value::known(x.clone()), ENC_BIT_LEN).unwrap()
        })
        .collect::<Vec<_>>();
    let r_assigned = input.r_enc
        .iter()
        .map(|x| {
            biguint_chip.assign_integer(ctx, Value::known(x.clone()), ENC_BIT_LEN).unwrap()
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
        &membership_proof_helper
    );

    // TODO: add a check to verify correct votes have been passed.

    //PK_ENC_n
    public_inputs.append(&mut pk_enc.n.limbs().to_vec());

    //PK_ENC_g
    public_inputs.append(&mut pk_enc.g.limbs().to_vec());

    // 2. Verify correct vote encryption
    for i in 0..input.vote.len() {
        let _vote_enc = paillier_chip
            .encrypt(ctx, &pk_enc, &vote_assigned[i], &r_assigned[i])
            .unwrap();

        //ENC_VOTE
        public_inputs.append(&mut _vote_enc.limbs().to_vec());
    }

    // 3. Verify nullifier
    let message = proposal_id
        .value()
        .to_bytes_le()[..2]
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
                _proposal_id
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
        message
    );
    verify_plume(ctx, &ecc_chip, &sha256_chip, 4, 4, plume_input);

    //NULLIFIER
    public_inputs.append(&mut compressed_nullifier.to_vec());

    //MERKLE_ROOT
    public_inputs.append(&mut [membership_root].to_vec());

    //PROPOSAL_ID
    public_inputs.append(&mut [proposal_id].to_vec());
}

#[derive(Clone, Default)]
pub struct VoterCircuit<F: BigPrimeField> {
    input: VoterCircuitInput<F>,
    pub inner: BaseCircuitBuilder<F>,
}

impl<F: BigPrimeField> VoterCircuit<F> {
    pub fn new(
        config: BaseCircuitParams,
        stage: CircuitBuilderStage,
        input: VoterCircuitInput<F>
    ) -> Self {
        let mut inner = BaseCircuitBuilder::from_stage(stage)
            .use_k(15)
            .use_lookup_bits(14)
            .use_instance_columns(1);
        let mut public_inputs = Vec::<AssignedValue<F>>::new();
        let range = inner.range_chip();
        let ctx = inner.main(0);
        voter_circuit(ctx, &range, input.clone(), &mut public_inputs);
        inner.assigned_instances[0].extend(public_inputs);
        inner.calculate_params(Some(10));
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
        gates::circuit::{ BaseCircuitParams, CircuitBuilderStage },
        halo2_proofs::dev::MockProver,
    };

    use super::{ utils::generate_random_voter_circuit_inputs, VoterCircuit };

    #[test]
    fn test_voter_circuit() {
        let input = generate_random_voter_circuit_inputs();

        let config = BaseCircuitParams {
            k: 15 as usize,
            num_advice_per_phase: vec![8],
            num_lookup_advice_per_phase: vec![1],
            num_fixed: 1,
            lookup_bits: Some(14),
            num_instance_columns: 1,
        };

        let circuit = VoterCircuit::new(config, CircuitBuilderStage::Mock, input.clone());
        let prover = MockProver::run(15, &circuit, vec![]).unwrap();
        prover.verify().unwrap();

        // base_test()
        //     .k(15)
        //     .lookup_bits(14)
        //     .expect_satisfied(true)
        //     .run_builder(|pool, range| {
        //         let ctx = pool.main();

        //         let mut public_inputs = Vec::<AssignedValue<Fr>>::new();

        //         voter_circuit(ctx, &range, input, &mut public_inputs);
        //     })
    }
}
