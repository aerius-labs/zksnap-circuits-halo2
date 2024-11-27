pub mod merkletree;

use halo2_base::{
    gates::{
        circuit::{builder::BaseCircuitBuilder, BaseCircuitParams, BaseConfig},
        GateInstructions, RangeChip, RangeInstructions,
    },
    halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        halo2curves::{
            group::ff::Field,
            secp256k1::{Fq, Secp256k1Affine},
        },
        plonk::{Circuit, ConstraintSystem, Error, Selector},
    },
    poseidon::hasher::{spec::OptimizedPoseidonSpec, PoseidonHasher},
    utils::{fe_to_biguint, BigPrimeField},
    AssignedValue, Context, QuantumCell,
};
use halo2_ecc::{
    bigint::{big_is_even, ProperCrtUint},
    ecc::{EcPoint, EccChip},
    fields::FieldChip,
    secp256k1::{sha256::Sha256Chip, FpChip, FqChip},
};
use indexed_merkle_tree_halo2::indexed_merkle_tree::verify_merkle_proof;
use itertools::Itertools;

use num_bigint::BigUint;

use biguint_halo2::big_uint::chip::BigUintChip;
use paillier_chip::paillier::{EncryptionPublicKeyAssigned, PaillierChip};
use plume_halo2::plume::{verify_plume, PlumeInput};
use serde::{Deserialize, Serialize};

const ENC_BIT_LEN: usize = 176;
const LIMB_BIT_LEN: usize = 88;
const NUM_LIMBS: usize = 3;

const T: usize = 3;
const RATE: usize = 2;
const R_F: usize = 8;
const R_P: usize = 57;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EncryptionPublicKey {
    pub n: BigUint,
    pub g: BigUint,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct VoterCircuitInput<F: BigPrimeField> {
    // * Public inputs
    // pub membership_root: F,
    pub pk_enc: EncryptionPublicKey,
    // pub nullifier: Poseidon<[F;32]>,
    pub nullifier: F,
    // ? This will be 2 bytes for performance, can change this
    // ? to accomodate more bytes later based on requirement.
    pub proposal_id: F,
    pub vote_enc: Vec<BigUint>,

    // * Private inputs

    // * s = r + sk * c
    // pub s_nullifier: Fq,

    pub vote: Vec<F>,
    pub r_enc: Vec<BigUint>,
    // pub pk_voter: Secp256k1Affine,
    // pub c_nullifier: Fq,
    // pub membership_proof: Vec<F>,
    // pub membership_proof_helper: Vec<F>,
}

impl<F: BigPrimeField> VoterCircuitInput<F> {
    pub fn new(
        pk_enc: EncryptionPublicKey,
        nullifier: F,
        proposal_id: F,
        vote_enc: Vec<BigUint>,
        vote: Vec<F>,
        r_enc: Vec<BigUint>,
    ) -> Self {
        Self {
            pk_enc,
            nullifier,
            proposal_id,
            vote_enc,
            vote,
            r_enc,
        }
    }
}

pub trait CircuitExt<F: Field>: Circuit<F> {
    fn num_instance() -> Vec<usize>;

    fn instances(&self) -> Vec<Vec<F>>;

    fn accumulator_indices() -> Option<Vec<(usize, usize)>> {
        None
    }

    /// Output the simple selector columns (before selector compression) of the circuit
    fn selectors(_: &Self::Config) -> Vec<Selector> {
        vec![]
    }
}

// pub fn compress_nullifier<F: BigPrimeField>(
//     ctx: &mut Context<F>,
//     range: &RangeChip<F>,
//     nullifier: &EcPoint<F, ProperCrtUint<F>>,
// ) -> Vec<AssignedValue<F>> {
//     let mut compressed_pt = Vec::<AssignedValue<F>>::with_capacity(4);

//     let is_y_even = big_is_even::positive(
//         range,
//         ctx,
//         nullifier.y().as_ref().truncation.clone(),
//         LIMB_BIT_LEN,
//     );

//     let tag = range.gate().select(
//         ctx,
//         QuantumCell::Constant(F::from(2u64)),
//         QuantumCell::Constant(F::from(3u64)),
//         is_y_even,
//     );

//     compressed_pt.push(tag);
//     compressed_pt.extend(nullifier.x().limbs().to_vec());

//     compressed_pt
// }

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
    
    let nullifier_fe = ctx.load_witness(input.nullifier);
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

    // Check to verify correct votes have been passed.
    let _ = vote_assigned_fe.iter().map(|x| gate.assert_bit(ctx, *x));
    let zero = ctx.load_zero();
    let one = ctx.load_constant(F::ONE);
    let vote_sum_assigned = vote_assigned_fe
        .iter()
        .fold(zero, |zero, x| gate.add(ctx, zero, *x));
    ctx.constrain_equal(&vote_sum_assigned, &one);

    //PK_ENC_n
    println!("pk_enc n : {:?}", pk_enc.n.limbs().to_vec());
    public_inputs.extend(pk_enc.n.limbs().to_vec());

    //PK_ENC_g
    println!("pk_enc n : {:?}", pk_enc.n.limbs().to_vec());
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

    // //NULLIFIER
    public_inputs.push(nullifier_fe);

    //PROPOSAL_ID
    public_inputs.push(proposal_id);


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
        inner.calculate_params(Some(9));
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
