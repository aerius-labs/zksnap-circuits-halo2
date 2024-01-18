use crate::voter_circuit::EncryptionPublicKey;
use halo2_base::{
    gates::{
        circuit::{builder::BaseCircuitBuilder, CircuitBuilderStage},
        GateChip, GateInstructions, RangeChip, RangeInstructions,
    },
    halo2_proofs::circuit::Value,
    poseidon::hasher::PoseidonHasher,
    utils::biguint_to_fe,
    utils::{BigPrimeField, ScalarField},
    AssignedValue, Context,
};
use num_bigint::BigUint;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct BaseCircuitInput {
    pub membership_root: BigUint,
    pub proposal_id: BigUint,
    pub vote_enc_old: Vec<BigUint>,
    pub vote_enc_new: Vec<BigUint>,
    pub nullifier_root_old: BigUint,
    pub nullifier_root_new: BigUint,
    pub pk_enc: EncryptionPublicKey,
}

pub fn base_circuit<F: BigPrimeField>(
    builder: &mut BaseCircuitBuilder<F>,
    input: BaseCircuitInput,
    make_public: &mut Vec<AssignedValue<F>>,
) {
    let ctx = builder.main(0);

    let membership_root = ctx.load_witness(biguint_to_fe(&input.membership_root));
    let n = ctx.load_witness(biguint_to_fe(&input.pk_enc.n));
    let g = ctx.load_witness(biguint_to_fe(&input.pk_enc.g));
    let proposal_id = ctx.load_witness(biguint_to_fe(&input.proposal_id));
    let vote_enc_old: Vec<AssignedValue<F>> = input
        .vote_enc_old
        .iter()
        .map(|x| ctx.load_witness(biguint_to_fe(x)))
        .collect();
    let vote_enc_new: Vec<AssignedValue<F>> = input
        .vote_enc_new
        .iter()
        .map(|x| ctx.load_witness(biguint_to_fe(x)))
        .collect();
    //todo nullifier load witness

    let nullifier_root_old = ctx.load_witness(biguint_to_fe(&input.nullifier_root_old));
    let nullifier_root_new = ctx.load_witness(biguint_to_fe(&input.nullifier_root_new));

    let mut public_input = Vec::<AssignedValue<F>>::new();
    public_input.extend([membership_root, n, g, proposal_id].to_vec());
    public_input.extend(vote_enc_old.iter());
    public_input.extend(vote_enc_new.iter());
    public_input.extend([nullifier_root_old, nullifier_root_new].to_vec());

    builder.assigned_instances[0].append(&mut public_input);
}
