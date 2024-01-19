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
#[derive(Deserialize, Clone)]
pub struct EncryptionPublicKeyU32 {
    pub n: Vec<u32>,
    pub g: Vec<u32>,
}

#[derive(Deserialize)]
pub struct BaseCircuitInput {
    pub membership_root: Vec<u32>,
    pub proposal_id: Vec<u32>,
    pub vote_enc_old: Vec<Vec<u32>>,
    pub vote_enc_new: Vec<Vec<u32>>,
    pub nullifier_root_old: Vec<u32>,
    pub nullifier_root_new: Vec<u32>,
    pub pk_enc: EncryptionPublicKeyU32,
}

pub fn base_circuit<F: BigPrimeField>(
    builder: &mut BaseCircuitBuilder<F>,
    input: BaseCircuitInput,
    make_public: &mut Vec<AssignedValue<F>>,
) {
    let ctx = builder.main(0);
    let membership_root_bu = BigUint::from_slice(&input.membership_root);
    let membership_root = ctx.load_witness(biguint_to_fe(&membership_root_bu));
    let n_bu = BigUint::from_slice(&input.pk_enc.n);
    let n = ctx.load_witness(biguint_to_fe(&n_bu));
    let g_bu = BigUint::from_slice(&input.pk_enc.g);
    let g = ctx.load_witness(biguint_to_fe(&g_bu));
    let proposal_id_bu = BigUint::from_slice(&input.proposal_id);
    let proposal_id = ctx.load_witness(biguint_to_fe(&proposal_id_bu));
    let vote_enc_old_bu: Vec<BigUint> = input
        .vote_enc_old
        .iter()
        .map(|x| BigUint::from_slice(x))
        .collect();
    let vote_enc_old: Vec<AssignedValue<F>> = vote_enc_old_bu
        .iter()
        .map(|x| ctx.load_witness(biguint_to_fe(x)))
        .collect();
    let vote_enc_new_bu: Vec<BigUint> = input
        .vote_enc_new
        .iter()
        .map(|x| BigUint::from_slice(x))
        .collect();
    let vote_enc_new: Vec<AssignedValue<F>> = vote_enc_new_bu
        .iter()
        .map(|x| ctx.load_witness(biguint_to_fe(x)))
        .collect();
    //todo nullifier load witness

    let nullifier_root_old_bu = BigUint::from_slice(&input.nullifier_root_old);

    let nullifier_root_old = ctx.load_witness(biguint_to_fe(&nullifier_root_old_bu));
    let nullifier_root_new_bu = BigUint::from_slice(&input.nullifier_root_new);
    let nullifier_root_new = ctx.load_witness(biguint_to_fe(&nullifier_root_new_bu));

    let mut public_input = Vec::<AssignedValue<F>>::new();
    public_input.extend([membership_root, n, g, proposal_id].to_vec());
    public_input.extend(vote_enc_old.iter());
    public_input.extend(vote_enc_new.iter());
    public_input.extend([nullifier_root_old, nullifier_root_new].to_vec());

    builder.assigned_instances[0].append(&mut public_input);
}
