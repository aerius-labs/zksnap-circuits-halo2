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
pub struct EncryptionPublicKey {
    n: BigUint,
    g: BigUint,
}

pub fn base_circuit<F: BigPrimeField>(
    builder: &mut BaseCircuitBuilder<F>,
    membership_root: BigUint,
    proposal_id: BigUint,
    vote_enc_old: Vec<BigUint>,
    vote_enc_new: Vec<BigUint>,
    nullifier_root_old: BigUint,
    nullifier_root_new: BigUint,
    pk_enc: EncryptionPublicKey,
) {
    let ctx = builder.main(0);

    let membership_root = ctx.load_witness(biguint_to_fe(&membership_root));
    let proposal_id = ctx.load_witness(biguint_to_fe(&proposal_id));
    let vote_enc_old: Vec<AssignedValue<F>> = vote_enc_old
        .iter()
        .map(|x| ctx.load_witness(biguint_to_fe(x)))
        .collect();
    let vote_enc_new: Vec<AssignedValue<F>> = vote_enc_new
        .iter()
        .map(|x| ctx.load_witness(biguint_to_fe(x)))
        .collect();
    let nullifier_root_old = ctx.load_witness(biguint_to_fe(&nullifier_root_old));
    let nullifier_root_new = ctx.load_witness(biguint_to_fe(&nullifier_root_new));
    let n = ctx.load_witness(biguint_to_fe(&pk_enc.n));
    let g = ctx.load_witness(biguint_to_fe(&pk_enc.g));

    let mut public_input = Vec::<AssignedValue<F>>::new();
    public_input.extend(
        [
            membership_root,
            proposal_id,
            n,
            g,
            nullifier_root_old,
            nullifier_root_new,
        ]
        .to_vec(),
    );
    public_input.extend(vote_enc_old.iter());
    public_input.extend(vote_enc_new.iter());

    builder.assigned_instances[0].append(&mut public_input);
}
