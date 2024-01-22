use halo2_base::{
    gates::RangeChip,
    utils::BigPrimeField,
    AssignedValue,
    halo2_proofs::circuit::Value,
    Context,
};
use num_bigint::BigUint;
use paillier_chip::{ big_uint::chip::BigUintChip, paillier::PaillierChip };

use crate::voter_circuit::EncryptionPublicKey;

#[derive(Debug, Clone)]
pub struct BaseCircuitInput<F: BigPrimeField> {
    // Public
    pub membership_root: F,
    pub proposal_id: F,
    pub pk_enc: EncryptionPublicKey,
    pub init_vote_enc: Vec<BigUint>,
    pub init_nullifier_root: F,
    // Private
    pub r_enc: Vec<BigUint>,
    // Utils
    pub limb_bit_len: usize,
    pub enc_bit_len: usize,
}

pub fn base_circuit<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    input: BaseCircuitInput<F>,
    make_public: &mut Vec<AssignedValue<F>>
) {
    let biguint_chip = BigUintChip::construct(&range, input.limb_bit_len);

    let membership_root = ctx.load_witness(input.membership_root);
    make_public.push(membership_root.clone());

    let proposal_id = ctx.load_witness(input.proposal_id);
    make_public.push(proposal_id.clone());

    let init_nullifier_root = ctx.load_witness(input.init_nullifier_root);
    make_public.push(init_nullifier_root.clone());

    let n_assigned = biguint_chip
        .assign_integer(ctx, Value::known(input.pk_enc.n.clone()), input.enc_bit_len)
        .unwrap();
    make_public.append(&mut n_assigned.limbs().to_vec());

    let g_assigned = biguint_chip
        .assign_integer(ctx, Value::known(input.pk_enc.g.clone()), input.enc_bit_len)
        .unwrap();
    make_public.append(&mut g_assigned.limbs().to_vec());

    let paillier_chip = PaillierChip::construct(
        &biguint_chip,
        input.enc_bit_len,
        &n_assigned,
        input.pk_enc.n,
        &g_assigned
    );

    let init_vote_enc = input.init_vote_enc
        .iter()
        .map(|v| {
            biguint_chip
                .assign_integer(ctx, Value::known(v.clone()), input.enc_bit_len * 2)
                .unwrap()
        })
        .collect::<Vec<_>>();

    let r_enc = input.r_enc
        .iter()
        .map(|x| {
            biguint_chip.assign_integer(ctx, Value::known(x.clone()), input.enc_bit_len).unwrap()
        })
        .collect::<Vec<_>>();

    for i in 0..input.init_vote_enc.len() {
        let _init_vote_enc = paillier_chip.encrypt(ctx, BigUint::default(), &r_enc[i]).unwrap();
        biguint_chip.assert_equal_fresh(ctx, &_init_vote_enc, &init_vote_enc[i]).unwrap();
    }
    make_public.append(
        &mut init_vote_enc
            .iter()
            .flat_map(|v| { v.limbs().to_vec() })
            .collect::<Vec<_>>()
    );
}

#[cfg(test)]
mod tests {
    use halo2_base::{
        halo2_proofs::{ halo2curves::grumpkin::Fq as Fr, arithmetic::Field },
        utils::testing::base_test,
        AssignedValue,
    };
    use num_bigint::{ BigUint, RandBigInt };
    use rand::thread_rng;

    use crate::{
        aggregator::{
            utils::paillier_enc_native,
            base_circuit::{ BaseCircuitInput, base_circuit },
        },
        voter_circuit::EncryptionPublicKey,
    };

    #[test]
    fn test_base_circuit() {
        const ENC_BIT_LEN: usize = 176;
        const LIMB_BIT_LEN: usize = 88;

        let mut rng = thread_rng();

        let membership_root = Fr::random(rng.clone());
        let proposal_id = Fr::random(rng.clone());
        let n = rng.gen_biguint(ENC_BIT_LEN as u64);
        let g = rng.gen_biguint(ENC_BIT_LEN as u64);
        let pk_enc = EncryptionPublicKey { n: n.clone(), g: g.clone() };
        let init_nullifier_root = Fr::random(rng.clone());

        let mut r_enc = Vec::<BigUint>::new();
        let mut init_vote_enc = Vec::<BigUint>::new();
        for i in 0..5 {
            r_enc.push(rng.gen_biguint(ENC_BIT_LEN as u64));
            // TODO: add paillier_enc_native to common utils
            init_vote_enc.push(paillier_enc_native(&n, &g, &BigUint::default(), &r_enc[i]));
        }

        let input = BaseCircuitInput {
            membership_root,
            proposal_id,
            pk_enc,
            init_vote_enc,
            init_nullifier_root,
            r_enc,
            limb_bit_len: LIMB_BIT_LEN,
            enc_bit_len: ENC_BIT_LEN,
        };

        base_test()
            .k(15)
            .lookup_bits(14)
            .expect_satisfied(true)
            .run(|ctx, range| {
                let mut make_public = Vec::<AssignedValue<Fr>>::new();
                base_circuit(ctx, range, input.clone(), &mut make_public);
            })
    }
}
