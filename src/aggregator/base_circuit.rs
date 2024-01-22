use halo2_base::{
    gates::{circuit::builder::BaseCircuitBuilder, RangeChip},
    halo2_proofs::circuit::Value,
    utils::BigPrimeField,
    AssignedValue, Context,
};
use num_bigint::BigUint;
use paillier_chip::{big_uint::chip::BigUintChip, paillier::PaillierChip};
use serde::Deserialize;

use crate::voter_circuit::EncryptionPublicKey;

#[derive(Deserialize, Clone)]
pub struct BaseCircuitInput<F: BigPrimeField> {
    // Public
    pub membership_root: F,
    pub proposal_id: F,
    pub n: Vec<u32>,
    pub g: Vec<u32>,
    pub init_vote_enc: Vec<Vec<u32>>,
    pub init_nullifier_root: F,
    // Private
    pub r_enc: Vec<Vec<u32>>,
    // Utils
    pub limb_bit_len: usize,
    pub enc_bit_len: usize,
}

pub fn base_circuit<F: BigPrimeField>(
    builder: &mut BaseCircuitBuilder<F>,
    input: BaseCircuitInput<F>,
    make_public: &mut Vec<AssignedValue<F>>,
) {
    let range = builder.range_chip();
    let ctx = builder.main(0);

    let biguint_chip = BigUintChip::construct(&range, input.limb_bit_len);

    let membership_root = ctx.load_witness(input.membership_root);
    make_public.push(membership_root.clone());

    let proposal_id = ctx.load_witness(input.proposal_id);
    make_public.push(proposal_id.clone());

    let init_nullifier_root = ctx.load_witness(input.init_nullifier_root);
    make_public.push(init_nullifier_root.clone());
    let pk_enc = EncryptionPublicKey {
        n: BigUint::from_slice(&input.n),
        g: BigUint::from_slice(&input.g),
    };

    let n_assigned = biguint_chip
        .assign_integer(ctx, Value::known(pk_enc.n.clone()), input.enc_bit_len)
        .unwrap();
    make_public.append(&mut n_assigned.limbs().to_vec());

    let g_assigned = biguint_chip
        .assign_integer(ctx, Value::known(pk_enc.g.clone()), input.enc_bit_len)
        .unwrap();
    make_public.append(&mut g_assigned.limbs().to_vec());

    let paillier_chip = PaillierChip::construct(
        &biguint_chip,
        input.enc_bit_len,
        &n_assigned,
        pk_enc.n,
        &g_assigned,
    );

    let init_vote_enc = input
        .init_vote_enc
        .iter()
        .map(|v| {
            biguint_chip
                .assign_integer(
                    ctx,
                    Value::known(BigUint::from_slice(v)),
                    input.enc_bit_len * 2,
                )
                .unwrap()
        })
        .collect::<Vec<_>>();

    let r_enc = input
        .r_enc
        .iter()
        .map(|x| {
            biguint_chip
                .assign_integer(ctx, Value::known(BigUint::from_slice(x)), input.enc_bit_len)
                .unwrap()
        })
        .collect::<Vec<_>>();

    for i in 0..input.init_vote_enc.len() {
        let _init_vote_enc = paillier_chip
            .encrypt(ctx, BigUint::default(), &r_enc[i])
            .unwrap();
        biguint_chip
            .assert_equal_fresh(ctx, &_init_vote_enc, &init_vote_enc[i])
            .unwrap();
    }
    make_public.append(
        &mut init_vote_enc
            .iter()
            .flat_map(|v| v.limbs().to_vec())
            .collect::<Vec<_>>(),
    );
}

#[cfg(test)]
mod tests {
    use halo2_base::{
        halo2_proofs::{arithmetic::Field, halo2curves::grumpkin::Fq as Fr},
        utils::testing::base_test,
        AssignedValue,
    };
    use num_bigint::{BigUint, RandBigInt};
    use rand::thread_rng;

    use crate::{
        aggregator::{
            base_circuit::{base_circuit, BaseCircuitInput},
            utils::paillier_enc_native,
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
        let pk_enc = EncryptionPublicKey {
            n: n.clone(),
            g: g.clone(),
        };
        let init_nullifier_root = Fr::random(rng.clone());

        let mut r_enc = Vec::<BigUint>::new();
        let mut init_vote_enc = Vec::<Vec<u32>>::new();
        for i in 0..5 {
            r_enc.push(rng.gen_biguint(ENC_BIT_LEN as u64));
            // TODO: add paillier_enc_native to common utils
            init_vote_enc
                .push(paillier_enc_native(&n, &g, &BigUint::default(), &r_enc[i]).to_u32_digits());
        }
        let r_enc = (0..5).map(|i| r_enc[i].to_u32_digits()).collect();

        let input = BaseCircuitInput {
            membership_root,
            proposal_id,
            n: pk_enc.n.to_u32_digits(),
            g: pk_enc.g.to_u32_digits(),
            init_vote_enc,
            init_nullifier_root,
            r_enc,
            limb_bit_len: LIMB_BIT_LEN,
            enc_bit_len: ENC_BIT_LEN,
        };
    }
}
