use halo2_base::halo2_proofs::arithmetic::{CurveAffine, Field};
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::halo2_proofs::halo2curves::ff::PrimeField;
use halo2_base::halo2_proofs::halo2curves::group::Curve;
use halo2_base::halo2_proofs::halo2curves::secp256k1::{Fp, Fq, Secp256k1, Secp256k1Affine};
use halo2_base::utils::{fe_to_biguint, ScalarField};
use halo2_ecc::*;
use indexed_merkle_tree_halo2::utils::IndexedMerkleTree;
use k256::elliptic_curve::hash2curve::GroupDigest;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{
    elliptic_curve::hash2curve::ExpandMsgXmd, sha2::Sha256 as K256Sha256,
    Secp256k1 as K256Secp256k1,
};
use num_bigint::{BigUint, RandBigInt};
use paillier_chip::paillier::paillier_enc_native;
use pse_poseidon::Poseidon;
use rand::rngs::OsRng;
use rand::{thread_rng, Rng};
use sha2::{Digest, Sha256};

use voter::merkletree::native::{self, MerkleTree};
use voter::{voter_circuit, EncryptionPublicKey, VoterCircuitInput};

pub fn compress_point(point: &Secp256k1Affine) -> [u8; 33] {
    let mut x = point.x.to_bytes();
    x.reverse();
    let y_is_odd = if point.y.is_odd().unwrap_u8() == 1u8 {
        3u8
    } else {
        2u8
    };
    let mut compressed_pk = [0u8; 33];
    compressed_pk[0] = y_is_odd;
    compressed_pk[1..].copy_from_slice(&x);

    compressed_pk
}

pub fn hash_to_curve(message: &[u8], compressed_pk: &[u8; 33]) -> Secp256k1Affine {
    let hashed_to_curve = K256Secp256k1::hash_from_bytes::<ExpandMsgXmd<K256Sha256>>(
        &[[message, compressed_pk].concat().as_slice()],
        &[b"QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_"],
    )
    .unwrap()
    .to_affine();
    let hashed_to_curve = hashed_to_curve
        .to_encoded_point(false)
        .to_bytes()
        .into_vec();
    assert_eq!(hashed_to_curve.len(), 65);

    let mut x = hashed_to_curve[1..33].to_vec();
    x.reverse();
    let mut y = hashed_to_curve[33..].to_vec();
    y.reverse();

    Secp256k1Affine::from_xy(
        Fp::from_bytes_le(x.as_slice()),
        Fp::from_bytes_le(y.as_slice()),
    )
    .unwrap()
}

pub fn verify_nullifier(
    message: &[u8],
    nullifier: &Secp256k1Affine,
    pk: &Secp256k1Affine,
    s: &Fq,
    c: &Fq,
) {
    let compressed_pk = compress_point(&pk);
    let hashed_to_curve = hash_to_curve(message, &compressed_pk);
    let hashed_to_curve_s_nullifier_c = (hashed_to_curve * s - nullifier * c).to_affine();
    let gs_pkc = (Secp256k1::generator() * s - pk * c).to_affine();

    let mut sha_hasher = Sha256::new();
    sha_hasher.update(
        vec![
            compress_point(&Secp256k1::generator().to_affine()),
            compressed_pk,
            compress_point(&hashed_to_curve),
            compress_point(&nullifier),
            compress_point(&gs_pkc),
            compress_point(&hashed_to_curve_s_nullifier_c),
        ]
        .concat(),
    );

    let mut _c = sha_hasher.finalize();
    _c.reverse();
    let _c = Fq::from_bytes_le(_c.as_slice());

    assert_eq!(*c, _c);
}

pub fn gen_test_nullifier() -> Fr {
    // generate 32 bytes random number
    let mut rng = thread_rng();
    Fr::random(&mut rng)
}

pub fn generate_random_voter_circuit_inputs() -> VoterCircuitInput<Fr> {
    const ENC_BIT_LEN: usize = 176;

    let mut rng = thread_rng();

    let vote = [Fr::one(), Fr::zero(), Fr::zero(), Fr::zero(), Fr::zero()].to_vec();

    let n = rng.gen_biguint(ENC_BIT_LEN as u64);
    let g = rng.gen_biguint(ENC_BIT_LEN as u64);

    let mut r_enc = Vec::<BigUint>::with_capacity(5);
    let mut vote_enc = Vec::<BigUint>::with_capacity(5);

    for i in 0..5 {
        r_enc.push(rng.gen_biguint(ENC_BIT_LEN as u64));
        vote_enc.push(paillier_enc_native(
            &n,
            &g,
            &fe_to_biguint(&vote[i]),
            &r_enc[i],
        ));
    }

    let pk_enc = EncryptionPublicKey { n, g };

    // Proposal id = 1
    let nullifier = gen_test_nullifier();

    let input = VoterCircuitInput {
        pk_enc,
        nullifier,
        proposal_id: Fr::from(1u64),
        vote_enc,
        vote,
        r_enc,
    };

    input
}

#[cfg(test)]
mod test {
    use halo2_base::{
        gates::circuit::BaseCircuitParams,
        halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr},
        utils::testing::base_test,
        AssignedValue,
    };

    use super::generate_random_voter_circuit_inputs;
    use voter::{voter_circuit, CircuitExt, VoterCircuit};

    #[test]
    fn test_voter_circuit() {
        let input = generate_random_voter_circuit_inputs();

        let config = BaseCircuitParams {
            k: 12 as usize,
            num_advice_per_phase: vec![8],
            num_lookup_advice_per_phase: vec![1],
            num_fixed: 1,
            lookup_bits: Some(11),
            num_instance_columns: 1,
        };

        let circuit = VoterCircuit::new(config, input.clone());
        let prover = MockProver::run(12, &circuit, circuit.instances()).unwrap();
        prover.verify().unwrap();

        // base_test()
        //     .k(12)
        //     .lookup_bits(11)
        //     .expect_satisfied(true)
        //     .run_builder(|pool, range| {
        //         let ctx = pool.main();

        //         let mut public_inputs = Vec::<AssignedValue<Fr>>::new();

        //         voter_circuit(ctx, &range, input, &mut public_inputs);
        //     })
    }
}
