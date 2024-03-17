use halo2_base::halo2_proofs::arithmetic::{CurveAffine, Field};
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::halo2_proofs::halo2curves::ff::PrimeField;
use halo2_base::halo2_proofs::halo2curves::group::Curve;
use halo2_base::halo2_proofs::halo2curves::secp256k1::{Fp, Fq, Secp256k1, Secp256k1Affine};
use halo2_base::utils::{fe_to_biguint, ScalarField};
use halo2_ecc::*;
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
use rand::thread_rng;
use sha2::{Digest, Sha256};

use crate::merkletree::native::MerkleTree;
use crate::{EncryptionPublicKey, VoterCircuitInput};

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

pub fn gen_test_nullifier(sk: &Fq, message: &[u8]) -> (Secp256k1Affine, Fq, Fq) {
    let pk = (Secp256k1::generator() * sk).to_affine();
    let compressed_pk = compress_point(&pk);

    let hashed_to_curve = hash_to_curve(message, &compressed_pk);

    let hashed_to_curve_sk = (hashed_to_curve * sk).to_affine();

    let r = Fq::random(OsRng);
    let g_r = (Secp256k1::generator() * r).to_affine();
    let hashed_to_curve_r = (hashed_to_curve * r).to_affine();

    let mut sha_hasher = Sha256::new();
    sha_hasher.update(
        vec![
            compress_point(&Secp256k1::generator().to_affine()),
            compressed_pk,
            compress_point(&hashed_to_curve),
            compress_point(&hashed_to_curve_sk),
            compress_point(&g_r),
            compress_point(&hashed_to_curve_r),
        ]
        .concat(),
    );

    let mut c = sha_hasher.finalize();
    c.reverse();

    let c = Fq::from_bytes_le(c.as_slice());
    let s = r + sk * c;

    (hashed_to_curve_sk, s, c)
}

pub fn generate_random_voter_circuit_inputs() -> VoterCircuitInput<Fr> {
    const ENC_BIT_LEN: usize = 176;

    const T: usize = 3;
    const RATE: usize = 2;
    const R_F: usize = 8;
    const R_P: usize = 57;

    let mut rng = thread_rng();

    let treesize = u32::pow(2, 3);

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

    let mut native_hasher = Poseidon::<Fr, T, RATE>::new(R_F, R_P);

    let mut leaves = Vec::<Fr>::new();

    let sk = Fq::random(OsRng);
    let pk_voter = (Secp256k1::generator() * sk).to_affine();

    let pk_voter_x = pk_voter
        .x
        .to_bytes()
        .to_vec()
        .chunks(11)
        .into_iter()
        .map(|chunk| Fr::from_bytes_le(chunk))
        .collect::<Vec<_>>();
    let pk_voter_y = pk_voter
        .y
        .to_bytes()
        .to_vec()
        .chunks(11)
        .into_iter()
        .map(|chunk| Fr::from_bytes_le(chunk))
        .collect::<Vec<_>>();

    for i in 0..treesize {
        if i == 0 {
            native_hasher.update(pk_voter_x.as_slice());
            native_hasher.update(pk_voter_y.as_slice());
        } else {
            native_hasher.update(&[Fr::ZERO]);
        }
        leaves.push(native_hasher.squeeze_and_reset());
    }

    let mut membership_tree =
        MerkleTree::<Fr, T, RATE>::new(&mut native_hasher, leaves.clone()).unwrap();

    let membership_root = membership_tree.get_root();
    let (membership_proof, membership_proof_helper) = membership_tree.get_proof(0);
    assert_eq!(
        membership_tree.verify_proof(&leaves[0], 0, &membership_root, &membership_proof),
        true
    );

    let pk_enc = EncryptionPublicKey { n, g };

    // Proposal id = 1
    let (nullifier, s, c) = gen_test_nullifier(&sk, &[1u8, 0u8]);
    verify_nullifier(&[1u8, 0u8], &nullifier, &pk_voter, &s, &c);

    let input = VoterCircuitInput {
        membership_root,
        pk_enc,
        nullifier,
        proposal_id: Fr::from(1u64),
        vote_enc,
        s_nullifier: s,
        vote,
        r_enc,
        pk_voter,
        c_nullifier: c,
        membership_proof: membership_proof.clone(),
        membership_proof_helper: membership_proof_helper.clone(),
    };

    input
}
