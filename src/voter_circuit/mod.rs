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

use crate::merkletree::verify_membership_proof;

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
    // * s = r + sk * c
    s_nullifier: Fq,

    // * Private inputs
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
    let compressed_nullifier = compress_point(ctx, range, &nullifier);

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

    //PK_ENC_g
    public_inputs.append(&mut pk_enc.g.limbs().to_vec());

    //PK_ENC_n
    public_inputs.append(&mut pk_enc.n.limbs().to_vec());

    //PROPOSAL_ID
    public_inputs.append(&mut [proposal_id].to_vec());

    //S_NULLIFIER
    public_inputs.append(&mut s_nullifier.limbs().to_vec());
}

#[derive(Clone, Default)]
pub struct VoterCircuit<F: BigPrimeField> {
    input: VoterCircuitInput<F>,
    inner: BaseCircuitBuilder<F>,
}

impl<F: BigPrimeField> VoterCircuit<F> {
    pub fn new(input: VoterCircuitInput<F>, params: BaseCircuitParams) -> Self {
        //   let mut inner = BaseCircuitBuilder::new(false).use_params(params);
        let mut inner = BaseCircuitBuilder::from_stage(CircuitBuilderStage::Mock);
        inner.set_lookup_bits(14);
        inner.set_k(15);
        let mut public_inputs = Vec::<AssignedValue<F>>::new();
        let range = inner.range_chip();
        let ctx = inner.main(0);

        voter_circuit(ctx, &range, input.clone(), &mut public_inputs);
        Self {
            input,
            inner,
        }
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

#[cfg(test)]
mod test {
    use halo2_base::gates::circuit::BaseCircuitParams;
    use halo2_base::halo2_proofs::arithmetic::{ CurveAffine, Field };
    use halo2_base::halo2_proofs::dev::MockProver;
    use halo2_base::halo2_proofs::halo2curves::ff::PrimeField;
    use halo2_base::halo2_proofs::halo2curves::group::Curve;
    use halo2_base::halo2_proofs::halo2curves::grumpkin::Fq as Fr;
    use halo2_base::halo2_proofs::halo2curves::secp256k1::{ Fp, Fq, Secp256k1, Secp256k1Affine };
    use halo2_base::utils::testing::base_test;
    use halo2_base::utils::ScalarField;
    use halo2_base::AssignedValue;
    use halo2_ecc::*;
    use k256::elliptic_curve::hash2curve::GroupDigest;
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::{
        elliptic_curve::hash2curve::ExpandMsgXmd,
        sha2::Sha256 as K256Sha256,
        Secp256k1 as K256Secp256k1,
    };
    use num_bigint::{ BigUint, RandBigInt };
    use num_traits::One;
    use paillier_chip::paillier::paillier_enc_native;
    use pse_poseidon::Poseidon;
    use rand::rngs::OsRng;
    use rand::thread_rng;
    use sha2::{ Digest, Sha256 };

    use crate::merkletree::native::MerkleTree;
    use crate::voter_circuit::{
        voter_circuit,
        EncryptionPublicKey,
        VoterCircuit,
        VoterCircuitInput,
        ENC_BIT_LEN,
        RATE,
        R_F,
        R_P,
        T,
    };

    pub fn compress_point(point: &Secp256k1Affine) -> [u8; 33] {
        let mut x = point.x.to_bytes();
        x.reverse();
        let y_is_odd = if point.y.is_odd().unwrap_u8() == 1u8 { 3u8 } else { 2u8 };
        let mut compressed_pk = [0u8; 33];
        compressed_pk[0] = y_is_odd;
        compressed_pk[1..].copy_from_slice(&x);

        compressed_pk
    }

    fn hash_to_curve(message: &[u8], compressed_pk: &[u8; 33]) -> Secp256k1Affine {
        let hashed_to_curve = K256Secp256k1::hash_from_bytes::<ExpandMsgXmd<K256Sha256>>(
            &[[message, compressed_pk].concat().as_slice()],
            &[b"QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_"]
        )
            .unwrap()
            .to_affine();
        let hashed_to_curve = hashed_to_curve.to_encoded_point(false).to_bytes().into_vec();
        assert_eq!(hashed_to_curve.len(), 65);

        let mut x = hashed_to_curve[1..33].to_vec();
        x.reverse();
        let mut y = hashed_to_curve[33..].to_vec();
        y.reverse();

        Secp256k1Affine::from_xy(
            Fp::from_bytes_le(x.as_slice()),
            Fp::from_bytes_le(y.as_slice())
        ).unwrap()
    }

    fn verify_nullifier(
        message: &[u8],
        nullifier: &Secp256k1Affine,
        pk: &Secp256k1Affine,
        s: &Fq,
        c: &Fq
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
                compress_point(&hashed_to_curve_s_nullifier_c)
            ].concat()
        );

        let mut _c = sha_hasher.finalize();
        _c.reverse();
        let _c = Fq::from_bytes_le(_c.as_slice());

        assert_eq!(*c, _c);
    }

    fn gen_test_nullifier(sk: &Fq, message: &[u8]) -> (Secp256k1Affine, Fq, Fq) {
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
                compress_point(&hashed_to_curve_r)
            ].concat()
        );

        let mut c = sha_hasher.finalize();
        c.reverse();

        let c = Fq::from_bytes_le(c.as_slice());
        let s = r + sk * c;

        (hashed_to_curve_sk, s, c)
    }

    #[test]
    fn test_voter_circuit() {
        let mut rng = thread_rng();

        let treesize = u32::pow(2, 3);

        let vote = [
            BigUint::one(),
            BigUint::default(),
            BigUint::default(),
            BigUint::default(),
            BigUint::default(),
        ].to_vec();

        let n = rng.gen_biguint(ENC_BIT_LEN as u64);
        let g = rng.gen_biguint(ENC_BIT_LEN as u64);

        let mut r_enc = Vec::<BigUint>::with_capacity(5);
        let mut vote_enc = Vec::<BigUint>::with_capacity(5);

        for i in 0..5 {
            r_enc.push(rng.gen_biguint(ENC_BIT_LEN as u64));
            vote_enc.push(paillier_enc_native(&n, &g, &vote[i], &r_enc[i]));
        }

        let mut native_hasher = Poseidon::<Fr, T, RATE>::new(R_F, R_P);

        let mut leaves = Vec::<Fr>::new();

        let sk = Fq::random(OsRng);
        let pk_voter = (Secp256k1::generator() * sk).to_affine();

        let pk_voter_x = pk_voter.x
            .to_bytes()
            .to_vec()
            .chunks(11)
            .into_iter()
            .map(|chunk| Fr::from_bytes_le(chunk))
            .collect::<Vec<_>>();
        let pk_voter_y = pk_voter.y
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

        let mut membership_tree = MerkleTree::<Fr, T, RATE>
            ::new(&mut native_hasher, leaves.clone())
            .unwrap();

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
            s_nullifier: s,
            vote,
            r_enc,
            pk_voter,
            c_nullifier: c,
            membership_proof: membership_proof.clone(),
            membership_proof_helper: membership_proof_helper.clone(),
        };

        let config_params = BaseCircuitParams {
            k: 15 as usize,
            num_advice_per_phase: vec![10],
            num_lookup_advice_per_phase: vec![1],
            num_fixed: 1,
            lookup_bits: Some(14),
            num_instance_columns: 0,
        };
        let circuit = VoterCircuit::new(input.clone(), config_params);
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
