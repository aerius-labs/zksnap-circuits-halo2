pub mod base_circuit;
pub mod utils;
pub mod verifier;
use std::borrow::BorrowMut;

use crate::voter_circuit::{voter_circuit, EncryptionPublicKey, VoterCircuitInput};
use halo2_base::{
    gates::{
        circuit::{builder::BaseCircuitBuilder, CircuitBuilderStage},
        GateChip, GateInstructions, RangeChip, RangeInstructions,
    },
    halo2_proofs::{
        circuit::Value,
        halo2curves::{bn256::Bn256, grumpkin::Fq as Fr},
        poly::kzg::commitment::ParamsKZG,
    },
    utils::{biguint_to_fe, fe_to_biguint, BigPrimeField, ScalarField},
    AssignedValue,
};
use num_bigint::BigUint;
use paillier_chip::{big_uint::chip::BigUintChip, paillier::PaillierChip};
use snark_verifier_sdk::{
    halo2::aggregation::{
        AggregationConfigParams, Halo2KzgAccumulationScheme, VerifierUniversality,
    },
    Snark,
};

use self::verifier::{verify_snarks, AggregationCircuit};
use crate::aggregator::base_circuit::EncryptionPublicKeyU32;
use halo2_base::poseidon::hasher::PoseidonHasher;
use indexed_merkle_tree_halo2::indexed_merkle_tree::{insert_leaf, IndexedMerkleTreeLeaf};
use serde::Deserialize;
use snark_verifier_sdk::halo2::OptimizedPoseidonSpec;

const ENC_BIT_LEN: usize = 128;
const LIMB_BIT_LEN: usize = 64;
#[derive(Clone)]
pub struct IndexedMerkleLeaf<F: BigPrimeField> {
    val: F,
    next_val: F,
    next_idx: F,
}
#[derive(Clone)]
pub struct IndexedMerkleInput {
    low_leaf: IndexedMerkleLeaf<Fr>,
    low_leaf_proof: Vec<Fr>,
    low_leaf_proof_helper: Vec<Fr>,
    new_root: Fr,
    new_leaf: IndexedMerkleLeaf<Fr>,
    new_leaf_index: Fr,
    new_leaf_proof: Vec<Fr>,
    new_leaf_proof_helper: Vec<Fr>,
    is_new_leaf_largest: Fr,
}
#[derive(Deserialize)]
pub struct VoterInput<F: BigPrimeField> {
    membership_root: F,
    pk_enc: EncryptionPublicKeyU32,
    vote_enc: Vec<Vec<u32>>,
    nullifier: Vec<F>,
    proposal_id: F,
    nullifier_old: Vec<u32>,
    nullifier_new: Vec<u32>,
    vote: Vec<Vec<u32>>,
    vote_enc_old: Vec<Vec<u32>>,
    r_enc: Vec<Vec<u32>>,
    pk_voter: Vec<F>,
    membership_proof: Vec<F>,
    membership_proof_helper: Vec<F>,
    limb_bit_len: usize,
    enc_bit_len: usize,
}

pub fn voter_circuit_wrapper(
    builder: &mut BaseCircuitBuilder<Fr>,
    input: VoterInput<Fr>,
    make_public: &mut Vec<AssignedValue<Fr>>,
) {
    let range = builder.range_chip();
    let ctx = builder.main(0);
    let mut public_input = Vec::<AssignedValue<Fr>>::new();

    let membership_root = ctx.load_witness(input.membership_root.clone());
    public_input.push(membership_root);

    let n = ctx.load_witness(biguint_to_fe(&BigUint::from_slice(&input.pk_enc.n)));
    public_input.push(n);
    let g = ctx.load_witness(biguint_to_fe(&BigUint::from_slice(&input.pk_enc.g)));
    public_input.push(g);
    let proposal_id = ctx.load_witness(input.proposal_id);
    public_input.push(proposal_id);

    let mut hasher = PoseidonHasher::<Fr, 3, 2>::new(OptimizedPoseidonSpec::new::<8, 57, 0>());

    hasher.initialize_consts(ctx, &range.gate);
    let pk_enc = EncryptionPublicKey {
        n: BigUint::from_slice(&input.pk_enc.n),
        g: BigUint::from_slice(&input.pk_enc.g),
    };
    let vote_enc: Vec<BigUint> = input
        .vote_enc
        .iter()
        .map(|x| BigUint::from_slice(x))
        .collect();
    let vote: Vec<BigUint> = input.vote.iter().map(|x| BigUint::from_slice(x)).collect();
    let r_enc: Vec<BigUint> = input.r_enc.iter().map(|x| BigUint::from_slice(x)).collect();
    let inputs = VoterCircuitInput::<Fr>::new(
        input.membership_root,
        pk_enc,
        vote_enc.clone(),
        input.nullifier,
        input.proposal_id,
        vote,
        r_enc,
        input.pk_voter,
        input.membership_proof,
        input.membership_proof_helper,
    );
    let vote_enc_old: Vec<AssignedValue<Fr>> = (0..input.vote_enc.len())
        .map(|i| ctx.load_witness(biguint_to_fe(&BigUint::from_slice(&input.vote_enc_old[i]))))
        .collect();
    let vote_enc_assign: Vec<AssignedValue<Fr>> = (0..input.vote_enc.len())
        .map(|i| ctx.load_witness(biguint_to_fe(&vote_enc[i])))
        .collect();

    public_input.extend(vote_enc_old.clone());

    public_input.extend(vote_enc_assign.clone());


    let nullifier_old = ctx.load_witness(biguint_to_fe(&BigUint::from_slice(&input.nullifier_old)));
    public_input.push(nullifier_old);
    let nullifier_new = ctx.load_witness(biguint_to_fe(&BigUint::from_slice(&input.nullifier_new)));
    public_input.push(nullifier_new);

    voter_circuit::<Fr, 3, 2>(
        ctx,
        &range,
        &hasher,
        inputs,
        input.limb_bit_len,
        input.enc_bit_len,
    );

    builder.assigned_instances[0].append(&mut public_input);
}

pub fn aggregator<AS>(
    stage: CircuitBuilderStage,
    config_params: AggregationConfigParams,
    params: &ParamsKZG<Bn256>,
    snarks: impl IntoIterator<Item = Snark> + Clone,
    universality: VerifierUniversality,
    input: IndexedMerkleInput,
    expt_vote_enc: Vec<BigUint>,
) -> AggregationCircuit
where
    AS: for<'a> Halo2KzgAccumulationScheme<'a>,
{
    // This builder can be used to instantiate the custom circuit and then will be passed to the aggregation circuit.
    let mut builder = BaseCircuitBuilder::<Fr>::from_stage(stage).use_params(config_params.into());
    let snarks_clone = snarks.clone();
    let snark_len=snarks.clone();
    let (builder, previous_instances, preprocessed) =
        verify_snarks::<AS>(&mut builder, params, snarks.into_iter(), universality);

    let range = builder.range_chip();
    let ctx = builder.main(0);
    // TODO: implement the custom circuit.
    
    let mut snark_iter = snarks_clone.into_iter();
    let snark_len=snark_len.into_iter();
    println!("snark len={:?}",snark_len.count());
    let base_snark = snark_iter.next().unwrap();
    println!("base snarks ={:?}",base_snark.instances);
    let voter_snark = snark_iter.next().unwrap();
    println!("voter snarks ={:?}",voter_snark.instances);

    let mut public_var = Vec::<_>::with_capacity(16);

    let base_pub_input: Vec<AssignedValue<_>> = (0..16)
        .map(|j| ctx.load_witness(base_snark.instances[0][j]))
        .collect();
    let voter_pub_input: Vec<AssignedValue<_>> = (0..16)
        .map(|j| ctx.load_witness(voter_snark.instances[0][j]))
        .collect();

    // previous_instances[0][0..4] copy constraint base_pub_input[0..4]
    // previous_instances[base_instaces_vec_size][0..4] copy constraint voter_pub_input[0..4]

    for i in 0..previous_instances[0].len() {
        ctx.constrain_equal(&previous_instances[0][i], &base_pub_input[i]);
        ctx.constrain_equal(&previous_instances[1][i], &voter_pub_input[i]);
        if i > 3 && i < 13 {
            public_var.push(ctx.load_zero());
        } else {
            public_var.push(base_pub_input[i]);
        }
    }
    println!("public var length={:?}",public_var.len());

    let biguint_chip = BigUintChip::<Fr>::construct(&range, LIMB_BIT_LEN);

    let n_biguint = fe_to_biguint(base_pub_input[1].value());
    println!("0");
    let n_assigned = biguint_chip
        .assign_integer(ctx, Value::known(n_biguint.clone()), ENC_BIT_LEN)
        .unwrap();
    println!("1");
    let g_assigned = biguint_chip
        .assign_integer(
            ctx,
            Value::known(fe_to_biguint(base_pub_input[2].value())),
            ENC_BIT_LEN,
        )
        .unwrap();
    println!("2");

    let paillier_chip = PaillierChip::construct(
        &biguint_chip,
        ENC_BIT_LEN,
        &n_assigned,
        n_biguint,
        &g_assigned,
    );
    for i in 0..5 {
        public_var[4 + i] = voter_pub_input[4 + i];
        let vote_enc_old = biguint_chip
            .assign_integer(
                ctx,
                Value::known(fe_to_biguint(base_pub_input[4 + i].value())),
                ENC_BIT_LEN,
            )
            .unwrap();
      
        let vote_enc = biguint_chip
            .assign_integer(
                ctx,
                Value::known(fe_to_biguint(voter_pub_input[10 + i].value())),
                ENC_BIT_LEN,
            )
            .unwrap();
        println!("here {:?}",3+i);

        let vote_new_enc = paillier_chip.add(ctx, &vote_enc_old, &vote_enc).unwrap();
        public_var[10 + i] = ctx.load_witness(biguint_to_fe(&expt_vote_enc[i].clone()));
        let expt_vote_new_enc = biguint_chip
            .assign_integer(ctx, Value::known(expt_vote_enc[i].clone()), ENC_BIT_LEN*2)
            .unwrap();
        let result = biguint_chip
            .is_equal_fresh(ctx, &vote_new_enc, &expt_vote_new_enc)
            .unwrap();
        let one = ctx.load_constant(Fr::one());

        ctx.constrain_equal(&result, &one);
    }
    let mut hasher = PoseidonHasher::<Fr, 3, 2>::new(OptimizedPoseidonSpec::new::<8, 57, 0>());

    hasher.initialize_consts(ctx, &range.gate);

    let low_leaf_proof: Vec<AssignedValue<Fr>> = input
        .low_leaf_proof
        .into_iter()
        .map(|x| ctx.load_witness(x))
        .collect();
    let low_leaf_proof_helper: Vec<AssignedValue<Fr>> = input
        .low_leaf_proof_helper
        .into_iter()
        .map(|x| ctx.load_witness(x))
        .collect();
    let new_root = ctx.load_witness(input.new_root);
    ctx.constrain_equal(&new_root, &voter_pub_input[15]);
    let new_leaf_index = ctx.load_witness(input.new_leaf_index);
    let new_leaf_proof: Vec<AssignedValue<Fr>> = input
        .new_leaf_proof
        .into_iter()
        .map(|x| ctx.load_witness(x))
        .collect();
    let new_leaf_proof_helper: Vec<AssignedValue<Fr>> = input
        .new_leaf_proof_helper
        .into_iter()
        .map(|x| ctx.load_witness(x))
        .collect();
    let is_new_leaf_largest = ctx.load_witness(input.is_new_leaf_largest);
    let low_leaf = IndexedMerkleTreeLeaf::<Fr>::new(
        ctx.load_witness(input.low_leaf.val),
        ctx.load_witness(input.low_leaf.next_val),
        ctx.load_witness(input.low_leaf.next_idx),
    );
    let new_leaf = IndexedMerkleTreeLeaf::<Fr>::new(
        ctx.load_witness(input.new_leaf.val),
        ctx.load_witness(input.new_leaf.next_val),
        ctx.load_witness(input.new_leaf.next_idx),
    );
    println!("idx circuit");

    insert_leaf::<Fr, 3, 2>(
        ctx,
        &range,
        &hasher,
        &base_pub_input[14],
        &low_leaf,
        &low_leaf_proof[0..],
        &low_leaf_proof_helper[0..],
        &voter_pub_input[15],
        &new_leaf,
        &new_leaf_index,
        &new_leaf_proof[0..],
        &new_leaf_proof_helper[0..],
        &is_new_leaf_largest,
    );
    println!("done :)");
    AggregationCircuit {
        builder: builder.clone(),
        previous_instances,
        preprocessed,
    }

   
}

#[cfg(test)]
mod tests {
    use super::{
        insert_leaf, voter_circuit_wrapper, IndexedMerkleLeaf, IndexedMerkleTreeLeaf, VoterInput,
    };
    use crate::aggregator::base_circuit::base_circuit;
    use crate::aggregator::IndexedMerkleInput;
    use crate::aggregator::{
        aggregator,
        base_circuit::{BaseCircuitInput, EncryptionPublicKeyU32},
    };
    use crate::utils::run;
    use crate::voter_circuit::{
        utils::{paillier_enc_native, MerkleTree},
        EncryptionPublicKey,
    };
    use ark_std::{end_timer, start_timer};
    use halo2_base::halo2_proofs::arithmetic::Field;
    use halo2_base::halo2_proofs::halo2curves::ff::PrimeField;
    use halo2_base::{
        gates::circuit::{builder::BaseCircuitBuilder, CircuitBuilderStage},
        halo2_proofs::halo2curves::grumpkin::Fq as Fr,
        utils::{biguint_to_fe, fe_to_biguint, fs::gen_srs},
        AssignedValue,
    };
    use num_bigint::{BigUint, RandBigInt};
    use num_traits::{One, Zero};
    use pse_poseidon::Poseidon;
    use rand::thread_rng;
    use serde::Deserialize;
    use snark_verifier_sdk::{
        gen_pk,
        halo2::{
            aggregation::{AggregationConfigParams, VerifierUniversality},
            gen_snark_shplonk,
        },
        SHPLONK,
    };

    #[test]
    fn test_simple_aggregation() {
        const T: usize = 3;
        const RATE: usize = 2;
        const R_F: usize = 8;
        const R_P: usize = 57;
        const ENC_BIT_LEN: usize = 128;
        const LIMB_BIT_LEN: usize = 64;

        let mut rng = thread_rng();

        let treesize = u32::pow(2, 3);

        let vote = [
            BigUint::one(),
            BigUint::default(),
            BigUint::default(),
            BigUint::default(),
            BigUint::default(),
        ]
        .to_vec();

        let n = rng.gen_biguint(ENC_BIT_LEN as u64);
        let g = rng.gen_biguint(ENC_BIT_LEN as u64);

        let mut r_enc = Vec::<BigUint>::new();
        let mut vote_enc = Vec::<Vec<u32>>::new();

        for i in 0..5 {
            r_enc.push(rng.gen_biguint(ENC_BIT_LEN as u64));
            vote_enc.push(paillier_enc_native(&n, &g, &vote[i], &r_enc[i]).to_u32_digits());
            println!("vote enc={:?}",vote_enc[i]);
        }

        let mut native_hasher = Poseidon::<Fr, T, RATE>::new(R_F, R_P);

        let mut leaves = Vec::<Fr>::new();
        let mut indexed_merkle_leaves = Vec::<Fr>::new();
        let pk_voter = vec![Fr::random(rng.clone()), Fr::random(rng.clone())];

        for i in 0..treesize {
            if i == 0 {
                native_hasher.update(&[pk_voter[0], pk_voter[1]]);
            } else {
                native_hasher.update(&[Fr::ZERO]);
            }
            leaves.push(native_hasher.squeeze_and_reset());
        }

        for _ in 0..treesize {
            native_hasher.update(&[Fr::ZERO, Fr::ZERO, Fr::ZERO]);

            indexed_merkle_leaves.push(native_hasher.squeeze_and_reset());
        }

        let membership_tree =
            MerkleTree::<Fr, T, RATE>::new(&mut native_hasher, leaves.clone()).unwrap();
        let mut native_hasher2 = Poseidon::<Fr, T, RATE>::new(R_F, R_P);
        let indexed_tree =
            MerkleTree::<Fr, T, RATE>::new(&mut native_hasher2, indexed_merkle_leaves.clone())
                .unwrap();

        let membership_root = fe_to_biguint(&membership_tree.get_root());
        let (membership_proof, membership_proof_helper) = membership_tree.get_proof(0);
        let nullifier_root_old = fe_to_biguint(&indexed_tree.get_root()).to_u32_digits();

        //  let pk_enc = EncryptionPublicKey { n:n.clone(), g:g.clone() };

        native_hasher.update(&[Fr::ZERO, Fr::ONE, Fr::from_u128(20 as u128)]);
        indexed_merkle_leaves[1]=native_hasher.squeeze_and_reset();

        let new_indexed_tree =
            MerkleTree::<Fr, T, RATE>::new(&mut native_hasher, indexed_merkle_leaves.clone())
                .unwrap();

        let vote_enc_old: Vec<Vec<u32>> = (0..5).map(|_| BigUint::zero().to_u32_digits()).collect();
        let membership_root = membership_root.to_u32_digits();
        let pk_enc = EncryptionPublicKeyU32 {
            n: n.to_u32_digits(),
            g: g.to_u32_digits(),
        };
        let base_proof = run::<BaseCircuitInput>(
            16,
            15,
            base_circuit,
            BaseCircuitInput {
                membership_root: membership_root.clone(),
                proposal_id: BigUint::one().to_u32_digits(),
                vote_enc_old: vote_enc_old.clone(),
                vote_enc_new: vote_enc.clone(),
                nullifier_root_old: nullifier_root_old.clone(),
                nullifier_root_new: fe_to_biguint(&new_indexed_tree.get_root()).to_u32_digits(),
                pk_enc: pk_enc.clone(),
            },
        );

        let vote = vote.iter().map(|x| x.to_u32_digits()).collect();
        let r_enc = r_enc.iter().map(|x| x.to_u32_digits()).collect();
        let voter_proof = run::<VoterInput<Fr>>(
            16,
            15,
            voter_circuit_wrapper,
            VoterInput {
                membership_root: biguint_to_fe(&BigUint::from_slice(&membership_root)),
                pk_enc,
                vote_enc: vote_enc.clone(),
                nullifier: leaves,
                proposal_id: Fr::one(),
                nullifier_old: nullifier_root_old,
                nullifier_new: fe_to_biguint(&new_indexed_tree.get_root()).to_u32_digits(),
                vote,
                vote_enc_old,
                r_enc,
                pk_voter,
                membership_proof,
                membership_proof_helper,
                limb_bit_len: LIMB_BIT_LEN,
                enc_bit_len: ENC_BIT_LEN,
            },
        );

        let k = 16u32;
        let lookup_bits = (k - 1) as usize;

        let params = gen_srs(k);
        let low_leaf = IndexedMerkleLeaf::<Fr> {
            val: Fr::ZERO,
            next_val: Fr::ZERO,
            next_idx: Fr::ZERO,
        };
        let new_leaf = IndexedMerkleLeaf::<Fr> {
            val: Fr::ZERO,
            next_val: Fr::from_u128(20 as u128),
            next_idx: Fr::ONE,
        };
        let (low_leaf_proof, low_leaf_proof_helper) = indexed_tree.get_proof(0);
        let new_root = new_indexed_tree.get_root();
        let (new_leaf_proof, new_leaf_proof_helper) = new_indexed_tree.get_proof(1);
        let input = IndexedMerkleInput {
            low_leaf,
            low_leaf_proof,
            low_leaf_proof_helper,
            new_root,
            new_leaf,
            new_leaf_index: Fr::ONE,
            new_leaf_proof,
            new_leaf_proof_helper,
            is_new_leaf_largest: Fr::ONE,
        };
        let vote_enc_bu: Vec<BigUint> = vote_enc.iter().map(|x| BigUint::from_slice(x)).collect();

        let mut agg_circuit = aggregator::<SHPLONK>(
            CircuitBuilderStage::Keygen,
            AggregationConfigParams {
                degree: k,
                lookup_bits,
                ..Default::default()
            },
            &params,
            vec![base_proof.clone(), voter_proof.clone()],
            VerifierUniversality::Full,
            input.clone(),
            vote_enc_bu.clone(),
        );
        let agg_config = agg_circuit.calculate_params(Some(10));

        let start0 = start_timer!(|| "gen vk & pk");
        let pk = gen_pk(&params, &agg_circuit, None);
        end_timer!(start0);
        let break_points = agg_circuit.break_points();
        println!("keygen done");

        let agg_circuit = aggregator::<SHPLONK>(
            CircuitBuilderStage::Prover,
            agg_config,
            &params,
            vec![base_proof.clone(), voter_proof.clone()],
            VerifierUniversality::Full,
            input,
            vote_enc_bu,
        )
        .use_break_points(break_points.clone());
    println!("prover done");

        let _snark = gen_snark_shplonk(&params, &pk, agg_circuit, None::<&str>);
        println!("snark success");
    }
}
