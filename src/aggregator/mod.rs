pub mod base_circuit;
pub mod recursion;
pub mod utils;
pub mod verifier;

use halo2_base::{
    gates::circuit::{builder::BaseCircuitBuilder, CircuitBuilderStage},
    halo2_proofs::{
        circuit::Value,
        halo2curves::{bn256::Bn256, grumpkin::Fq as Fr},
        poly::kzg::commitment::ParamsKZG,
    },
    utils::BigPrimeField,
    AssignedValue,
};
use halo2_ecc::bigint::OverflowInteger;

use biguint_halo2::big_uint::{chip::BigUintChip, AssignedBigUint, Fresh};
use paillier_chip::paillier::{EncryptionPublicKeyAssigned, PaillierChip};
use snark_verifier_sdk::{
    halo2::aggregation::{
        AggregationConfigParams, Halo2KzgAccumulationScheme, VerifierUniversality,
    },
    Snark,
};

use self::verifier::{verify_snarks, AggregationCircuit};
use crate::aggregator::utils::to_biguint;
use halo2_base::poseidon::hasher::PoseidonHasher;
use indexed_merkle_tree_halo2::indexed_merkle_tree::{insert_leaf, IndexedMerkleTreeLeaf};
use snark_verifier_sdk::halo2::OptimizedPoseidonSpec;

#[derive(Debug, Clone)]
pub struct IndexedMerkleLeaf<F: BigPrimeField> {
    val: F,
    next_val: F,
    next_idx: F,
}

#[derive(Debug, Clone)]
pub struct AggregatorCircuitInput {
    low_leaf: IndexedMerkleLeaf<Fr>,
    low_leaf_proof: Vec<Fr>,
    low_leaf_proof_helper: Vec<Fr>,
    new_root: Fr,
    new_leaf: IndexedMerkleLeaf<Fr>,
    new_leaf_index: Fr,
    new_leaf_proof: Vec<Fr>,
    new_leaf_proof_helper: Vec<Fr>,
    is_new_leaf_largest: Fr,
    limb_bit_len: usize,
    enc_bit_len: usize,
}

pub fn base_aggregator<AS>(
    stage: CircuitBuilderStage,
    config_params: AggregationConfigParams,
    params: &ParamsKZG<Bn256>,
    base_proof: Snark,
    voter_proof: Snark,
    universality: VerifierUniversality,
    input: AggregatorCircuitInput,
) -> AggregationCircuit
where
    AS: for<'a> Halo2KzgAccumulationScheme<'a>,
{
    // This builder can be used to instantiate the custom circuit and then will be passed to the aggregation circuit.
    let mut builder = BaseCircuitBuilder::<Fr>::from_stage(stage).use_params(config_params.into());

    let (builder, previous_instances, preprocessed) = verify_snarks::<AS>(
        &mut builder,
        params,
        [base_proof, voter_proof],
        universality,
    );

    let range = builder.range_chip();
    let biguint_chip = BigUintChip::<Fr>::construct(&range, input.limb_bit_len);

    // 1. Constrain all constants
    // membership_root
    builder
        .main(0)
        .constrain_equal(&previous_instances[0][0], &previous_instances[1][0]);
    builder.assigned_instances[0].append(&mut vec![previous_instances[0][0].clone()]);

    // proposal_id
    builder
        .main(0)
        .constrain_equal(&previous_instances[0][1], &previous_instances[1][1]);
    builder.assigned_instances[0].append(&mut vec![previous_instances[0][1].clone()]);

    builder.assigned_instances[0].append(&mut vec![previous_instances[0][2].clone()]);

    // n
    for i in 0..2 {
        builder
            .main(0)
            .constrain_equal(&previous_instances[0][3 + i], &previous_instances[1][2 + i]);
    }
    builder.assigned_instances[0].append(&mut vec![
        previous_instances[0][3].clone(),
        previous_instances[0][4].clone(),
    ]);

    // g
    for i in 0..2 {
        builder
            .main(0)
            .constrain_equal(&previous_instances[0][5 + i], &previous_instances[1][4 + i]);
    }
    builder.assigned_instances[0].append(&mut vec![
        previous_instances[0][5].clone(),
        previous_instances[0][6].clone(),
    ]);

    let n_overflow = OverflowInteger::<Fr>::new(
        [previous_instances[0][3], previous_instances[0][4]].to_vec(),
        input.limb_bit_len,
    );
    let n_biguint = to_biguint(n_overflow.clone(), input.limb_bit_len);
    let n_assigned = AssignedBigUint::<Fr, Fresh>::new(n_overflow, Value::known(n_biguint));

    let g_overflow = OverflowInteger::<Fr>::new(
        [previous_instances[0][5], previous_instances[0][6]].to_vec(),
        input.limb_bit_len,
    );
    let g_biguint = to_biguint(g_overflow.clone(), input.limb_bit_len);
    let g_assigned = AssignedBigUint::<Fr, Fresh>::new(g_overflow, Value::known(g_biguint));

    let pk_enc = EncryptionPublicKeyAssigned {
        n: n_assigned,
        g: g_assigned,
    };

    let paillier_chip = PaillierChip::construct(&biguint_chip, input.enc_bit_len);

    let mut vote_new_enc = Vec::<AssignedBigUint<Fr, Fresh>>::new();

    let mut x = 6;
    let mut y = 10;

    for _ in 0..5 {
        println!("x: {}, y: {}", x, y);

        let vote_enc_old_overflow = OverflowInteger::<Fr>::new(
            previous_instances[0][x + 1..y + 1].to_vec(),
            input.limb_bit_len,
        );
        let vote_enc_old_biguint = to_biguint(vote_enc_old_overflow.clone(), input.limb_bit_len);
        let vote_enc_old = AssignedBigUint::<Fr, Fresh>::new(
            vote_enc_old_overflow,
            Value::known(vote_enc_old_biguint),
        );

        let user_vote_enc_overflow =
            OverflowInteger::<Fr>::new(previous_instances[1][x..y].to_vec(), input.limb_bit_len);
        let user_vote_enc_biguint = to_biguint(user_vote_enc_overflow.clone(), input.limb_bit_len);
        let user_vote_enc = AssignedBigUint::<Fr, Fresh>::new(
            user_vote_enc_overflow,
            Value::known(user_vote_enc_biguint),
        );

        vote_new_enc.push(
            paillier_chip
                .add(builder.main(0), &pk_enc, &vote_enc_old, &user_vote_enc)
                .unwrap(),
        );

        x = y;
        y += 4;
    }

    let mut hasher = PoseidonHasher::<Fr, 3, 2>::new(OptimizedPoseidonSpec::new::<8, 57, 0>());
    hasher.initialize_consts(builder.main(0), &range.gate);

    let low_leaf_proof: Vec<AssignedValue<Fr>> = input
        .low_leaf_proof
        .into_iter()
        .map(|x| builder.main(0).load_witness(x))
        .collect();
    let low_leaf_proof_helper: Vec<AssignedValue<Fr>> = input
        .low_leaf_proof_helper
        .into_iter()
        .map(|x| builder.main(0).load_witness(x))
        .collect();
    let new_root = builder.main(0).load_witness(input.new_root);
    builder.assigned_instances[0].insert(4, new_root.clone());
    let new_leaf_index = builder.main(0).load_witness(input.new_leaf_index);
    let new_leaf_proof: Vec<AssignedValue<Fr>> = input
        .new_leaf_proof
        .into_iter()
        .map(|x| builder.main(0).load_witness(x))
        .collect();
    let new_leaf_proof_helper: Vec<AssignedValue<Fr>> = input
        .new_leaf_proof_helper
        .into_iter()
        .map(|x| builder.main(0).load_witness(x))
        .collect();
    let is_new_leaf_largest = builder.main(0).load_witness(input.is_new_leaf_largest);
    let low_leaf = IndexedMerkleTreeLeaf::<Fr>::new(
        builder.main(0).load_witness(input.low_leaf.val),
        builder.main(0).load_witness(input.low_leaf.next_val),
        builder.main(0).load_witness(input.low_leaf.next_idx),
    );
    let new_leaf = IndexedMerkleTreeLeaf::<Fr>::new(
        builder.main(0).load_witness(input.new_leaf.val),
        builder.main(0).load_witness(input.new_leaf.next_val),
        builder.main(0).load_witness(input.new_leaf.next_idx),
    );

    insert_leaf::<Fr, 3, 2>(
        builder.main(0),
        &range,
        &hasher,
        &previous_instances[0][2],
        &low_leaf,
        &low_leaf_proof[0..],
        &low_leaf_proof_helper[0..],
        &new_root,
        &new_leaf,
        &new_leaf_index,
        &new_leaf_proof[0..],
        &new_leaf_proof_helper[0..],
        &is_new_leaf_largest,
    );

    AggregationCircuit {
        builder: builder.clone(),
        previous_instances,
        preprocessed,
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::BorrowMut;

    use crate::aggregator::base_aggregator;
    use crate::aggregator::base_circuit::base_circuit;
    use crate::aggregator::base_circuit::BaseCircuitInput;
    use crate::aggregator::recursion::recursion::gen_recursion_pk;
    use crate::aggregator::utils::generate_idx_input;
    use crate::merkletree::native::MerkleTree;
    use crate::utils::{generate_circuit_params, run};
    use crate::voter_circuit::{
        pse::VoterCircuit, voter_circuit, EncryptionPublicKey, VoterCircuitInput,
    };

    use ark_std::{end_timer, start_timer};
    use halo2_base::gates::circuit::builder::BaseCircuitBuilder;
    use halo2_base::gates::circuit::BaseCircuitParams;
    use halo2_base::gates::RangeChip;
    use halo2_base::halo2_proofs::arithmetic::Field;

    use halo2_base::AssignedValue;
    use halo2_base::{
        gates::circuit::CircuitBuilderStage, halo2_proofs::halo2curves::grumpkin::Fq as Fr,
        utils::fs::gen_srs,
    };
    use num_bigint::{BigUint, RandBigInt};
    use num_traits::{One, Zero};

    use paillier_chip::paillier::paillier_enc_native;
    use pse_poseidon::Poseidon;
    use rand::thread_rng;
    use snark_verifier_sdk::{
        gen_pk,
        halo2::{
            aggregation::{AggregationConfigParams, VerifierUniversality},
            gen_snark_shplonk,
        },
        SHPLONK,
    };

    #[test]
    fn test_voter_aggregation() {
        const T: usize = 3;
        const RATE: usize = 2;
        const R_F: usize = 8;
        const R_P: usize = 57;
        const ENC_BIT_LEN: usize = 176;
        const LIMB_BIT_LEN: usize = 88;

        let mut rng = thread_rng();

        let treesize = u32::pow(2, 3);

        let vote = [
            BigUint::one(),
            BigUint::zero(),
            BigUint::zero(),
            BigUint::zero(),
            BigUint::zero(),
        ]
        .to_vec();

        let n = rng.gen_biguint(ENC_BIT_LEN as u64);
        let g = rng.gen_biguint(ENC_BIT_LEN as u64);
        let pk_enc = EncryptionPublicKey {
            n: n.clone(),
            g: g.clone(),
        };

        let mut r_enc = Vec::<BigUint>::new();
        let mut vote_enc = Vec::<BigUint>::new();
        let mut init_vote_enc = Vec::<BigUint>::new();
        let mut vote_enc_old = Vec::<BigUint>::new();
        for i in 0..5 {
            r_enc.push(rng.gen_biguint(ENC_BIT_LEN as u64));
            vote_enc.push(paillier_enc_native(&n, &g, &vote[i], &r_enc[i]));
            init_vote_enc.push(paillier_enc_native(&n, &g, &BigUint::zero(), &r_enc[i]));
            vote_enc_old.push(paillier_enc_native(&n, &g, &BigUint::zero(), &r_enc[i]));
        }

        let mut native_hasher = Poseidon::<Fr, T, RATE>::new(R_F, R_P);

        let mut membership_leaves = Vec::<Fr>::new();

        let pk_voter = vec![Fr::random(rng.clone()), Fr::random(rng.clone())];

        for i in 0..treesize {
            if i == 0 {
                native_hasher.update(&[pk_voter[0], pk_voter[1]]);
            } else {
                native_hasher.update(&[Fr::ZERO]);
            }
            membership_leaves.push(native_hasher.squeeze_and_reset());
        }
        let membership_tree =
            MerkleTree::<Fr, T, RATE>::new(&mut native_hasher, membership_leaves.clone()).unwrap();

        let mut native_hasher2 = Poseidon::<Fr, T, RATE>::new(R_F, R_P);
        let mut nullifier_leaves = Vec::<Fr>::new();
        for i in 0..treesize {
            if i == 0 {
                native_hasher2.update(&[Fr::ZERO, Fr::ZERO, Fr::ZERO]);
                nullifier_leaves.push(native_hasher2.squeeze_and_reset());
            } else {
                nullifier_leaves.push(Fr::from(0));
            }
        }

        let membership_root = membership_tree.get_root();

        let nullifier_tree =
            MerkleTree::<Fr, T, RATE>::new(&mut native_hasher2, nullifier_leaves.clone()).unwrap();

        let init_nullifier_root = nullifier_tree.get_root();

        let (membership_proof, membership_proof_helper) = membership_tree.get_proof(0);

        let base_proof = run::<BaseCircuitInput<Fr>>(
            16,
            15,
            base_circuit,
            BaseCircuitInput {
                membership_root,
                proposal_id: Fr::one(),
                pk_enc: pk_enc.clone(),
                init_vote_enc: vote_enc_old,
                init_nullifier_root,
                r_enc: r_enc.clone(),
                limb_bit_len: LIMB_BIT_LEN,
                enc_bit_len: ENC_BIT_LEN,
            },
        );

        let voter_proof = run::<VoterCircuitInput<Fr>>(
            16,
            15,
            voter_circuit,
            VoterCircuitInput {
                membership_root,
                pk_enc,
                vote_enc,
                proposal_id: Fr::one(),
                vote,
                r_enc: r_enc.clone(),
                pk_voter,
                membership_proof,
                membership_proof_helper,
            },
        );

        let k = 16u32;
        let lookup_bits = (k - 1) as usize;
        let params = gen_srs(k);

        let input = generate_idx_input(n.clone(), g.clone());

        let mut agg_circuit = base_aggregator::<SHPLONK>(
            CircuitBuilderStage::Keygen,
            AggregationConfigParams {
                degree: k,
                lookup_bits,
                ..Default::default()
            },
            &params,
            base_proof.clone(),
            voter_proof.clone(),
            VerifierUniversality::Full,
            input.clone(),
        );
        let agg_config = agg_circuit.calculate_params(Some(10));

        let start0 = start_timer!(|| "gen vk & pk");
        let pk = gen_pk(&params, &agg_circuit, None);
        end_timer!(start0);
        let break_points = agg_circuit.break_points();
        println!("keygen done");

        let agg_circuit = base_aggregator::<SHPLONK>(
            CircuitBuilderStage::Prover,
            agg_config,
            &params,
            base_proof.clone(),
            voter_proof.clone(),
            VerifierUniversality::Full,
            input,
        )
        .use_break_points(break_points.clone());
        println!("prover done");

        let _snark = gen_snark_shplonk(&params, &pk, agg_circuit, None::<&str>);
        println!("snark success");
    }

    #[test]
    fn test_step_aggregation() {
        const VOTER_K: usize = 15;
        const VOTER_LOOKUP_BITS: usize = 8;
        const RECURSION_K: usize = 14;
        const RECURSION_LOOKUP_BITS: usize = 8;

        let voter_config = generate_circuit_params(VOTER_K, VOTER_LOOKUP_BITS);
        let mut voter_builder = BaseCircuitBuilder::new(false).use_params(voter_config.clone());
        let range = RangeChip::<Fr>::new(VOTER_LOOKUP_BITS, voter_builder.lookup_manager().clone());
        voter_circuit(
            voter_builder.pool(0).main().borrow_mut(),
            &range,
            VoterCircuitInput::default(),
            &mut Vec::<AssignedValue<Fr>>::with_capacity(26),
        );
        let voter_params = gen_srs(VOTER_K as u32);
        let voter_pk = gen_pk(
            &voter_params,
            &(VoterCircuit {
                builder: voter_builder,
            }),
            None,
        );

        let recursion_params = gen_srs(RECURSION_K as u32);
        let recursion_pk = gen_recursion_pk::<VoterCircuit>(
            &recursion_params,
            &voter_params,
            voter_pk.get_vk(),
            BaseCircuitParams {
                k: RECURSION_K,
                num_advice_per_phase: vec![4],
                num_lookup_advice_per_phase: vec![1],
                num_fixed: 1,
                lookup_bits: Some(RECURSION_LOOKUP_BITS),
                num_instance_columns: 1,
            },
            voter_config.try_into().unwrap(),
        );
    }
}
