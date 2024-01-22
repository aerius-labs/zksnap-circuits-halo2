pub mod base_circuit;
pub mod utils;
pub mod verifier;

use crate::voter_circuit::EncryptionPublicKey;
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

use paillier_chip::{
    big_uint::{chip::BigUintChip, AssignedBigUint, Fresh},
    paillier::PaillierChip,
};
use snark_verifier_sdk::{
    halo2::aggregation::{
        AggregationConfigParams, Halo2KzgAccumulationScheme, VerifierUniversality,
    },
    Snark,
};

use self::verifier::{verify_snarks, AggregationCircuit};
use crate::aggregator::utils::to_bigUint;
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
    pub pk_enc: EncryptionPublicKey,
    // Utils
    pub limb_bit_len: usize,
    pub enc_bit_len: usize,
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

pub fn aggregator<AS>(
    stage: CircuitBuilderStage,
    config_params: AggregationConfigParams,
    params: &ParamsKZG<Bn256>,
    earlier_proof: Snark,
    voter_proof: Snark,
    universality: VerifierUniversality,
    input: AggregatorCircuitInput,
) -> AggregationCircuit
where
    AS: for<'a> Halo2KzgAccumulationScheme<'a>,
{
    // This builder can be used to instantiate the custom circuit and then will be passed to the aggregation circuit.
    let mut builder = BaseCircuitBuilder::<Fr>::from_stage(stage).use_params(config_params.into());

    // TODO: can this be done at the last?
    let (builder, previous_instances, preprocessed) = verify_snarks::<AS>(
        &mut builder,
        params,
        [earlier_proof, voter_proof],
        universality,
    );

    let range = builder.range_chip();
    let ctx = builder.main(0);
    let biguint_chip = BigUintChip::<Fr>::construct(&range, input.limb_bit_len);

    // 1. Constrain all constants
    // membership_root
    ctx.constrain_equal(&previous_instances[0][0], &previous_instances[1][0]);
    // proposal_id
    ctx.constrain_equal(&previous_instances[0][1], &previous_instances[1][1]);
    // n
    for i in 0..2 {
        ctx.constrain_equal(&previous_instances[0][3 + i], &previous_instances[1][3 + i]);
    }
    // g
    for i in 0..2 {
        ctx.constrain_equal(&previous_instances[0][4 + i], &previous_instances[1][4 + i]);
    }

    let overflow_n = OverflowInteger::<Fr>::new(
        [previous_instances[0][3], previous_instances[0][4]].to_vec(),
        input.limb_bit_len,
    );
    let n_biguint = to_bigUint(overflow_n.clone(), input.limb_bit_len);
    let n_assigned = AssignedBigUint::new(overflow_n, Value::known(n_biguint));

    let overflow_g = OverflowInteger::<Fr>::new(
        [previous_instances[0][5], previous_instances[0][6]].to_vec(),
        input.limb_bit_len,
    );
    let g_biguint = to_bigUint(overflow_g.clone(), input.limb_bit_len);
    let g_assigned = AssignedBigUint::new(overflow_g, Value::known(g_biguint));

    // TODO: constrain these with previous_instances

    let paillier_chip = PaillierChip::construct(
        &biguint_chip,
        input.enc_bit_len,
        &n_assigned,
        input.pk_enc.n.clone(),
        &g_assigned,
    );

    let mut vote_new_enc = Vec::<AssignedBigUint<Fr, Fresh>>::new();
    let mut x = 0;
    let mut y = 4;
    for i in 0..5 {
        let vote_enc_old_int =
            OverflowInteger::<Fr>::new(previous_instances[0][x..y].to_vec(), input.limb_bit_len);
        let vote_enc_old_biguint = to_bigUint(vote_enc_old_int, input.limb_bit_len);
        let vote_enc_old = biguint_chip
            .assign_integer(ctx, Value::known(vote_enc_old_biguint), input.limb_bit_len)
            .unwrap();

        let vote_enc_int = OverflowInteger::<Fr>::new(
            previous_instances[1][6 + i..9 + i].to_vec(),
            input.limb_bit_len,
        );
        let vote_enc_biguint = to_bigUint(vote_enc_int, input.limb_bit_len);
        let vote_enc = biguint_chip
            .assign_integer(ctx, Value::known(vote_enc_biguint), input.limb_bit_len)
            .unwrap();

        vote_new_enc.push(paillier_chip.add(ctx, &vote_enc_old, &vote_enc).unwrap());
        x = y;
        y += 4;
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
    println!("indexed merkle tree ");

    insert_leaf::<Fr, 3, 2>(
        ctx,
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
    println!("done");

    AggregationCircuit {
        builder: builder.clone(),
        previous_instances,
        preprocessed,
    }
}

#[cfg(test)]
mod tests {
    use crate::aggregator::base_circuit::base_circuit;
    use crate::aggregator::utils::generate_idx_input;
    use crate::aggregator::{aggregator, base_circuit::BaseCircuitInput};
    use crate::utils::run;
    use crate::voter_circuit::{
        utils::{paillier_enc_native, MerkleTree},
        voter_circuit, VoterInput,
    };
    use ark_std::{end_timer, start_timer};
    use halo2_base::halo2_proofs::arithmetic::Field;

    use halo2_base::{
        gates::circuit::CircuitBuilderStage,
        halo2_proofs::halo2curves::grumpkin::Fq as Fr,
        utils::{biguint_to_fe, fs::gen_srs},
    };
    use num_bigint::{BigUint, RandBigInt};
    use num_traits::{One, Zero};

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
        const ENC_BIT_LEN: usize = 128;
        const LIMB_BIT_LEN: usize = 64;

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

        let mut r_enc = Vec::<BigUint>::new();
        let mut vote_enc = Vec::<Vec<u32>>::new();
        let mut vote_enc_old = Vec::<Vec<u32>>::new();
        for i in 0..5 {
            r_enc.push(rng.gen_biguint(ENC_BIT_LEN as u64));
            vote_enc.push(paillier_enc_native(&n, &g, &vote[i], &r_enc[i]).to_u32_digits());
            vote_enc_old
                .push(paillier_enc_native(&n, &g, &BigUint::zero(), &r_enc[i]).to_u32_digits());
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

        let vote = vote.iter().map(|x| biguint_to_fe(x)).collect();

        let r_enc: Vec<Vec<u32>> = r_enc.iter().map(|x| x.to_u32_digits()).collect();
        let base_proof = run::<BaseCircuitInput<Fr>>(
            16,
            15,
            base_circuit,
            BaseCircuitInput {
                membership_root,
                proposal_id: Fr::one(),
                n: n.to_u32_digits(),
                g: g.to_u32_digits(),
                init_vote_enc: vote_enc_old,
                init_nullifier_root,
                r_enc: r_enc.clone(),
                limb_bit_len: LIMB_BIT_LEN,
                enc_bit_len: ENC_BIT_LEN,
            },
        );
        let voter_proof = run::<VoterInput<Fr>>(
            16,
            15,
            voter_circuit,
            VoterInput {
                membership_root,
                n: n.to_u32_digits(),
                g: g.to_u32_digits(),
                vote_enc,
                nullifier: nullifier_leaves,
                proposal_id: Fr::one(),
                vote,
                r_enc: r_enc.clone(),
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

        let input = generate_idx_input(n.clone(), g.clone());

        let mut agg_circuit = aggregator::<SHPLONK>(
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

        let agg_circuit = aggregator::<SHPLONK>(
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
}
