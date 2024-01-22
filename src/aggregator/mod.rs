pub mod base_circuit;
pub mod utils;
pub mod verifier;

use crate::voter_circuit::{ voter_circuit, EncryptionPublicKey, VoterCircuitInput };
use halo2_base::{
    gates::circuit::{ builder::BaseCircuitBuilder, CircuitBuilderStage },
    halo2_proofs::{
        circuit::Value,
        halo2curves::{ bn256::Bn256, grumpkin::Fq as Fr },
        poly::kzg::commitment::ParamsKZG,
    },
    utils::{ biguint_to_fe, fe_to_biguint, BigPrimeField, ScalarField },
    AssignedValue,
};
use num_bigint::BigUint;
use paillier_chip::{ big_uint::{ chip::BigUintChip, AssignedBigUint }, paillier::PaillierChip };
use snark_verifier_sdk::{
    halo2::aggregation::{
        AggregationConfigParams,
        Halo2KzgAccumulationScheme,
        VerifierUniversality,
    },
    Snark,
};

use self::verifier::{ verify_snarks, AggregationCircuit };
use halo2_base::poseidon::hasher::PoseidonHasher;
use indexed_merkle_tree_halo2::indexed_merkle_tree::{ insert_leaf, IndexedMerkleTreeLeaf };
use serde::Deserialize;
use snark_verifier_sdk::halo2::OptimizedPoseidonSpec;

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

// pub struct VoterInput<F: BigPrimeField> {
//     membership_root: F,
//     pk_enc: EncryptionPublicKey,
//     vote_enc: Vec<Vec<u32>>,
//     nullifier: Vec<F>,
//     proposal_id: F,
//     nullifier_old: Vec<u32>,
//     nullifier_new: Vec<u32>,
//     vote: Vec<F>,
//     vote_enc_old: Vec<Vec<u32>>,
//     r_enc: Vec<Vec<u32>>,
//     pk_voter: Vec<F>,
//     membership_proof: Vec<F>,
//     membership_proof_helper: Vec<F>,
//     limb_bit_len: usize,
//     enc_bit_len: usize,
// }

// pub fn voter_circuit_wrapper(
//     builder: &mut BaseCircuitBuilder<Fr>,
//     input: VoterInput<Fr>,
//     make_public: &mut Vec<AssignedValue<Fr>>
// ) {
//     let range = builder.range_chip();
//     let ctx = builder.main(0);
//     let mut public_input = Vec::<AssignedValue<Fr>>::new();

//     let membership_root = ctx.load_witness(input.membership_root);
//     public_input.push(membership_root);

//     let n = ctx.load_witness(input.pk_enc.n);
//     public_input.push(n);
//     let g = ctx.load_witness(input.pk_enc.g);
//     public_input.push(g);
//     let proposal_id = ctx.load_witness(input.proposal_id);
//     public_input.push(proposal_id);

//     let mut hasher = PoseidonHasher::<Fr, 3, 2>::new(OptimizedPoseidonSpec::new::<8, 57, 0>());

//     hasher.initialize_consts(ctx, &range.gate);
//     let pk_enc = EncryptionPublicKey {
//         n: fe_to_biguint(&input.pk_enc.n),
//         g: fe_to_biguint(&input.pk_enc.g),
//     };
//     let vote_enc: Vec<BigUint> = input.vote_enc
//         .iter()
//         .map(|x| BigUint::from_slice(x))
//         .collect();
//     //vote to F
//     let vote: Vec<BigUint> = input.vote
//         .iter()
//         .map(|x| fe_to_biguint(x))
//         .collect();
//     let r_enc: Vec<BigUint> = input.r_enc
//         .iter()
//         .map(|x| BigUint::from_slice(x))
//         .collect();
//     println!("r_enc voter={:?}", r_enc);
//     let inputs = VoterCircuitInput::<Fr>::new(
//         input.membership_root,
//         pk_enc,
//         vote_enc.clone(),
//         input.nullifier,
//         input.proposal_id,
//         vote,
//         r_enc,
//         input.pk_voter,
//         input.membership_proof,
//         input.membership_proof_helper
//     );
//     let vote_enc_old: Vec<AssignedValue<Fr>> = (0..input.vote_enc.len())
//         .map(|i| ctx.load_witness(biguint_to_fe(&BigUint::from_slice(&input.vote_enc_old[i]))))
//         .collect();
//     for i in 0..5 {
//         println!("vote_enc_old voter circuit={:?}", fe_to_biguint(vote_enc_old[i].value()));
//     }

//     let vote_enc_assign: Vec<AssignedValue<Fr>> = (0..input.vote_enc.len())
//         .map(|i| ctx.load_witness(biguint_to_fe(&vote_enc[i])))
//         .collect();
//     for i in 0..5 {
//         println!("vote_enc voter circuit={:?}", fe_to_biguint(vote_enc_assign[i].value()));
//     }

//     public_input.extend(vote_enc_old.clone());

//     public_input.extend(vote_enc_assign.clone());

//     let nullifier_old = ctx.load_witness(biguint_to_fe(&BigUint::from_slice(&input.nullifier_old)));
//     public_input.push(nullifier_old);
//     let nullifier_new = ctx.load_witness(biguint_to_fe(&BigUint::from_slice(&input.nullifier_new)));
//     public_input.push(nullifier_new);

//     voter_circuit::<Fr, 3, 2>(ctx, &range, &hasher, inputs, input.limb_bit_len, input.enc_bit_len);

//     builder.assigned_instances[0].append(&mut public_input);
// }

#[derive(Debug, Clone)]
pub struct AggregatorCircuitInput {
    pub pk_enc: EncryptionPublicKey,
    // Utils
    pub limb_bit_len: usize,
    pub enc_bit_len: usize,
}

pub fn aggregator<AS>(
    stage: CircuitBuilderStage,
    config_params: AggregationConfigParams,
    params: &ParamsKZG<Bn256>,
    earlier_proof: Snark,
    voter_proof: Snark,
    universality: VerifierUniversality,
    input: AggregatorCircuitInput
) -> AggregationCircuit
    where AS: for<'a> Halo2KzgAccumulationScheme<'a>
{
    // This builder can be used to instantiate the custom circuit and then will be passed to the aggregation circuit.
    let mut builder = BaseCircuitBuilder::<Fr>::from_stage(stage).use_params(config_params.into());

    // TODO: can this be done at the last?
    let (builder, previous_instances, preprocessed) = verify_snarks::<AS>(
        &mut builder,
        params,
        [earlier_proof, voter_proof],
        universality
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
        ctx.constrain_equal(&previous_instances[0][2 + i], &previous_instances[1][2 + i]);
    }
    // g
    for i in 0..2 {
        ctx.constrain_equal(&previous_instances[0][4 + i], &previous_instances[1][4 + i]);
    }

    let n_assigned = biguint_chip
        .assign_integer(ctx, Value::known(input.pk_enc.n.clone()), input.enc_bit_len)
        .unwrap();
    let g_assigned = biguint_chip
        .assign_integer(ctx, Value::known(input.pk_enc.g.clone()), input.enc_bit_len)
        .unwrap();

    // TODO: constrain these with previous_instances

    let paillier_chip = PaillierChip::construct(
        &biguint_chip,
        input.enc_bit_len,
        &n_assigned,
        input.pk_enc.n.clone(),
        &g_assigned
    );

    // println!("vote_enc_old");
    // for i in 0..5 {
    //     println!(
    //         "{:?}",
    //         biguint_chip
    //             .assign_integer(
    //                 ctx,
    //                 Value::known(fe_to_biguint(base_pub_input[4 + i].value())),
    //                 ENC_BIT_LEN
    //             )
    //             .unwrap()
    //             .value()
    //     );
    // }
    // println!("vote_enc");
    // for i in 0..5 {
    //     println!(
    //         "{:?}",
    //         biguint_chip
    //             .assign_integer(
    //                 ctx,
    //                 Value::known(fe_to_biguint(base_pub_input[9 + i].value())),
    //                 ENC_BIT_LEN
    //             )
    //             .unwrap()
    //             .value()
    //     );
    // }

    // for i in 0..5 {
    //     public_var[4 + i] = voter_pub_input[4 + i];
    //     let vote_enc_old = biguint_chip
    //         .assign_integer(
    //             ctx,
    //             Value::known(fe_to_biguint(base_pub_input[4 + i].value())),
    //             ENC_BIT_LEN
    //         )
    //         .unwrap();

    //     let vote_enc = biguint_chip
    //         .assign_integer(
    //             ctx,
    //             Value::known(fe_to_biguint(voter_pub_input[9 + i].value())),
    //             ENC_BIT_LEN
    //         )
    //         .unwrap();

    //     // println!("vote_enc_old circuit ={:?} \n vote_enc circuit ={:?}\n\n",vote_enc_old.value(),vote_enc.value());

    //     let vote_new_enc = paillier_chip.add(ctx, &vote_enc_old, &vote_enc).unwrap();
    //     public_var[9 + i] = ctx.load_witness(biguint_to_fe(&expt_vote_enc[i].clone()));
    //     let expt_vote_new_enc = biguint_chip
    //         .assign_integer(ctx, Value::known(expt_vote_enc[i].clone()), ENC_BIT_LEN * 2)
    //         .unwrap();
    //     println!("\n pallier add outout = {:?}", vote_new_enc.value());
    //     println!("expected add output\n = {:?}", expt_vote_new_enc.value());

    //     let result = biguint_chip.is_equal_fresh(ctx, &vote_new_enc, &expt_vote_new_enc).unwrap();
    //     let one = ctx.load_constant(Fr::one());

    //     ctx.constrain_equal(&result, &one);
    // }

    // TODO: convert assigned values to assigned biguint
    let old_vote_enc = previous_instances[0][7..27].to_vec();

    let mut hasher = PoseidonHasher::<Fr, 3, 2>::new(OptimizedPoseidonSpec::new::<8, 57, 0>());

    hasher.initialize_consts(ctx, &range.gate);

    let low_leaf_proof: Vec<AssignedValue<Fr>> = input.low_leaf_proof
        .into_iter()
        .map(|x| ctx.load_witness(x))
        .collect();
    let low_leaf_proof_helper: Vec<AssignedValue<Fr>> = input.low_leaf_proof_helper
        .into_iter()
        .map(|x| ctx.load_witness(x))
        .collect();
    let new_root = ctx.load_witness(input.new_root);
    ctx.constrain_equal(&new_root, &voter_pub_input[15]);
    let new_leaf_index = ctx.load_witness(input.new_leaf_index);
    let new_leaf_proof: Vec<AssignedValue<Fr>> = input.new_leaf_proof
        .into_iter()
        .map(|x| ctx.load_witness(x))
        .collect();
    let new_leaf_proof_helper: Vec<AssignedValue<Fr>> = input.new_leaf_proof_helper
        .into_iter()
        .map(|x| ctx.load_witness(x))
        .collect();
    let is_new_leaf_largest = ctx.load_witness(input.is_new_leaf_largest);
    let low_leaf = IndexedMerkleTreeLeaf::<Fr>::new(
        ctx.load_witness(input.low_leaf.val),
        ctx.load_witness(input.low_leaf.next_val),
        ctx.load_witness(input.low_leaf.next_idx)
    );
    let new_leaf = IndexedMerkleTreeLeaf::<Fr>::new(
        ctx.load_witness(input.new_leaf.val),
        ctx.load_witness(input.new_leaf.next_val),
        ctx.load_witness(input.new_leaf.next_idx)
    );

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
        &is_new_leaf_largest
    );

    AggregationCircuit {
        builder: builder.clone(),
        previous_instances,
        preprocessed,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        insert_leaf,
        voter_circuit_wrapper,
        IndexedMerkleLeaf,
        IndexedMerkleTreeLeaf,
        VoterInput,
    };
    use crate::aggregator::base_circuit::base_circuit;
    use crate::aggregator::IndexedMerkleInput;
    use crate::aggregator::{
        aggregator,
        base_circuit::{ BaseCircuitInput, EncryptionPublicKeyU32 },
    };
    use crate::utils::run;
    use crate::voter_circuit::{ utils::{ paillier_enc_native, MerkleTree }, EncryptionPublicKey };
    use ark_std::{ end_timer, start_timer };
    use halo2_base::halo2_proofs::arithmetic::Field;
    use halo2_base::halo2_proofs::halo2curves::ff::PrimeField;
    use halo2_base::halo2_proofs::halo2curves::pasta::pallas;
    use halo2_base::{
        gates::circuit::{ builder::BaseCircuitBuilder, CircuitBuilderStage },
        halo2_proofs::halo2curves::grumpkin::Fq as Fr,
        utils::{ biguint_to_fe, fe_to_biguint, fs::gen_srs },
        AssignedValue,
    };
    use num_bigint::{ BigUint, RandBigInt };
    use num_traits::{ One, Zero };
    use paillier_chip::bench::paillier_enc_add_test;
    use pse_poseidon::Poseidon;
    use rand::thread_rng;
    use serde::Deserialize;
    use snark_verifier_sdk::{
        gen_pk,
        halo2::{
            aggregation::{ AggregationConfigParams, VerifierUniversality },
            gen_snark_shplonk,
        },
        SHPLONK,
    };
    pub fn paillier_add(n: &BigUint, c1: &BigUint, c2: &BigUint) -> BigUint {
        let n2 = n * n;
        (c1 * c2) % n2
    }

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
            BigUint::zero(),
            BigUint::zero(),
            BigUint::zero(),
            BigUint::zero(),
        ].to_vec();

        let n = rng.gen_biguint(ENC_BIT_LEN as u64);
        let g = rng.gen_biguint(ENC_BIT_LEN as u64);

        let mut r_enc = Vec::<BigUint>::new();
        let mut vote_enc = Vec::<Vec<u32>>::new();
        let mut vote_enc_old = Vec::<Vec<u32>>::new();
        for i in 0..5 {
            r_enc.push(rng.gen_biguint(ENC_BIT_LEN as u64));
            vote_enc.push(paillier_enc_native(&n, &g, &vote[i], &r_enc[i]).to_u32_digits());
            vote_enc_old.push(
                paillier_enc_native(&n, &g, &BigUint::zero(), &r_enc[i]).to_u32_digits()
            );
        }
        println!("vote_enc_old  test =");
        for i in 0..5 {
            println!("{:?}", BigUint::from_slice(&vote_enc_old[i]));
        }
        println!("vote_enc  test =");
        for i in 0..5 {
            println!("{:?}", BigUint::from_slice(&vote_enc[i]));
        }
        println!("r_enc test={:?}", r_enc);

        let mut native_hasher = Poseidon::<Fr, T, RATE>::new(R_F, R_P);

        let mut membership_leaves = Vec::<Fr>::new();
        let mut nullifier_leaves = Vec::<Fr>::new();
        let pk_voter = vec![Fr::random(rng.clone()), Fr::random(rng.clone())];

        for i in 0..treesize {
            if i == 0 {
                native_hasher.update(&[pk_voter[0], pk_voter[1]]);
            } else {
                native_hasher.update(&[Fr::ZERO]);
            }
            membership_leaves.push(native_hasher.squeeze_and_reset());
        }

        for i in 0..treesize {
            if i == 0 {
                native_hasher.update(&[Fr::ZERO, Fr::ZERO, Fr::ZERO]);
                nullifier_leaves.push(native_hasher.squeeze_and_reset());
            } else {
                nullifier_leaves.push(Fr::from(0));
            }
        }

        let membership_tree = MerkleTree::<Fr, T, RATE>
            ::new(&mut native_hasher, membership_leaves.clone())
            .unwrap();
        // TODO: see if you can reuse the native hasher.
        // let mut native_hasher2 = Poseidon::<Fr, T, RATE>::new(R_F, R_P);
        let indexed_tree = MerkleTree::<Fr, T, RATE>
            ::new(&mut native_hasher, nullifier_leaves.clone())
            .unwrap();

        let membership_root = membership_tree.get_root();
        let init_nullifier_root = indexed_tree.get_root();

        let (membership_proof, membership_proof_helper) = membership_tree.get_proof(0);

        let new_val = Fr::from(69);
        native_hasher.update(&[Fr::ZERO, new_val, Fr::ONE]);
        nullifier_leaves[0] = native_hasher.squeeze_and_reset();

        let new_indexed_tree = MerkleTree::<Fr, T, RATE>
            ::new(&mut native_hasher, nullifier_leaves.clone())
            .unwrap();

        let pk_enc = EncryptionPublicKeyU32 {
            n: biguint_to_fe(&n),
            g: biguint_to_fe(&g),
        };

        let base_proof = run::<BaseCircuitInput<Fr>>(16, 15, base_circuit, BaseCircuitInput {
            membership_root,
            proposal_id: Fr::one(),
            vote_enc_old: vote_enc_old.clone(),
            vote_enc_new: vote_enc.clone(),
            nullifier_root_old: init_nullifier_root.clone(),
            nullifier_root_new: fe_to_biguint(&new_indexed_tree.get_root()).to_u32_digits(),
            pk_enc: pk_enc.clone(),
        });

        let vote = vote
            .iter()
            .map(|x| biguint_to_fe(x))
            .collect();
        let r_enc = r_enc
            .iter()
            .map(|x| x.to_u32_digits())
            .collect();
        let voter_proof = run::<VoterInput<Fr>>(16, 15, voter_circuit_wrapper, VoterInput {
            membership_root: biguint_to_fe(&membership_root),
            pk_enc: pk_enc.clone(),
            vote_enc: vote_enc.clone(),
            nullifier: leaves,
            proposal_id: Fr::one(),
            nullifier_old: nullifier_root_old,
            nullifier_new: fe_to_biguint(&new_indexed_tree.get_root()).to_u32_digits(),
            vote,
            vote_enc_old: vote_enc_old.clone(),
            r_enc,
            pk_voter,
            membership_proof,
            membership_proof_helper,
            limb_bit_len: LIMB_BIT_LEN,
            enc_bit_len: ENC_BIT_LEN,
        });

        let expt_vote_enc_aggr: Vec<BigUint> = (0..5)
            .map(|i| {
                paillier_add(
                    &fe_to_biguint(&pk_enc.n),
                    &BigUint::from_slice(&vote_enc_old[i]),
                    &BigUint::from_slice(&vote_enc[i])
                )
            })
            .collect();
        println!("expt_vote_enc_aggr=");
        for i in 0..5 {
            println!("{:?}", expt_vote_enc_aggr[i]);
        }

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
            expt_vote_enc_aggr.clone()
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
            expt_vote_enc_aggr
        ).use_break_points(break_points.clone());
        println!("prover done");

        let _snark = gen_snark_shplonk(&params, &pk, agg_circuit, None::<&str>);
        println!("snark success");
    }
}
