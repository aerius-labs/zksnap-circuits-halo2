pub mod base_circuit;
pub mod verifier;
use std::borrow::BorrowMut;

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
    utils::{fe_to_biguint, BigPrimeField, ScalarField},
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

use indexed_merkle_tree_halo2::indexed_merkle_tree::{insert_leaf, IndexedMerkleTreeLeaf};
//use indexed_merkle_tree_halo2::utils::IndexedMerkleTreeLeaf;
use self::verifier::{verify_snarks, AggregationCircuit};
use halo2_base::poseidon::hasher::PoseidonHasher;
use snark_verifier_sdk::halo2::OptimizedPoseidonSpec;

const LIMB_BIT_LEN: usize = 264;
const ENC_BIT_LEN: usize = 4;

pub struct IndexedMerkleInput {
    low_leaf: IndexedMerkleTreeLeaf<Fr>,
    low_leaf_proof: Vec<Fr>,
    low_leaf_proof_helper: Vec<Fr>,
    new_root: Fr,
    new_leaf: IndexedMerkleTreeLeaf<Fr>,
    new_leaf_index: Fr,
    new_leaf_proof: Vec<Fr>,
    new_leaf_proof_helper: Vec<Fr>,
    is_new_leaf_largest: Fr,
}

pub fn voter_circuit_wrapper(
    builder: &mut BaseCircuitBuilder<Fr>,
    input: DummyCircuitInput,
    make_public: &mut Vec<AssignedValue<Fr>>,
){
        let range =builder.range_chip();
    let ctx=builder.main(0);
    
    let biguint_chip = BigUintChip::<Fr>::construct(&range, LIMB_BIT_LEN);
    //todo
    let n_biguint = input.n;
    // let n_f=*base_pub_input[3].value().to_u64_limbs(num_limbs, bit_len);

    let n_assigned = biguint_chip
        .assign_integer(ctx, Value::known(n_biguint.clone()), ENC_BIT_LEN)
        .unwrap();
    let g_assigned = biguint_chip
        .assign_integer(
            ctx,
            Value::known(input.g),
            ENC_BIT_LEN,
        )
        .unwrap();
    let paillier_chip = PaillierChip::construct(
        &biguint_chip,
        ENC_BIT_LEN,
        &n_assigned,
        n_biguint,
        &g_assigned,
    );


}

pub fn aggregator<AS>(
    stage: CircuitBuilderStage,
    config_params: AggregationConfigParams,
    params: &ParamsKZG<Bn256>,
    snarks: impl IntoIterator<Item = Snark> + Clone,
    universality: VerifierUniversality,
    input: IndexedMerkleInput,
) -> AggregationCircuit
where
    AS: for<'a> Halo2KzgAccumulationScheme<'a>,
{
    // This builder can be used to instantiate the custom circuit and then will be passed to the aggregation circuit.
    let mut builder = BaseCircuitBuilder::<Fr>::from_stage(stage).use_params(config_params.into());
    let snarks_clone = snarks.clone();
    let (builder, previous_instances, preprocessed) =
        verify_snarks::<AS>(&mut builder, params, snarks.into_iter(), universality);

    let range = builder.range_chip();
    let ctx = builder.main(0);
    // TODO: implement the custom circuit.

    let mut snark_iter = snarks_clone.into_iter();
    let base_snark = snark_iter.nth(0).unwrap();
    let voter_snark = snark_iter.nth(1).unwrap();

    let mut public_var = Vec::<_>::new();

    let base_instances_vec_size = base_snark.instances.len();

    let base_pub_input: Vec<AssignedValue<_>> = (0..4)
        .map(|j| ctx.load_witness(base_snark.instances[0][j]))
        .collect();
    let voter_pub_input: Vec<AssignedValue<_>> = (0..4)
        .map(|j| ctx.load_witness(voter_snark.instances[0][j]))
        .collect();

    // previous_instances[0][0..4] copy constraint base_pub_input[0..4]
    // previous_instances[base_instaces_vec_size][0..4] copy constraint voter_pub_input[0..4]

    for i in 0..4 {
        ctx.constrain_equal(&base_pub_input[i], &voter_pub_input[i]);
        public_var.push(base_pub_input[i]);
    }

    let biguint_chip = BigUintChip::<Fr>::construct(&range, LIMB_BIT_LEN);
    //todo
    let n_biguint = fe_to_biguint(base_pub_input[3].value());
    // let n_f=*base_pub_input[3].value().to_u64_limbs(num_limbs, bit_len);

    let n_assigned = biguint_chip
        .assign_integer(ctx, Value::known(n_biguint.clone()), ENC_BIT_LEN)
        .unwrap();
    let g_assigned = biguint_chip
        .assign_integer(
            ctx,
            Value::known(fe_to_biguint(base_pub_input[0].value())),
            ENC_BIT_LEN,
        )
        .unwrap();

    let paillier_chip = PaillierChip::construct(
        &biguint_chip,
        ENC_BIT_LEN,
        &n_assigned,
        n_biguint,
        &g_assigned,
    );
    for i in 0..=5 {
        let vote_enc_old = biguint_chip
            .assign_integer(
                ctx,
                Value::known(fe_to_biguint(base_pub_input[12 + i].value())),
                ENC_BIT_LEN,
            )
            .unwrap();

        let vote_enc = biguint_chip
            .assign_integer(
                ctx,
                Value::known(fe_to_biguint(voter_pub_input[6 + i].value())),
                ENC_BIT_LEN,
            )
            .unwrap();

        let vote_new_enc = paillier_chip.add(ctx, &vote_enc_old, &vote_enc).unwrap();
        let expt_vote_new_enc = biguint_chip
            .assign_integer(
                ctx,
                Value::known(fe_to_biguint(voter_pub_input[12 + i].value())),
                LIMB_BIT_LEN,
            )
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
    insert_leaf::<Fr, 3, 2>(
        ctx,
        &range,
        &hasher,
        &base_pub_input[0],
        &input.low_leaf,
        &low_leaf_proof[0..],
        &low_leaf_proof_helper[0..],
        &new_root,
        &input.new_leaf,
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
    use crate::merkletree::verify_merkle_proof;
    use crate::utils::run;
    use ark_std::{end_timer, start_timer};
    use halo2_base::{
        gates::circuit::{builder::BaseCircuitBuilder, CircuitBuilderStage},
        halo2_proofs::halo2curves::grumpkin::Fq as Fr,
        utils::fs::gen_srs,
        AssignedValue,
    };
    use serde::Deserialize;
    use snark_verifier_sdk::{
        gen_pk,
        halo2::{
            aggregation::{AggregationConfigParams, VerifierUniversality},
            gen_snark_shplonk,
        },
        SHPLONK,
    };

    use super::aggregator;

    #[derive(Deserialize)]
    struct DummyCircuitInput {
        a: Fr,
        b: Fr,
        c: Fr,
        res: Fr,
    }

    fn dummy_voter_circuit(
        builder: &mut BaseCircuitBuilder<Fr>,
        input: DummyCircuitInput,
        make_public: &mut Vec<AssignedValue<Fr>>,
    ) {
        let ctx = builder.main(0);

        let a = ctx.load_witness(input.a);
        let b = ctx.load_witness(input.b);
        let c = ctx.load_witness(input.c);
        let res = ctx.load_witness(input.res);

        ctx.assign_region([c, a, b, res], [0]);

        make_public.push(res)
    }

    fn dummy_base_circuit(
        builder: &mut BaseCircuitBuilder<Fr>,
        input: DummyCircuitInput,
        make_public: &mut Vec<AssignedValue<Fr>>,
    ) {
        let ctx = builder.main(0);

        let a = ctx.load_witness(input.a);
        let b = ctx.load_witness(input.b);
        let c = ctx.load_witness(input.c);
        let res = ctx.load_witness(input.res);

        ctx.assign_region([a, b, c, res], [0]);

        make_public.push(res)
    }

    #[test]
    fn test_simple_aggregation() {
        let voter_proof = run::<DummyCircuitInput>(
            9,
            0,
            dummy_voter_circuit,
            DummyCircuitInput {
                a: Fr::from(1u64),
                b: Fr::from(2u64),
                c: Fr::from(3u64),
                res: Fr::from(5u64),
            },
        );
        let base_proof = run::<DummyCircuitInput>(
            9,
            0,
            dummy_base_circuit,
            DummyCircuitInput {
                a: Fr::from(1u64),
                b: Fr::from(2u64),
                c: Fr::from(3u64),
                res: Fr::from(7u64),
            },
        );

        let k = 16u32;
        let lookup_bits = (k - 1) as usize;

        let params = gen_srs(k);

        let mut agg_circuit = aggregator::<SHPLONK>(
            CircuitBuilderStage::Keygen,
            AggregationConfigParams {
                degree: k,
                lookup_bits,
                ..Default::default()
            },
            &params,
            vec![voter_proof.clone(), base_proof.clone()],
            VerifierUniversality::Full,
        );
        let agg_config = agg_circuit.calculate_params(Some(10));

        let start0 = start_timer!(|| "gen vk & pk");
        let pk = gen_pk(&params, &agg_circuit, None);
        end_timer!(start0);
        let break_points = agg_circuit.break_points();

        let agg_circuit = aggregator::<SHPLONK>(
            CircuitBuilderStage::Prover,
            agg_config,
            &params,
            vec![voter_proof.clone(), base_proof.clone()],
            VerifierUniversality::Full,
        )
        .use_break_points(break_points.clone());

        let _snark = gen_snark_shplonk(&params, &pk, agg_circuit, None::<&str>);
        println!("snark success");
    }
}
