use halo2_base::halo2_proofs::arithmetic::Field;
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::halo2_proofs::halo2curves::group::Curve;
use halo2_base::halo2_proofs::halo2curves::secp256k1::{ Fq, Secp256k1, Secp256k1Affine };
use halo2_base::halo2_proofs::halo2curves::secq256k1::Fp;
use halo2_base::utils::{ fe_to_biguint, ScalarField };
use halo2_ecc::*;
use num_bigint::{ BigUint, RandBigInt };
use paillier_chip::paillier::{ paillier_add_native, paillier_enc_native };
use pse_poseidon::Poseidon;
use rand::rngs::OsRng;
use rand::{ thread_rng, Rng };

use indexed_merkle_tree_halo2::utils::{ IndexedMerkleTree, IndexedMerkleTreeLeaf as IMTLeaf };
use voter::merkletree::native::MerkleTree;
use voter::utils::{ gen_test_nullifier, verify_nullifier };
use voter::{ EncryptionPublicKey, VoterCircuitInput };

use crate::state_transition::{ IndexedMerkleTreeInput, StateTransitionInput };

const ENC_BIT_LEN: usize = 176;
const T: usize = 3;
const RATE: usize = 2;
const R_F: usize = 8;
const R_P: usize = 57;

fn generate_voter_circuit_inputs(
    pk_enc: EncryptionPublicKey,
    nullifier: Secp256k1Affine,
    s: Fq,
    c: Fq,
    pk_voter: Secp256k1Affine,
    vote: Vec<Fr>,
    r_enc: Vec<BigUint>,
    members_tree: &MerkleTree<'_, Fr, T, RATE>,
    round: usize
) -> VoterCircuitInput<Fr> {
    let membership_root = members_tree.get_root();
    let (membership_proof, membership_proof_helper) = members_tree.get_proof(round);

    let mut vote_enc = Vec::<BigUint>::with_capacity(vote.len());
    for i in 0..vote.len() {
        vote_enc.push(
            paillier_enc_native(&pk_enc.n, &pk_enc.g, &fe_to_biguint(&vote[i]), &r_enc[i])
        );
    }

    verify_nullifier(&[1u8, 0u8], &nullifier, &pk_voter, &s, &c);

    let input = VoterCircuitInput::new(
        membership_root,
        pk_enc,
        nullifier,
        Fr::from(1u64),
        vote_enc,
        s,
        vote,
        r_enc,
        pk_voter,
        c,
        membership_proof.clone(),
        membership_proof_helper.clone()
    );

    input
}

fn update_idx_leaf(
    leaves: Vec<IMTLeaf<Fr>>,
    new_val: Fr,
    new_val_idx: u64
) -> (Vec<IMTLeaf<Fr>>, usize) {
    let mut nullifier_tree_preimages = leaves.clone();
    let mut low_leaf_idx = 0;
    for (i, node) in leaves.iter().enumerate() {
        if node.next_val == Fr::zero() && i == 0 {
            nullifier_tree_preimages[i + 1].val = new_val;
            nullifier_tree_preimages[i].next_val = new_val;
            nullifier_tree_preimages[i].next_idx = Fr::from((i as u64) + 1);
            low_leaf_idx = i;
            break;
        }
        if node.val < new_val && (node.next_val > new_val || node.next_val == Fr::zero()) {
            nullifier_tree_preimages[new_val_idx as usize].val = new_val;
            nullifier_tree_preimages[new_val_idx as usize].next_val = nullifier_tree_preimages[
                i
            ].next_val;
            nullifier_tree_preimages[new_val_idx as usize].next_idx = nullifier_tree_preimages[
                i
            ].next_idx;
            nullifier_tree_preimages[i].next_val = new_val;
            nullifier_tree_preimages[i].next_idx = Fr::from(new_val_idx);
            low_leaf_idx = i;
            break;
        }
    }
    (nullifier_tree_preimages, low_leaf_idx)
}

fn generate_state_transition_circuit_inputs(
    pk_enc: EncryptionPublicKey,
    nullifier_affine: Secp256k1Affine,
    incoming_vote: Vec<BigUint>,
    prev_vote: Vec<BigUint>,
    nullifier_tree_preimages: Vec<IMTLeaf<Fr>>,
    round: u64,
    nullifier_tree_leaves: Vec<Fr>
) -> (StateTransitionInput<Fr>, Vec<Fr>, Vec<IMTLeaf<Fr>>) {
    let mut leaves = nullifier_tree_leaves.clone();
    let mut native_hasher = Poseidon::<Fr, T, RATE>::new(R_F, R_P);

    let nullifier_compress = compress_native_nullifier(&nullifier_affine);
    native_hasher.update(&nullifier_compress);
    let new_val = native_hasher.squeeze_and_reset();

    let mut tree = IndexedMerkleTree::<Fr, T, RATE>
        ::new(&mut native_hasher, leaves.clone())
        .unwrap();

    let old_root = tree.get_root();

    let (updated_idx_leaves, low_leaf_idx) = update_idx_leaf(
        nullifier_tree_preimages.clone(),
        new_val,
        round
    );
    let low_leaf = nullifier_tree_preimages[low_leaf_idx].clone();
    let (low_leaf_proof, low_leaf_proof_helper) = tree.get_proof(low_leaf_idx);
    assert_eq!(
        tree.verify_proof(&leaves[low_leaf_idx], low_leaf_idx, &tree.get_root(), &low_leaf_proof),
        true
    );

    let new_low_leaf = updated_idx_leaves[low_leaf_idx].clone();
    let mut new_native_hasher = Poseidon::<Fr, T, RATE>::new(R_F, R_P);
    new_native_hasher.update(&[new_low_leaf.val, new_low_leaf.next_val, new_low_leaf.next_idx]);
    leaves[low_leaf_idx] = new_native_hasher.squeeze_and_reset();
    new_native_hasher.update(
        &[
            updated_idx_leaves[round as usize].val,
            updated_idx_leaves[round as usize].next_val,
            updated_idx_leaves[round as usize].next_idx,
        ]
    );
    leaves[round as usize] = new_native_hasher.squeeze_and_reset();
    tree = IndexedMerkleTree::<Fr, T, RATE>::new(&mut new_native_hasher, leaves.clone()).unwrap();
    let (new_leaf_proof, new_leaf_proof_helper) = tree.get_proof(round as usize);
    assert_eq!(
        tree.verify_proof(
            &leaves[round as usize],
            round as usize,
            &tree.get_root(),
            &new_leaf_proof
        ),
        true
    );

    let new_root = tree.get_root();
    let new_leaf = IMTLeaf::<Fr> {
        val: updated_idx_leaves[round as usize].val,
        next_val: updated_idx_leaves[round as usize].next_val,
        next_idx: updated_idx_leaves[round as usize].next_idx,
    };
    let new_leaf_index = Fr::from(round);
    let is_new_leaf_largest = if new_leaf.next_val == Fr::zero() { Fr::one() } else { Fr::zero() };

    let idx_input = IndexedMerkleTreeInput::new(
        old_root,
        low_leaf,
        low_leaf_proof,
        low_leaf_proof_helper,
        new_root,
        new_leaf,
        new_leaf_index,
        new_leaf_proof,
        new_leaf_proof_helper,
        is_new_leaf_largest
    );

    let input = StateTransitionInput::new(
        pk_enc,
        incoming_vote,
        prev_vote,
        idx_input,
        nullifier_affine
    );

    (input, leaves, updated_idx_leaves)
}

pub fn generate_wrapper_circuit_input(
    num_round: usize
) -> (Vec<VoterCircuitInput<Fr>>, Vec<StateTransitionInput<Fr>>) {
    let mut rng = thread_rng();
    let mut native_hasher = Poseidon::<Fr, T, RATE>::new(R_F, R_P);
    let mut native_hasher2 = Poseidon::<Fr, T, RATE>::new(R_F, R_P);

    // Generate pk_enc
    let n = rng.gen_biguint(ENC_BIT_LEN as u64);
    let g = rng.gen_biguint(ENC_BIT_LEN as u64);
    let pk_enc = EncryptionPublicKey {
        n: n.clone(),
        g: g.clone(),
    };

    let mut members_tree_leaves = Vec::<Fr>::new();

    let sk = (0..num_round).map(|_| Fq::random(OsRng)).collect::<Vec<_>>();
    let pk_voter = sk
        .iter()
        .map(|sk| (Secp256k1::generator() * *sk).to_affine())
        .collect::<Vec<_>>();

    let pk_voter_x = pk_voter
        .iter()
        .map(|pk_v| {
            pk_v.x
                .to_bytes()
                .to_vec()
                .chunks(11)
                .into_iter()
                .map(|chunk| Fr::from_bytes_le(chunk))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    let pk_voter_y = pk_voter
        .iter()
        .map(|pk_v| {
            pk_v.y
                .to_bytes()
                .to_vec()
                .chunks(11)
                .into_iter()
                .map(|chunk| Fr::from_bytes_le(chunk))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    for (x, y) in pk_voter_x.iter().zip(pk_voter_y.clone()) {
        native_hasher.update(x.as_slice());
        native_hasher.update(y.as_slice());
        members_tree_leaves.push(native_hasher.squeeze_and_reset());
    }

    for _ in num_round..8 {
        native_hasher.update(&[Fr::ZERO]);
        members_tree_leaves.push(native_hasher.squeeze_and_reset());
    }

    let members_tree = MerkleTree::new(&mut native_hasher, members_tree_leaves.clone()).unwrap();

    let mut rng = thread_rng();
    let mut prev_vote = Vec::<BigUint>::new();

    let mut voter_inputs = Vec::<VoterCircuitInput<Fr>>::new();
    let mut state_inputs = Vec::<StateTransitionInput<Fr>>::new();

    let mut state_input = generate_random_state_transition_circuit_inputs();

    let mut nullifier_tree_preimages = (0..8)
        .map(|_| IMTLeaf::<Fr> {
            val: Fr::from(0u64),
            next_val: Fr::from(0u64),
            next_idx: Fr::from(0u64),
        })
        .collect::<Vec<_>>();
    let mut nullifier_tree_leaves = nullifier_tree_preimages
        .iter()
        .map(|leaf| {
            native_hasher2.update(&[leaf.val, leaf.next_val, leaf.next_idx]);
            native_hasher2.squeeze_and_reset()
        })
        .collect::<Vec<Fr>>();

    for i in 0..num_round {
        let mut vote = [Fr::zero(), Fr::zero(), Fr::zero(), Fr::zero(), Fr::zero()].to_vec();
        vote[rng.gen_range(0..5)] = Fr::one();
        let (nullifier, s, c) = gen_test_nullifier(&sk[i], &[1u8, 0u8]);
        verify_nullifier(&[1u8, 0u8], &nullifier, &pk_voter[i], &s, &c);

        let r_enc = (0..5).map(|_| rng.gen_biguint(ENC_BIT_LEN as u64)).collect::<Vec<_>>();

        if i == 0 {
            prev_vote = (0..5)
                .map(|_| paillier_enc_native(&n, &g, &BigUint::from(0u64), &r_enc[i]))
                .collect::<Vec<_>>();
        }

        voter_inputs.push(
            generate_voter_circuit_inputs(
                pk_enc.clone(),
                nullifier,
                s,
                c,
                pk_voter[i],
                vote.clone(),
                r_enc.clone(),
                &members_tree,
                i
            )
        );

        let mut vote_enc = Vec::<BigUint>::with_capacity(5);
        for i in 0..5 {
            vote_enc.push(paillier_enc_native(&n, &g, &fe_to_biguint(&vote[i]), &r_enc[i]));
        }

        (state_input, nullifier_tree_leaves, nullifier_tree_preimages) =
            generate_state_transition_circuit_inputs(
                pk_enc.clone(),
                nullifier,
                vote_enc.clone(),
                prev_vote.clone(),
                nullifier_tree_preimages.clone(),
                (i + 1) as u64,
                nullifier_tree_leaves
            );

        state_inputs.push(state_input);

        prev_vote = prev_vote
            .iter()
            .zip(vote_enc)
            .map(|(x, y)| paillier_add_native(&n, &x, &y))
            .collect::<Vec<_>>();
    }

    (voter_inputs, state_inputs)
}

fn print_nullifier_leafs(node: Vec<IMTLeaf<Fr>>) {
    for (i, x) in node.iter().enumerate() {
        println!("val[{}]={:?}", i, x.val);
        println!("nxt_idx[{}]={:?}", i, x.next_idx);
        println!("next_val[{}]={:?}\n", i, x.next_val);
    }
}

pub fn compress_native_nullifier(point: &Secp256k1Affine) -> [Fr; 4] {
    let y_is_odd = BigUint::from_bytes_le(&point.y.to_bytes_le()) % 2u64;
    let tag = if y_is_odd == BigUint::from(0u64) { Fr::from(2u64) } else { Fr::from(3u64) };

    let x_limbs = point.x
        .to_bytes_le()
        .chunks(11)
        .map(|chunk| Fr::from_bytes_le(chunk))
        .collect::<Vec<_>>();

    [tag, x_limbs[0], x_limbs[1], x_limbs[2]]
}

pub fn generate_random_state_transition_circuit_inputs() -> StateTransitionInput<Fr> {
    const T: usize = 3;
    const RATE: usize = 2;
    const R_F: usize = 8;
    const R_P: usize = 57;

    let tree_size = (2u64).pow(3);
    let mut leaves = Vec::<Fr>::new();

    let sk = Fp::random(OsRng);
    let nullifier_affine = Secp256k1Affine::from(Secp256k1Affine::generator() * sk);

    let mut native_hasher = Poseidon::<Fr, T, RATE>::new(R_F, R_P);

    // Filling leaves with dfault values.
    for _ in 0..tree_size {
        native_hasher.update(&[Fr::from(0u64), Fr::from(0u64), Fr::from(0u64)]);
        leaves.push(native_hasher.squeeze_and_reset());
    }
    let nullifier_compress = compress_native_nullifier(&nullifier_affine);
    native_hasher.update(&nullifier_compress);
    let new_val = native_hasher.squeeze_and_reset();
    let mut tree = IndexedMerkleTree::<Fr, T, RATE>
        ::new(&mut native_hasher, leaves.clone())
        .unwrap();

    let old_root = tree.get_root();
    let low_leaf = IMTLeaf::<Fr> {
        val: Fr::from(0u64),
        next_val: Fr::from(0u64),
        next_idx: Fr::from(0u64),
    };
    let (low_leaf_proof, low_leaf_proof_helper) = tree.get_proof(0);
    assert_eq!(tree.verify_proof(&leaves[0], 0, &tree.get_root(), &low_leaf_proof), true);

    // compute interim state change
    let new_low_leaf = IMTLeaf::<Fr> {
        val: low_leaf.val,
        next_val: new_val,
        next_idx: Fr::from(1u64),
    };
    native_hasher.update(&[new_low_leaf.val, new_low_leaf.next_val, new_low_leaf.next_idx]);
    leaves[0] = native_hasher.squeeze_and_reset();

    native_hasher.update(&[new_val, Fr::from(0u64), Fr::from(0u64)]);
    leaves[1] = native_hasher.squeeze_and_reset();

    tree = IndexedMerkleTree::<Fr, T, RATE>::new(&mut native_hasher, leaves.clone()).unwrap();

    let (new_low_leaf_proof, _) = tree.get_proof(0);
    let (new_leaf_proof, new_leaf_proof_helper) = tree.get_proof(1);
    assert_eq!(tree.verify_proof(&leaves[1], 1, &tree.get_root(), &new_leaf_proof), true);

    let new_root = tree.get_root();
    let new_leaf = IMTLeaf::<Fr> {
        val: new_val,
        next_val: Fr::from(0u64),
        next_idx: Fr::from(0u64),
    };
    let new_leaf_index = Fr::from(1u64);
    let is_new_leaf_largest = Fr::from(true);

    let idx_input = IndexedMerkleTreeInput::new(
        old_root,
        low_leaf,
        low_leaf_proof,
        low_leaf_proof_helper,
        new_root,
        new_leaf,
        new_leaf_index,
        new_leaf_proof,
        new_leaf_proof_helper,
        is_new_leaf_largest
    );

    let mut rng = thread_rng();

    let n = rng.gen_biguint(ENC_BIT_LEN as u64);
    let g = rng.gen_biguint(ENC_BIT_LEN as u64);
    let pk_enc = EncryptionPublicKey {
        n: n.clone(),
        g: g.clone(),
    };
    let incoming_vote = (0..5)
        .map(|_| {
            paillier_enc_native(
                &n,
                &g,
                &rng.gen_biguint(ENC_BIT_LEN as u64),
                &rng.gen_biguint(ENC_BIT_LEN as u64)
            )
        })
        .collect::<Vec<_>>();
    let prev_vote = (0..5)
        .map(|_| {
            paillier_enc_native(
                &n,
                &g,
                &rng.gen_biguint(ENC_BIT_LEN as u64),
                &rng.gen_biguint(ENC_BIT_LEN as u64)
            )
        })
        .collect::<Vec<_>>();

    let input = StateTransitionInput {
        pk_enc,
        incoming_vote,
        prev_vote,
        nullifier_tree: idx_input,
        nullifier: nullifier_affine,
    };

    input
}
