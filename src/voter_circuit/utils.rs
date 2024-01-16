use halo2_base::{
    gates::{ GateChip, GateInstructions },
    utils::{ BigPrimeField, ScalarField },
    AssignedValue,
    Context,
};
use num_bigint::BigUint;

use pse_poseidon::Poseidon;

pub(crate) fn dual_mux<F: ScalarField>(
    ctx: &mut Context<F>,
    gate: &GateChip<F>,
    a: &AssignedValue<F>,
    b: &AssignedValue<F>,
    switch: &AssignedValue<F>
) -> [AssignedValue<F>; 2] {
    gate.assert_bit(ctx, *switch);

    let a_sub_b = gate.sub(ctx, *a, *b);
    let b_sub_a = gate.sub(ctx, *b, *a);

    let left = gate.mul_add(ctx, a_sub_b, *switch, *b); // left = (a-b)*s + b;
    let right = gate.mul_add(ctx, b_sub_a, *switch, *a); // right = (b-a)*s + a;

    [left, right]
}

pub(crate) fn paillier_enc_native(n: &BigUint, g: &BigUint, m: &BigUint, r: &BigUint) -> BigUint {
    let n2 = n * n;
    let gm = g.modpow(m, &n2);
    let rn = r.modpow(n, &n2);
    (gm * rn) % n2
}

#[derive(Debug)]
pub(crate) struct MerkleTree<'a, F: ScalarField, const T: usize, const RATE: usize> {
    hash: &'a mut Poseidon<F, T, RATE>,
    tree: Vec<Vec<F>>,
    root: F,
}

impl<'a, F: ScalarField, const T: usize, const RATE: usize> MerkleTree<'a, F, T, RATE> {
    pub(crate) fn new(
        hash: &'a mut Poseidon<F, T, RATE>,
        leaves: Vec<F>
    ) -> Result<MerkleTree<'a, F, T, RATE>, &'static str> {
        if leaves.is_empty() {
            return Err("Cannot create Merkle Tree with no leaves");
        }
        if leaves.len() == 1 {
            return Ok(MerkleTree {
                hash,
                tree: vec![leaves.clone()],
                root: leaves[0],
            });
        }
        if leaves.len() % 2 == 1 {
            return Err("Leaves must be even");
        }

        let mut tree = vec![leaves.clone()];
        let mut current_level = leaves.clone();

        while current_level.len() > 1 {
            let mut next_level = Vec::new();
            for i in (0..current_level.len()).step_by(2) {
                let left = current_level[i];
                let right = current_level[i + 1];
                hash.update(&[left, right]);
                next_level.push(hash.squeeze_and_reset());
            }
            tree.push(next_level.clone());
            current_level = next_level.clone();
        }
        Ok(MerkleTree {
            hash,
            tree,
            root: current_level[0],
        })
    }

    pub(crate) fn get_root(&self) -> F {
        self.root
    }

    pub(crate) fn get_proof(&self, index: usize) -> (Vec<F>, Vec<F>) {
        let mut proof = Vec::new();
        let mut proof_helper = Vec::new();
        let mut current_index = index;

        for i in 0..self.tree.len() - 1 {
            let level = &self.tree[i];
            let is_left_node = current_index % 2 == 0;
            let sibling_index = if is_left_node { current_index + 1 } else { current_index - 1 };
            let sibling = level[sibling_index];

            proof.push(sibling);
            proof_helper.push(if is_left_node { F::from(1) } else { F::from(0) });

            current_index /= 2;
        }

        (proof, proof_helper)
    }

    pub(crate) fn verify_proof(&mut self, leaf: &F, index: usize, root: &F, proof: &[F]) -> bool {
        let mut computed_hash = *leaf;
        let mut current_index = index;

        for i in 0..proof.len() {
            let proof_element = &proof[i];
            let is_left_node = current_index % 2 == 0;

            computed_hash = if is_left_node {
                self.hash.update(&[computed_hash, *proof_element]);
                self.hash.squeeze_and_reset()
            } else {
                self.hash.update(&[*proof_element, computed_hash]);
                self.hash.squeeze_and_reset()
            };

            current_index /= 2;
        }

        computed_hash == *root
    }
}
