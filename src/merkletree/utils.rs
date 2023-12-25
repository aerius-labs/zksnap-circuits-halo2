use poseidon_rs::{ Poseidon, Fr };

#[derive(Debug, Clone)]
pub struct MerkleTree {
    pub root: u128,
}

impl MerkleTree {
    pub fn new(leaves: &[u128]) -> Self {
        let mut tree = Self { root: 0 };
        // tree.build(leaves);
        tree
    }

    fn build(&mut self, leaves: &[u128]) {
        let mut tree = leaves.to_vec();
        let poseidon = Poseidon::new();
        while tree.len() > 1 {
            let mut new_tree = Vec::new();
            for chunk in tree.chunks(2) {
                let chunk0 = Fr::from_str();
                poseidon.hash([].to_vec());
            }
            tree = new_tree;
        }
        self.root = tree[0];
    }
}
