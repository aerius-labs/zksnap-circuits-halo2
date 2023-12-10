use super::poseidon::hash::{PoseidonChip, PoseidonConfig};
use super::poseidon::spec::MySpec;
use halo2_proofs::{arithmetic::FieldExt, circuit::*, plonk::*, poly::Rotation};

const WIDTH: usize = 3;
const RATE: usize = 2;
const L: usize = 2;

#[derive(Debug, Clone)]
pub struct MerkleTreeConfig<F: FieldExt> {
    pub advice: [Column<Advice>; 3],
    pub bool_selector: Selector,
    pub swap_selector: Selector,
    pub instance: Column<Instance>,
    pub poseidon_config: PoseidonConfig<F, WIDTH, RATE, L>,
}
#[derive(Debug, Clone)]
pub struct MerkleTreeChip<F: FieldExt> {
    config: MerkleTreeConfig<F>,
}

impl<F: FieldExt> MerkleTreeChip<F> {
    pub fn construct(config: MerkleTreeConfig<F>) -> Self {
        Self { config }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; 3],
        instance: Column<Instance>,
    ) -> MerkleTreeConfig<F> {
        let col_a = advice[0];
        let col_b = advice[1];
        let col_c = advice[2];

        // create selectors
        let bool_selector = meta.selector();
        let swap_selector = meta.selector();

        meta.enable_equality(col_a);
        meta.enable_equality(col_b);
        meta.enable_equality(col_c);
        meta.enable_equality(instance);

        // Enforces that c is either a 0 or 1 when the bool selector is enabled
        // s * c * (1 - c) = 0
        meta.create_gate("bool constraint", |meta| {
            let s = meta.query_selector(bool_selector);
            let c = meta.query_advice(col_c, Rotation::cur());
            vec![s * c.clone() * (Expression::Constant(F::from(1)) - c)]
        });

        // Enforces that if the swap bit (c) is on, l=b and r=a. Otherwise, l=a and r=b.
        // s * (c * 2 * (b - a) - (l - a) - (b - r)) = 0
        // This applies only when the swap selector is enabled
        meta.create_gate("swap constraint", |meta| {
            let s = meta.query_selector(swap_selector);
            let a = meta.query_advice(col_a, Rotation::cur());
            let b = meta.query_advice(col_b, Rotation::cur());
            let c = meta.query_advice(col_c, Rotation::cur());
            let l = meta.query_advice(col_a, Rotation::next());
            let r = meta.query_advice(col_b, Rotation::next());
            vec![
                s * (c * Expression::Constant(F::from(2)) * (b.clone() - a.clone())
                    - (l - a)
                    - (b - r)),
            ]
        });

        let hash_inputs = (0..WIDTH).map(|_| meta.advice_column()).collect::<Vec<_>>();

        let poseidon_config =
            PoseidonChip::<F, MySpec<F, WIDTH, RATE>, WIDTH, RATE, L>::configure(meta, hash_inputs);

        MerkleTreeConfig {
            advice: [col_a, col_b, col_c],
            bool_selector,
            swap_selector,
            instance,
            poseidon_config,
        }
    }

    pub fn assing_leaf(
        &self,
        mut layouter: impl Layouter<F>,
        leaf: Value<F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        let node_cell = layouter.assign_region(
            || "assign leaf",
            |mut region| region.assign_advice(|| "assign leaf", self.config.advice[0], 0, || leaf),
        )?;

        Ok(node_cell)
    }

    pub fn merkle_prove_layer(
        &self,
        mut layouter: impl Layouter<F>,
        node_cell: &AssignedCell<F, F>,
        path_element: Value<F>,
        index: Value<F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        let (left, right) = layouter.assign_region(
            || "merkle prove layer",
            |mut region| {
                // Row 0
                self.config.bool_selector.enable(&mut region, 0)?;
                self.config.swap_selector.enable(&mut region, 0)?;
                node_cell.copy_advice(
                    || "copy node cell from previous prove layer",
                    &mut region,
                    self.config.advice[0],
                    0,
                )?;
                region.assign_advice(
                    || "assign element",
                    self.config.advice[1],
                    0,
                    || path_element,
                )?;
                region.assign_advice(|| "assign index", self.config.advice[2], 0, || index)?;

                // Row 1
                // Here we just perform the assignment - no hashing is performed here!
                let node_cell_value = node_cell.value().map(|x| x.to_owned());
                let (mut l, mut r) = (node_cell_value, path_element);
                index.map(|x| {
                    (l, r) = if x == F::zero() { (l, r) } else { (r, l) };
                });

                // We need to perform the assignment of the row below in order to perform the swap check
                let left = region.assign_advice(
                    || "assign left to be hashed",
                    self.config.advice[0],
                    1,
                    || l,
                )?;
                let right = region.assign_advice(
                    || "assign right to be hashed",
                    self.config.advice[1],
                    1,
                    || r,
                )?;

                Ok((left, right))
            },
        )?;

        // instantiate the poseidon_chip
        let poseidon_chip = PoseidonChip::<F, MySpec<F, WIDTH, RATE>, WIDTH, RATE, L>::construct(
            self.config.poseidon_config.clone(),
        );

        // The hash function inside the poseidon_chip performs the following action
        // 1. Copy the left and right cells from the previous row
        // 2. Perform the hash function and assign the digest to the current row
        // 3. Constrain the digest to be equal to the hash of the left and right values
        let digest =
            poseidon_chip.hash(layouter.namespace(|| "hash row constaint"), [left, right])?;
        Ok(digest)
    }

    // Enforce permutation check between input cell and instance column at row passed as input
    pub fn expose_public(
        &self,
        mut layouter: impl Layouter<F>,
        cell: &AssignedCell<F, F>,
        row: usize,
    ) -> Result<(), Error> {
        layouter.constrain_instance(cell.cell(), self.config.instance, row)
    }
}
