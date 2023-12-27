use halo2_base::{
    utils::BigPrimeField,
    gates::circuit::builder::BaseCircuitBuilder,
    AssignedValue,
};

#[derive(Clone, Debug)]
pub struct CircuitInput {}

fn circuit<F: BigPrimeField>(
    builder: &mut BaseCircuitBuilder<F>,
    input: CircuitInput,
    make_public: &mut Vec<AssignedValue<F>>
) {}
