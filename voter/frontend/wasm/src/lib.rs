use voter::voter_circuit;
use voter_tests::generate_random_voter_circuit_inputs;
use wasm_bindgen::prelude::*;
use std::{ cell::RefCell, rc::Rc };

use halo2_wasm::{
    halo2_base::{ gates::{ circuit::builder::BaseCircuitBuilder, RangeChip }, AssignedValue },
    halo2lib::ecc::Bn254Fr as Fr,
    Halo2Wasm,
};

#[wasm_bindgen]
pub struct MyCircuit {
    range: RangeChip<Fr>,
    builder: Rc<RefCell<BaseCircuitBuilder<Fr>>>,
}

#[wasm_bindgen]
impl MyCircuit {
    #[wasm_bindgen(constructor)]
    pub fn new(circuit: &Halo2Wasm) -> Self {
        let builder = Rc::clone(&circuit.circuit);
        let lookup_bits = match builder.borrow_mut().lookup_bits() {
            Some(x) => x,
            None => panic!("Lookup bits not found"),
        };
        let lookup_manager = builder.borrow_mut().lookup_manager().clone();
        let range = RangeChip::<Fr>::new(lookup_bits, lookup_manager);
        MyCircuit {
            range,
            builder: Rc::clone(&circuit.circuit),
        }
    }

    pub fn run(&mut self) {
        let mut builder_borrow = self.builder.borrow_mut();
        let ctx = builder_borrow.main(0);

        let input = generate_random_voter_circuit_inputs();

        let mut public_inputs = Vec::<AssignedValue<Fr>>::new();
        voter_circuit(ctx, &self.range, input, &mut public_inputs);
        builder_borrow.assigned_instances[0].extend_from_slice(&public_inputs);
    }
}
