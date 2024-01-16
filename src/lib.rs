pub mod voter_circuit;

use halo2_base::halo2_proofs::arithmetic::Field;
use wasm_bindgen::prelude::*;

use std::cell::RefCell;
use std::sync::Arc;


use halo2_base::halo2_proofs::halo2curves::bn256::Fr;


use crate::voter_circuit::{voter_circuit,VoterInput,EncryptionPublicKey,utils::{enc_help, get_proof, merkle_help}};
use pse_poseidon::Poseidon;
use rand::thread_rng;
use num_bigint::{BigUint, RandBigInt};
use halo2_wasm::Halo2Wasm;
use halo2_ecc::ecc::EcPoint;
use num_traits::One;

use halo2_base::{
    gates::{
        circuit::{builder::BaseCircuitBuilder, BaseCircuitParams, CircuitBuilderStage},
        GateChip, RangeChip, RangeInstructions,
    },
  
    halo2_proofs::{circuit::Value, halo2curves::bn256::G1Affine},
    poseidon::hasher::{spec::OptimizedPoseidonSpec, PoseidonHasher},
    utils::{fe_to_biguint, BigPrimeField, ScalarField},
    AssignedValue, Context,
};


#[wasm_bindgen]
pub struct NnWasm {
    gate: GateChip<Fr>,
    builder: Arc<RefCell<BaseCircuitBuilder<Fr>>>,
}
#[warn(dead_code)]
const T: usize = 3;
const RATE: usize = 2;
const R_F: usize = 8;
const R_P: usize = 57;

#[wasm_bindgen]
impl NnWasm {
    #[wasm_bindgen(constructor)]
    pub fn new(circuit: &Halo2Wasm) -> Self {
        let gate = GateChip::new();
        NnWasm {
            gate,
            builder: Arc::clone(&circuit.circuit),
        }
    }

    pub fn run(&mut self) {
        const ENC_BIT_LEN: usize = 128;
        const LIMB_BIT_LEN: usize = 64;
        let mut rng = thread_rng();
        let treesize = u32::pow(2, 3);

        let vote = [
            BigUint::one(),
            BigUint::default(),
            BigUint::default(),
            BigUint::default(),
            BigUint::default(),
        ]
        .to_vec();

        let n_b = rng.gen_biguint(ENC_BIT_LEN as u64);
        let g_b = rng.gen_biguint(ENC_BIT_LEN as u64);
        let mut r_enc = Vec::<BigUint>::new();
        let mut vote_enc = Vec::<BigUint>::new();
        for i in 0..5 {
            r_enc.push(rng.gen_biguint(ENC_BIT_LEN as u64));
            vote_enc.push(enc_help(&n_b, &g_b, &vote[i], &r_enc[i]));
        }

        let mut native_hasher = Poseidon::<Fr, T, RATE>::new(R_F, R_P);
        let mut leaves = Vec::<Fr>::new();
        let pubkey = EcPoint::new(Fr::random(rng.clone()), Fr::random(rng));
        for i in 0..treesize {
            if i == 0 {
                native_hasher.update(&[pubkey.x])
            } else {
                native_hasher.update(&[Fr::ZERO])
            }
            leaves.push(native_hasher.squeeze_and_reset());
        }
        let mut helper = merkle_help::<Fr, 3, 2>(&mut native_hasher, leaves.clone());
        let membership_root = helper.pop().unwrap()[0];
        let (membership_proof, membership_proof_helper) = get_proof(0, helper);
       

        let pk_enc = EncryptionPublicKey { n: n_b, g: g_b };

        let input = VoterInput::new(vote, vote_enc, r_enc, pk_enc, membership_root, pubkey, membership_proof, membership_proof_helper);
        let range:RangeChip<Fr> =RangeChip::new(self.builder.borrow_mut().config_params.lookup_bits.unwrap(),*self.builder.borrow_mut().lookup_manager());
      let gate=range.gate();
        let mut hasher =
        PoseidonHasher::<Fr, T, RATE>::new(OptimizedPoseidonSpec::new::<R_F, R_P, 0>());
    hasher.initialize_consts(self.builder.borrow_mut().main(0), gate);

        voter_circuit(self.builder.borrow_mut().main(0), &range, &hasher, input, LIMB_BIT_LEN, ENC_BIT_LEN)
    }
}
