use halo2_base::halo2_proofs::dev::MockProver;
use halo2_base::halo2_proofs::halo2curves::ff::PrimeField;
use halo2_base::halo2_proofs::plonk::ProvingKey;
use halo2_base::utils::fs::gen_srs;
use snark_verifier_sdk::halo2::gen_snark_shplonk;
use zkevm_hashes::util::eth_types::Field;
use std::marker::PhantomData;
use zkevm_hashes::sha256::vanilla::{
    columns::Sha256CircuitConfig,
    util::get_sha2_capacity,
    witness::AssignedSha256Block,
};
use halo2_base::halo2_proofs::{
    circuit::SimpleFloorPlanner,
    plonk::Circuit,
    halo2curves::bn256::{Fr, G1Affine}
};

use halo2_base::{
    halo2_proofs::{
        circuit::Layouter,
        plonk::{Assigned, ConstraintSystem, Column, Instance, Error},
    },
    utils::{
        halo2::Halo2AssignedCell,
        value_to_option,
    },
};
use sha2::{Digest, Sha256};
use snark_verifier_sdk::{gen_pk, CircuitExt, Snark};
use itertools::Itertools;

#[derive(Clone)]
pub struct Sha256BitCircuitConfig<F: Field> {
    sha256_circuit_config: Sha256CircuitConfig<F>,
    #[allow(dead_code)]
    instance: Column<Instance>,
}

#[derive(Default)]
pub struct Sha256BitCircuit<F: Field> {
    inputs: Vec<Vec<u8>>,
    num_rows: Option<usize>,
    assigned_instances: Vec<Vec<F>>,
    witness_gen_only: bool,
    _marker: PhantomData<F>,
}

impl<F: Field> Circuit<F> for Sha256BitCircuit<F> {
    type Config = Sha256BitCircuitConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let sha256_circuit_config = Sha256CircuitConfig::new(meta);
        let instance = meta.instance_column();
        meta.enable_equality(instance);
        Self::Config { sha256_circuit_config, instance }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let result = layouter.assign_region(
            || "SHA256 Bit Circuit",
            |mut region| {
                let start = std::time::Instant::now();
                let blocks = config.sha256_circuit_config.multi_sha256(
                    &mut region,
                    self.inputs.clone(),
                    self.num_rows.map(get_sha2_capacity),
                );
                println!("Witness generation time: {:?}", start.elapsed());
                if self.witness_gen_only {
                    self.verify_output(&blocks);
                }

                Ok(blocks)
            },
        )?;

        if !self.witness_gen_only {

            let mut layouter = layouter.namespace(|| "expose");
            for assigned_blocks in result {
                let value = **value_to_option(assigned_blocks.is_final().value()).unwrap_or(&&Assigned::Zero);
                let value = match value {
                    Assigned::Trivial(v) => v,
                    Assigned::Zero => F::ZERO,
                    Assigned::Rational(a, b) => a * b.invert().unwrap(),
                };
                if value == F::ONE {
                    layouter.constrain_instance(assigned_blocks.output().lo().cell(), config.instance, 0);
                    layouter.constrain_instance(assigned_blocks.output().hi().cell(), config.instance, 1);
                    break;
                }
            }
        }

        Ok(())
    }
}

impl<F: Field> Sha256BitCircuit<F> {
    /// Creates a new circuit instance
    pub fn new(
        num_rows: Option<usize>,
        inputs: Vec<Vec<u8>>,
        witness_gen_only: bool
    ) -> Self {
        Sha256BitCircuit { num_rows, inputs, witness_gen_only, assigned_instances: vec![vec![]], _marker: PhantomData }
    }

    pub fn set_instances(
        &mut self,
        instances: Vec<F>,
    ) {
        self.assigned_instances[0].extend(instances);
    }

    fn verify_output(&self, assigned_blocks: &[AssignedSha256Block<F>]) {
        let mut input_offset = 0;
        let mut input = vec![];
        let extract_value = |a: Halo2AssignedCell<F>| {
            let value = *value_to_option(a.value()).unwrap();
            #[cfg(feature = "halo2-axiom")]
            let value = *value;
            #[cfg(not(feature = "halo2-axiom"))]
            let value = value.clone();
            match value {
                Assigned::Trivial(v) => v,
                Assigned::Zero => F::ZERO,
                Assigned::Rational(a, b) => a * b.invert().unwrap(),
            }
        };
        for input_block in assigned_blocks {
            let is_final = input_block.is_final().clone();
            let output = input_block.output().clone();
            let word_values = input_block.word_values().clone();
            let length = input_block.length().clone();
            let [is_final, output_lo, output_hi, length] =
                [is_final, output.lo(), output.hi(), length].map(extract_value);
            let word_values = word_values.iter().cloned().map(extract_value).collect::<Vec<_>>();
            for word in word_values {
                let word = word.get_lower_32().to_le_bytes();
                input.extend_from_slice(&word);
            }
            let is_final = is_final == F::ONE;
            if is_final {
                let empty = vec![];
                let true_input = self.inputs.get(input_offset).unwrap_or(&empty);
                let true_length = true_input.len();
                assert_eq!(length.get_lower_64(), true_length as u64, "Length does not match");
                // clear global input and make it local
                let mut input = std::mem::take(&mut input);
                input.truncate(true_length);
                assert_eq!(&input, true_input, "Inputs do not match");
                let output_lo = output_lo.to_repr(); // u128 as 32 byte LE
                let output_hi = output_hi.to_repr();
                let mut output = [&output_lo[..16], &output_hi[..16]].concat();
                output.reverse();

                let mut hasher = Sha256::new();
                hasher.update(true_input);
                let a = hasher.finalize().to_vec();
                assert_eq!(output, a, "Outputs do not match");

                input_offset += 1;
            }
        }
    }

}

impl<F: Field> CircuitExt<F> for Sha256BitCircuit<F> {
    fn num_instance(&self) -> Vec<usize> {
        self.assigned_instances.iter().map(|instances| instances.len()).collect_vec()
    }

    fn instances(&self) -> Vec<Vec<F>> {
        self.assigned_instances.clone()
    }
}
pub fn generate_sha256_snark( k: usize,pk:ProvingKey<G1Affine>) ->Snark {

    let inputs = vec![
        (0u8..200).collect::<Vec<_>>(),
        vec![],
        (0u8..1).collect::<Vec<_>>(),
        (0u8..54).collect::<Vec<_>>(),
        (0u8..55).collect::<Vec<_>>(), 
        (0u8..56).collect::<Vec<_>>(), 
    ];
    let inp=inputs.clone();
    let empty=vec![];
    let true_input = inp.get(0).unwrap_or(&empty);
    let mut sha256_bit_circuit = Sha256BitCircuit::new(
        Some(2usize.pow(k as u32) - 109),
        inputs,
        true
    );

    let mut hasher=Sha256::new();
    hasher.update(true_input);
    let hashed_tbs = hasher.finalize();
    let lo = &hashed_tbs[0..16];
    let hi = &hashed_tbs[16..32];
    let mut hashed_lo = [0u8; 16];
    let mut hashed_hi = [0u8; 16];
    hashed_lo.copy_from_slice(lo);
    hashed_hi.copy_from_slice(hi);
    
    let lo_u128 = u128::from_be_bytes(hashed_lo);
    let hi_u128 = u128::from_be_bytes(hashed_hi);
    sha256_bit_circuit.set_instances(vec![
        Fr::from_u128(lo_u128),
        Fr::from_u128(hi_u128)
    ]);
    MockProver::run(k as u32, &sha256_bit_circuit, sha256_bit_circuit.instances()).unwrap().assert_satisfied();
    let params=gen_srs(k as u32);

   gen_snark_shplonk(&params, &pk, sha256_bit_circuit, None::<&str>)
}

pub fn generate_pk(input:Vec<u8>,k:usize)->ProvingKey<G1Affine>{
    let inp=input.clone();
    let mut dummy_circuit = Sha256BitCircuit::new(
        Some(2usize.pow(k as u32) - 109),
        vec![inp.to_vec()],
        false
    );
    // Calculate public instances
    let hashed_tbs = Sha256::digest(inp);
    println!("Hashed TBS: {:?}", hashed_tbs);
    let lo = &hashed_tbs[0..16];
    let hi = &hashed_tbs[16..32];
    let mut hashed_lo = [0u8; 16];
    let mut hashed_hi = [0u8; 16];
    hashed_lo.copy_from_slice(lo);
    hashed_hi.copy_from_slice(hi);
    let lo_u128 = u128::from_be_bytes(hashed_lo);
    let hi_u128 = u128::from_be_bytes(hashed_hi);
    dummy_circuit.set_instances(vec![
        Fr::from_u128(lo_u128),
        Fr::from_u128(hi_u128)
    ]);

    let params = gen_srs(k as u32);
    
    gen_pk(&params, &dummy_circuit, None)
}

#[cfg(test)]
mod tests {

use halo2_base::halo2_proofs::dev::MockProver;
use halo2_base::halo2_proofs::halo2curves::{ff::PrimeField,  grumpkin::Fq as Fr};  
use sha2::{Digest, Sha256};
use snark_verifier_sdk:: CircuitExt;
use super::{generate_pk, generate_sha256_snark};


use super::Sha256BitCircuit;
    pub fn sha256_proof( k: usize)  {

        let inputs = vec![
            (0u8..200).collect::<Vec<_>>(),
            vec![],
            (0u8..1).collect::<Vec<_>>(),
            (0u8..54).collect::<Vec<_>>(),
            (0u8..55).collect::<Vec<_>>(), // with padding 55 + 1 + 8 = 64 bytes, still fits in 1 block
            (0u8..56).collect::<Vec<_>>(), // needs 2 blocks, due to padding
        ];
        let inp=inputs.clone();
        let empty=vec![];
        let true_input = inp.get(0).unwrap_or(&empty);
        let mut sha256_bit_circuit = Sha256BitCircuit::new(
            Some(2usize.pow(k as u32) - 109),
            inputs,
            true
        );

        let mut hasher=Sha256::new();
        hasher.update(true_input);
        let hashed_tbs = hasher.finalize();
        let lo = &hashed_tbs[0..16];
        let hi = &hashed_tbs[16..32];
        let mut hashed_lo = [0u8; 16];
        let mut hashed_hi = [0u8; 16];
        hashed_lo.copy_from_slice(lo);
        hashed_hi.copy_from_slice(hi);
        
        let lo_u128 = u128::from_be_bytes(hashed_lo);
        let hi_u128 = u128::from_be_bytes(hashed_hi);
        sha256_bit_circuit.set_instances(vec![
            Fr::from_u128(lo_u128),
            Fr::from_u128(hi_u128)
        ]);
        MockProver::run(k as u32, &sha256_bit_circuit, sha256_bit_circuit.instances()).unwrap().assert_satisfied();
    }

    #[test]
    fn test_sha256_snark(){
        //sha256_proof(11);
        let input=   (0u8..200).collect::<Vec<_>>();
        let pk=generate_pk(input, 11);
       generate_sha256_snark(11,pk);
    }


    
}