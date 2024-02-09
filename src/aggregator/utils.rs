// use std::marker::PhantomData;

// use halo2_base::halo2_proofs::{arithmetic::Field, circuit::Layouter, halo2curves::{bn256::G1Affine, bn256::Bn256, grumpkin::Fq as Fr}, plonk::{keygen_vk, VerifyingKey, Circuit, ConstraintSystem, Error}, poly::{commitment::Params, kzg::commitment::ParamsKZG}};
// use snark_verifier_sdk::{snark_verifier::system::halo2::{compile, Config}, CircuitExt, Snark};
// // halo2curves::{bn256::Bn256, grumpkin::Fq as Fr},

//  pub fn gen_dummy_snark<ConcreteCircuit: CircuitExt<Fr>>(
//         params: &ParamsKZG<Bn256>,
//         vk: Option<&VerifyingKey<G1Affine>>,
//         config_params: ConcreteCircuit::Params,
//     ) -> Snark
//     where
//         ConcreteCircuit::Params: Clone,
//     {
//         struct CsProxy<F: Field, C: Circuit<F>>(C::Params, PhantomData<(F, C)>);

//         impl<F: Field, C: CircuitExt<F>> Circuit<F> for CsProxy<F, C>
//         where
//             C::Params: Clone,
//         {
//             type Config = C::Config;
//             type FloorPlanner = C::FloorPlanner;
//             type Params = C::Params;

//             fn params(&self) -> Self::Params {
//                 self.0.clone()
//             }

//             fn without_witnesses(&self) -> Self {
//                 CsProxy(self.0.clone(), PhantomData)
//             }

//             fn configure_with_params(
//                 meta: &mut ConstraintSystem<F>,
//                 params: Self::Params,
//             ) -> Self::Config {
//                 C::configure_with_params(meta, params)
//             }

//             fn configure(_: &mut ConstraintSystem<F>) -> Self::Config {
//                 unreachable!()
//             }

//             fn synthesize(
//                 &self,
//                 config: Self::Config,
//                 mut layouter: impl Layouter<F>,
//             ) -> Result<(), Error> {
//                 // when `C` has simple selectors, we tell `CsProxy` not to over-optimize the selectors (e.g., compressing them  all into one) by turning all selectors on in the first row
//                 // currently this only works if all simple selector columns are used in the actual circuit and there are overlaps amongst all enabled selectors (i.e., the actual circuit will not optimize constraint system further)
//                 layouter.assign_region(
//                     || "",
//                     |mut region| {
//                         for q in C::selectors(&config).iter() {
//                             q.enable(&mut region, 0)?;
//                         }
//                         Ok(())
//                     },
//                 );
//                 Ok(())
//                }
//         }

//         let dummy_vk = vk.is_none().then(|| {
//             keygen_vk(params, &CsProxy::<Fr, ConcreteCircuit>(config_params, PhantomData)).unwrap()
//         });
//         let protocol = compile(
//             params,
//             vk.or(dummy_vk.as_ref()).unwrap(),
//             Config::kzg()
//                 .with_num_instance(ConcreteCircuit::num_instance(&params))
//                 .with_accumulator_indices(ConcreteCircuit::accumulator_indices()),
//         );
//         let instances = ConcreteCircuit::num_instance()
//             .into_iter()
//             .map(|n| iter::repeat_with(|| Fr::random(OsRng)).take(n).collect())
//             .collect();
//         let proof = {
//             let mut transcript =
//                 PoseidonTranscript::<NativeLoader, _>::new::<SECURE_MDS>(Vec::new());
//             for _ in 0..protocol
//                 .num_witness
//                 .iter()
//                 .chain(Some(&protocol.quotient.num_chunk()))
//                 .sum::<usize>()
//             {
//                 transcript.write_ec_point(G1Affine::random(OsRng)).unwrap();
//             }
//             for _ in 0..protocol.evaluations.len() {
//                 transcript.write_scalar(Fr::random(OsRng)).unwrap();
//             }
//             let queries = PlonkProof::<G1Affine, NativeLoader, As>::empty_queries(&protocol);
//             for _ in 0..As::estimate_cost(&queries).num_commitment {
//                 transcript.write_ec_point(G1Affine::random(OsRng)).unwrap();
//             }
//             transcript.finalize()
//         };

//         Snark::new(protocol, instances, proof)
//     }
