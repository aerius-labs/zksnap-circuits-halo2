// #![allow(clippy::type_complexity)]

// use ark_std::{ end_timer, start_timer };
// use common::*;
// use halo2_base::{ gates::circuit::BaseCircuitParams, halo2_proofs };
// use halo2_proofs::{
//     circuit::{ Layouter, SimpleFloorPlanner },
//     dev::MockProver,
//     halo2curves::{ bn256::{ Bn256, Fr, G1Affine }, group::ff::Field },
//     plonk::{
//         create_proof,
//         keygen_pk,
//         keygen_vk,
//         Circuit,
//         ConstraintSystem,
//         Error,
//         ProvingKey,
//         Selector,
//         VerifyingKey,
//     },
//     poly::{
//         commitment::ParamsProver,
//         kzg::{
//             commitment::ParamsKZG,
//             multiopen::{ ProverGWC, VerifierGWC },
//             strategy::AccumulatorStrategy,
//         },
//         VerificationStrategy,
//     },
// };
// use itertools::Itertools;
// use rand_chacha::rand_core::OsRng;
// use snark_verifier_sdk::snark_verifier::{
//     loader::{ self, native::NativeLoader, Loader, ScalarLoader },
//     pcs::{
//         kzg::{ Gwc19, KzgAccumulator, KzgAs, KzgSuccinctVerifyingKey, LimbsEncoding },
//         AccumulationScheme,
//         AccumulationSchemeProver,
//     },
//     system::halo2::{ self, compile, Config },
//     util::{ arithmetic::{ fe_to_fe, fe_to_limbs }, hash },
//     verifier::{ self, plonk::{ PlonkProof, PlonkProtocol }, SnarkVerifier },
// };
// use std::{ iter, marker::PhantomData, rc::Rc };

// const LIMBS: usize = 3;
// const BITS: usize = 88;
// const T: usize = 3;
// const RATE: usize = 2;
// const R_F: usize = 8;
// const R_P: usize = 57;
// const SECURE_MDS: usize = 0;

// type Svk = KzgSuccinctVerifyingKey<G1Affine>;
// type As = KzgAs<Bn256, Gwc19>;
// type PlonkVerifier = verifier::plonk::PlonkVerifier<As, LimbsEncoding<LIMBS, BITS>>;
// type PlonkSuccinctVerifier = verifier::plonk::PlonkSuccinctVerifier<As, LimbsEncoding<LIMBS, BITS>>;
// type Poseidon<L> = hash::Poseidon<Fr, L, T, RATE>;
// type PoseidonTranscript<L, S> = halo2::transcript::halo2::PoseidonTranscript<
//     G1Affine,
//     L,
//     S,
//     T,
//     RATE,
//     R_F,
//     R_P
// >;

// mod common {
//     use super::*;
//     use halo2_proofs::{ plonk::verify_proof, poly::commitment::Params };
//     use snark_verifier_sdk::snark_verifier::{
//         cost::CostEstimation,
//         util::transcript::TranscriptWrite,
//     };

//     pub fn poseidon<L: Loader<G1Affine>>(
//         loader: &L,
//         inputs: &[L::LoadedScalar]
//     ) -> L::LoadedScalar {
//         // warning: generating a new spec is time intensive, use lazy_static in production
//         let mut hasher = Poseidon::new::<R_F, R_P, SECURE_MDS>(loader);
//         hasher.update(inputs);
//         hasher.squeeze()
//     }

//     #[derive(Clone)]
//     pub struct Snark {
//         pub protocol: PlonkProtocol<G1Affine>,
//         pub instances: Vec<Vec<Fr>>,
//         pub proof: Vec<u8>,
//     }

//     impl Snark {
//         pub fn new(
//             protocol: PlonkProtocol<G1Affine>,
//             instances: Vec<Vec<Fr>>,
//             proof: Vec<u8>
//         ) -> Self {
//             Self { protocol, instances, proof }
//         }

//         pub fn proof(&self) -> &[u8] {
//             &self.proof[..]
//         }
//     }

//     pub trait CircuitExt<F: Field>: Circuit<F> {
//         fn num_instance() -> Vec<usize>;

//         fn instances(&self) -> Vec<Vec<F>>;

//         fn accumulator_indices() -> Option<Vec<(usize, usize)>> {
//             None
//         }

//         /// Output the simple selector columns (before selector compression) of the circuit
//         fn selectors(_: &Self::Config) -> Vec<Selector> {
//             vec![]
//         }
//     }

//     pub fn gen_pk<C: Circuit<Fr>>(params: &ParamsKZG<Bn256>, circuit: &C) -> ProvingKey<G1Affine> {
//         let vk = keygen_vk(params, circuit).unwrap();
//         keygen_pk(params, vk, circuit).unwrap()
//     }

//     pub fn gen_proof<C: Circuit<Fr>>(
//         params: &ParamsKZG<Bn256>,
//         pk: &ProvingKey<G1Affine>,
//         circuit: C,
//         instances: Vec<Vec<Fr>>
//     ) -> Vec<u8> {
//         if params.k() > 3 {
//             let mock = start_timer!(|| "Mock prover");
//             MockProver::run(params.k(), &circuit, instances.clone()).unwrap().assert_satisfied();
//             end_timer!(mock);
//         }

//         let instances = instances.iter().map(Vec::as_slice).collect_vec();
//         let proof = {
//             let mut transcript = PoseidonTranscript::<NativeLoader, _>::new::<SECURE_MDS>(
//                 Vec::new()
//             );
//             create_proof::<_, ProverGWC<_>, _, _, _, _>(
//                 params,
//                 pk,
//                 &[circuit],
//                 &[instances.as_slice()],
//                 OsRng,
//                 &mut transcript
//             ).unwrap();
//             transcript.finalize()
//         };

//         let accept = {
//             let mut transcript = PoseidonTranscript::<NativeLoader, _>::new::<SECURE_MDS>(
//                 proof.as_slice()
//             );
//             VerificationStrategy::<_, VerifierGWC<_>>::finalize(
//                 verify_proof::<_, VerifierGWC<_>, _, _, _>(
//                     params.verifier_params(),
//                     pk.get_vk(),
//                     AccumulatorStrategy::new(params.verifier_params()),
//                     &[instances.as_slice()],
//                     &mut transcript
//                 ).unwrap()
//             )
//         };
//         assert!(accept);

//         proof
//     }

//     pub fn gen_snark<ConcreteCircuit: CircuitExt<Fr>>(
//         params: &ParamsKZG<Bn256>,
//         pk: &ProvingKey<G1Affine>,
//         circuit: ConcreteCircuit
//     ) -> Snark {
//         let protocol = compile(
//             params,
//             pk.get_vk(),
//             Config::kzg()
//                 .with_num_instance(ConcreteCircuit::num_instance())
//                 .with_accumulator_indices(ConcreteCircuit::accumulator_indices())
//         );

//         let instances = circuit.instances();
//         let proof = gen_proof(params, pk, circuit, instances.clone());

//         Snark::new(protocol, instances, proof)
//     }

//     pub fn gen_dummy_snark<ConcreteCircuit: CircuitExt<Fr>>(
//         params: &ParamsKZG<Bn256>,
//         vk: Option<&VerifyingKey<G1Affine>>,
//         config_params: ConcreteCircuit::Params
//     ) -> Snark
//         where ConcreteCircuit::Params: Clone
//     {
//         struct CsProxy<F: Field, C: Circuit<F>>(C::Params, PhantomData<(F, C)>);

//         impl<F: Field, C: CircuitExt<F>> Circuit<F> for CsProxy<F, C> where C::Params: Clone {
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
//                 params: Self::Params
//             ) -> Self::Config {
//                 C::configure_with_params(meta, params)
//             }

//             fn configure(_: &mut ConstraintSystem<F>) -> Self::Config {
//                 unreachable!()
//             }

//             fn synthesize(
//                 &self,
//                 config: Self::Config,
//                 mut layouter: impl Layouter<F>
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
//                     }
//                 )?;
//                 Ok(())
//             }
//         }

//         let dummy_vk = vk
//             .is_none()
//             .then(|| {
//                 keygen_vk(
//                     params,
//                     &CsProxy::<Fr, ConcreteCircuit>(config_params, PhantomData)
//                 ).unwrap()
//             });
//         let protocol = compile(
//             params,
//             vk.or(dummy_vk.as_ref()).unwrap(),
//             Config::kzg()
//                 .with_num_instance(ConcreteCircuit::num_instance())
//                 .with_accumulator_indices(ConcreteCircuit::accumulator_indices())
//         );
//         let instances = ConcreteCircuit::num_instance()
//             .into_iter()
//             .map(|n|
//                 iter
//                     ::repeat_with(|| Fr::random(OsRng))
//                     .take(n)
//                     .collect()
//             )
//             .collect();
//         let proof = {
//             let mut transcript = PoseidonTranscript::<NativeLoader, _>::new::<SECURE_MDS>(
//                 Vec::new()
//             );
//             for _ in 0..protocol.num_witness
//                 .iter()
//                 .chain(Some(&protocol.quotient.num_chunk()))
//                 .sum::<usize>() {
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
// }

// mod vertical {
//     use crate::voter_circuit::{VoterCircuit,VoterCircuitInput};
//     use super::*;

   
//     impl CircuitExt<Fr> for VoterCircuit<Fr>{
//         fn num_instance() -> Vec<usize> {
//             vec![1] // [val]
//         }

//         fn instances(&self) -> Vec<Vec<Fr>> {
//             vec![
//                 self.inner.assigned_instances[0]
//                     .iter()
//                     .map(|instance| *instance.value())
//                     .collect()
//             ]
//         }
//     }
// }

// mod state_transition {
//     use halo2_base::gates::{
//         circuit::{ builder::BaseCircuitBuilder, BaseConfig },
//         GateChip,
//         GateInstructions,
//     };

//     use crate::state_transition_circuit::{StateTranInput,StateTransitionCircuit};

//     use super::*;

//     impl CircuitExt<Fr> for StateTransitionCircuit<Fr> {
//         fn num_instance() -> Vec<usize> {
//             vec![3] // [lhs, rhs, result]
//         }

//         fn instances(&self) -> Vec<Vec<Fr>> {
//             vec![
//                 self.inner.assigned_instances[0]
//                     .iter()
//                     .map(|instance| *instance.value())
//                     .collect()
//             ]
//         }
//     }
// }

// mod recursion {
//     use std::mem;

//     use halo2_base::{
//         gates::{
//             circuit::{ builder::BaseCircuitBuilder, BaseConfig },
//             GateInstructions,
//             RangeInstructions,
//         }, utils::BigPrimeField, AssignedValue
//     };
//     use halo2_ecc::{ bn254::FpChip, ecc::EcPoint };
//     use snark_verifier_sdk::snark_verifier::loader::halo2::{ EccInstructions, IntegerInstructions };
//     use crate::state_transition_circuit::{StateTranInput,StateTransitionCircuit};

//     use crate::voter_circuit::{VoterCircuit,VoterCircuitInput};


//     use super::*;

//     type BaseFieldEccChip<'chip> = halo2_ecc::ecc::BaseFieldEccChip<'chip, G1Affine>;
//     type Halo2Loader<'chip> = loader::halo2::Halo2Loader<G1Affine, BaseFieldEccChip<'chip>>;



//     fn succinct_verify<'a>(
//         svk: &Svk,
//         loader: &Rc<Halo2Loader<'a>>,
//         snark: &Snark,
//         preprocessed_digest: Option<AssignedValue<Fr>>
//     ) -> (Vec<Vec<AssignedValue<Fr>>>, Vec<KzgAccumulator<G1Affine, Rc<Halo2Loader<'a>>>>) {
//         let protocol = if let Some(preprocessed_digest) = preprocessed_digest {
//             let preprocessed_digest = loader.scalar_from_assigned(preprocessed_digest);
//             let protocol = snark.protocol.loaded_preprocessed_as_witness(loader, false);
//             let inputs = protocol.preprocessed
//                 .iter()
//                 .flat_map(|preprocessed| {
//                     let assigned = preprocessed.assigned();
//                     [assigned.x(), assigned.y()].map(|coordinate|
//                         loader.scalar_from_assigned(*coordinate.native())
//                     )
//                 })
//                 .chain(protocol.transcript_initial_state.clone())
//                 .collect_vec();
//             loader.assert_eq("", &poseidon(loader, &inputs), &preprocessed_digest);
//             protocol
//         } else {
//             snark.protocol.loaded(loader)
//         };

//         let instances = snark.instances
//             .iter()
//             .map(|instances| {
//                 instances
//                     .iter()
//                     .map(|instance| loader.assign_scalar(*instance))
//                     .collect_vec()
//             })
//             .collect_vec();
//         let mut transcript = PoseidonTranscript::<Rc<Halo2Loader>, _>::new::<SECURE_MDS>(
//             loader,
//             snark.proof()
//         );
//         let proof = PlonkSuccinctVerifier::read_proof(
//             svk,
//             &protocol,
//             &instances,
//             &mut transcript
//         ).unwrap();
//         let accumulators = PlonkSuccinctVerifier::verify(
//             svk,
//             &protocol,
//             &instances,
//             &proof
//         ).unwrap();

//         (
//             instances
//                 .into_iter()
//                 .map(|instance| {
//                     instance
//                         .into_iter()
//                         .map(|instance| instance.into_assigned())
//                         .collect()
//                 })
//                 .collect(),
//             accumulators,
//         )
//     }

//     fn select_accumulator<'a>(
//         loader: &Rc<Halo2Loader<'a>>,
//         condition: &AssignedValue<Fr>,
//         lhs: &KzgAccumulator<G1Affine, Rc<Halo2Loader<'a>>>,
//         rhs: &KzgAccumulator<G1Affine, Rc<Halo2Loader<'a>>>
//     ) -> Result<KzgAccumulator<G1Affine, Rc<Halo2Loader<'a>>>, Error> {
//         let [lhs, rhs]: [_; 2] = [lhs.lhs.assigned(), lhs.rhs.assigned()]
//             .iter()
//             .zip([rhs.lhs.assigned(), rhs.rhs.assigned()].iter())
//             .map(|(lhs, rhs)| {
//                 loader
//                     .ecc_chip()
//                     .select(
//                         loader.ctx_mut().main(),
//                         EcPoint::clone(lhs),
//                         EcPoint::clone(rhs),
//                         *condition
//                     )
//             })
//             .collect::<Vec<_>>()
//             .try_into()
//             .unwrap();
//         Ok(
//             KzgAccumulator::new(
//                 loader.ec_point_from_assigned(lhs),
//                 loader.ec_point_from_assigned(rhs)
//             )
//         )
//     }

//     fn accumulate<'a>(
//         loader: &Rc<Halo2Loader<'a>>,
//         accumulators: Vec<KzgAccumulator<G1Affine, Rc<Halo2Loader<'a>>>>,
//         as_proof: &[u8]
//     ) -> KzgAccumulator<G1Affine, Rc<Halo2Loader<'a>>> {
//         let mut transcript = PoseidonTranscript::<Rc<Halo2Loader>, _>::new::<SECURE_MDS>(
//             loader,
//             as_proof
//         );
//         let proof = As::read_proof(&Default::default(), &accumulators, &mut transcript).unwrap();
//         As::verify(&Default::default(), &accumulators, &proof).unwrap()
//     }

//     #[derive(serde::Serialize, serde::Deserialize)]
//     pub struct AggregationConfigParams {
//         pub degree: u32,
//         pub num_advice: usize,
//         pub num_lookup_advice: usize,
//         pub num_fixed: usize,
//         pub lookup_bits: usize,
//     }

//     #[derive(Clone)]
//     pub struct RecursionCircuit {
//         svk: Svk,
//         default_accumulator: KzgAccumulator<G1Affine, NativeLoader>,
//         //voter
//         vertical: Snark,
//         state_transition: Snark,
//         previous: Snark,
//         #[allow(dead_code)]
//         round: usize,
//         instances: Vec<Fr>,
//         as_proof: Vec<u8>,

//         inner: BaseCircuitBuilder<Fr>,
//     }

//     impl RecursionCircuit {
//         const PREPROCESSED_DIGEST_ROW: usize = 4 * LIMBS;
//         const INITIAL_STATE_ROW: usize = 4 * LIMBS + 1;
//         const STATE_ROW: usize = 4 * LIMBS + 2;
//         const ROUND_ROW: usize = 4 * LIMBS + 3;

//         pub fn new<F:BigPrimeField>(
//             params: &ParamsKZG<Bn256>,
//             vertical: Snark,
//             state_transition: Snark,
//             previous: Snark,
//             initial_app_state: StateTranInput<F>,
//             current_app_state: StateTranInput<F>,
//             round: usize,
//             config_params: BaseCircuitParams
//         ) -> Self {
//             let svk = params.get_g()[0].into();
//             let default_accumulator = KzgAccumulator::new(params.get_g()[1], params.get_g()[0]);

//             let succinct_verify = |snark: &Snark| {
//                 let mut transcript = PoseidonTranscript::<NativeLoader, _>::new::<SECURE_MDS>(
//                     snark.proof.as_slice()
//                 );
//                 let proof = PlonkSuccinctVerifier::read_proof(
//                     &svk,
//                     &snark.protocol,
//                     &snark.instances,
//                     &mut transcript
//                 ).unwrap();
//                 PlonkSuccinctVerifier::verify(
//                     &svk,
//                     &snark.protocol,
//                     &snark.instances,
//                     &proof
//                 ).unwrap()
//             };

//             let accumulators = iter
//                 ::empty()
//                 .chain(succinct_verify(&vertical))
//                 .chain(succinct_verify(&state_transition))
//                 .chain(
//                     (round > 0)
//                         .then(|| succinct_verify(&previous))
//                         .unwrap_or_else(|| {
//                             let num_accumulator = 1 + previous.protocol.accumulator_indices.len();
//                             vec![default_accumulator.clone(); num_accumulator]
//                         })
//                 )
//                 .collect_vec();

//             let (accumulator, as_proof) = {
//                 let mut transcript = PoseidonTranscript::<NativeLoader, _>::new::<SECURE_MDS>(
//                     Vec::new()
//                 );
//                 let accumulator = As::create_proof(
//                     &Default::default(),
//                     &accumulators,
//                     &mut transcript,
//                     OsRng
//                 ).unwrap();
//                 (accumulator, transcript.finalize())
//             };

//             let preprocessed_digest = {
//                 let inputs = previous.protocol.preprocessed
//                     .iter()
//                     .flat_map(|preprocessed| [preprocessed.x, preprocessed.y])
//                     .map(fe_to_fe)
//                     .chain(previous.protocol.transcript_initial_state)
//                     .collect_vec();
//                 poseidon(&NativeLoader, &inputs)
//             };
//             let instances = [
//                 accumulator.lhs.x,
//                 accumulator.lhs.y,
//                 accumulator.rhs.x,
//                 accumulator.rhs.y,
//             ]
//                 .into_iter()
//                 .flat_map(fe_to_limbs::<_, _, LIMBS, BITS>)
//                 .chain([
//                     preprocessed_digest,
//                     initial_app_state,
//                     current_app_state,
//                     Fr::from(round as u64),
//                 ])
//                 .collect();

//             let inner = BaseCircuitBuilder::new(false).use_params(config_params);
//             let mut circuit = Self {
//                 svk,
//                 default_accumulator,
//                 vertical,
//                 state_transition,
//                 previous,
//                 round,
//                 instances,
//                 as_proof,
//                 inner,
//             };
//             circuit.build();
//             circuit
//         }

//         fn build(&mut self) {
//             let range = self.inner.range_chip();
//             let main_gate = range.gate();
//             let pool = self.inner.pool(0);
//             let [preprocessed_digest, initial_state, state, round] = [
//                 self.instances[Self::PREPROCESSED_DIGEST_ROW],
//                 self.instances[Self::INITIAL_STATE_ROW],
//                 self.instances[Self::STATE_ROW],
//                 self.instances[Self::ROUND_ROW],
//             ].map(|instance| main_gate.assign_integer(pool, instance));
//             let first_round = main_gate.is_zero(pool.main(), round);
//             let not_first_round = main_gate.not(pool.main(), first_round);

//             let fp_chip = FpChip::<Fr>::new(&range, BITS, LIMBS);
//             let ecc_chip = BaseFieldEccChip::new(&fp_chip);
//             let loader = Halo2Loader::new(ecc_chip, mem::take(self.inner.pool(0)));

//             let (mut vertical_instances, vertical_accumulators) = succinct_verify(
//                 &self.svk,
//                 &loader,
//                 &self.vertical,
//                 None
//             );

//             let (mut state_transition_instances, state_transition_accumulators) = succinct_verify(
//                 &self.svk,
//                 &loader,
//                 &self.state_transition,
//                 None
//             );

//             let (mut previous_instances, previous_accumulators) = succinct_verify(
//                 &self.svk,
//                 &loader,
//                 &self.previous,
//                 Some(preprocessed_digest)
//             );

//             let default_accmulator = self.load_default_accumulator(&loader).unwrap();
//             let previous_accumulators = previous_accumulators
//                 .iter()
//                 .map(|previous_accumulator| {
//                     select_accumulator(
//                         &loader,
//                         &first_round,
//                         &default_accmulator,
//                         previous_accumulator
//                     ).unwrap()
//                 })
//                 .collect::<Vec<_>>();

//             let KzgAccumulator { lhs, rhs } = accumulate(
//                 &loader,
//                 [
//                     vertical_accumulators,
//                     state_transition_accumulators,
//                     previous_accumulators,
//                 ].concat(),
//                 self.as_proof()
//             );

//             let lhs = lhs.into_assigned();
//             let rhs = rhs.into_assigned();
//             let vertical_instances = vertical_instances.pop().unwrap();
//             let state_transition_instances = state_transition_instances.pop().unwrap();
//             let previous_instances = previous_instances.pop().unwrap();

//             let mut pool = loader.take_ctx();
//             let ctx = pool.main();

//             let muled_preprocessed_digest = main_gate.mul(
//                 ctx,
//                 preprocessed_digest,
//                 not_first_round
//             );
//             assert_eq!(
//                 muled_preprocessed_digest.value(),
//                 previous_instances[Self::PREPROCESSED_DIGEST_ROW].value()
//             );
//             ctx.constrain_equal(
//                 &muled_preprocessed_digest,
//                 &previous_instances[Self::PREPROCESSED_DIGEST_ROW]
//             );

//             // current[initial_state] == previous[state]
//             let muled_initial_state = main_gate.mul(ctx, initial_state, not_first_round);
//             assert_eq!(muled_initial_state.value(), previous_instances[Self::STATE_ROW].value());
//             ctx.constrain_equal(&muled_initial_state, &previous_instances[Self::STATE_ROW]);

//             // previous[state] == state_transition[lhs]
//             let muled_state = main_gate.mul(ctx, state_transition_instances[0], not_first_round);
//             assert_eq!(previous_instances[Self::STATE_ROW].value(), muled_state.value());
//             ctx.constrain_equal(&previous_instances[Self::STATE_ROW], &muled_state);

//             // vertical[rhs] == state_transition[rhs]
//             let muled_vertical = main_gate.mul(ctx, vertical_instances[0], not_first_round);
//             let muled_state_transition = main_gate.mul(
//                 ctx,
//                 state_transition_instances[1],
//                 not_first_round
//             );
//             assert_eq!(muled_vertical.value(), muled_state_transition.value());
//             ctx.constrain_equal(&muled_vertical, &muled_state_transition);

//             // state_transition[sum] == current[state]
//             let muled_state_transition = main_gate.mul(
//                 ctx,
//                 state_transition_instances[2],
//                 not_first_round
//             );
//             assert_eq!(state.value(), muled_state_transition.value());
//             ctx.constrain_equal(&state, &muled_state_transition);

//             // current[round] == previous[round] + 1
//             let added_round = main_gate.add(
//                 ctx,
//                 previous_instances[Self::ROUND_ROW],
//                 not_first_round
//             );
//             assert_eq!(added_round.value(), round.value());
//             ctx.constrain_equal(&round, &added_round);

//             *self.inner.pool(0) = pool;

//             self.inner.assigned_instances[0].extend(
//                 [lhs.x(), lhs.y(), rhs.x(), rhs.y()]
//                     .into_iter()
//                     .flat_map(|coordinate| coordinate.limbs())
//                     .chain([preprocessed_digest, initial_state, state, round].iter())
//                     .copied()
//             );
//         }

//         fn initial_snark(
//             params: &ParamsKZG<Bn256>,
//             vk: Option<&VerifyingKey<G1Affine>>,
//             config_params: BaseCircuitParams
//         ) -> Snark {
//             let mut snark = gen_dummy_snark::<RecursionCircuit>(params, vk, config_params);
//             let g = params.get_g();
//             snark.instances = vec![
//                 [g[1].x, g[1].y, g[0].x, g[0].y]
//                     .into_iter()
//                     .flat_map(fe_to_limbs::<_, _, LIMBS, BITS>)
//                     .chain([Fr::zero(); 4])
//                     .collect_vec()
//             ];
//             snark
//         }

//         fn as_proof(&self) -> &[u8] {
//             &self.as_proof[..]
//         }

//         fn load_default_accumulator<'a>(
//             &self,
//             loader: &Rc<Halo2Loader<'a>>
//         ) -> Result<KzgAccumulator<G1Affine, Rc<Halo2Loader<'a>>>, Error> {
//             let [lhs, rhs] = [self.default_accumulator.lhs, self.default_accumulator.rhs].map(
//                 |default| {
//                     let assigned = loader
//                         .ecc_chip()
//                         .assign_constant(&mut loader.ctx_mut(), default);
//                     loader.ec_point_from_assigned(assigned)
//                 }
//             );
//             Ok(KzgAccumulator::new(lhs, rhs))
//         }
//     }

//     impl Circuit<Fr> for RecursionCircuit {
//         type Config = BaseConfig<Fr>;
//         type FloorPlanner = SimpleFloorPlanner;
//         type Params = BaseCircuitParams;

//         fn params(&self) -> Self::Params {
//             self.inner.params()
//         }

//         fn without_witnesses(&self) -> Self {
//             unimplemented!()
//         }

//         fn configure_with_params(
//             meta: &mut ConstraintSystem<Fr>,
//             params: Self::Params
//         ) -> Self::Config {
//             BaseCircuitBuilder::configure_with_params(meta, params)
//         }

//         fn configure(_: &mut ConstraintSystem<Fr>) -> Self::Config {
//             unreachable!()
//         }

//         fn synthesize(
//             &self,
//             config: Self::Config,
//             layouter: impl Layouter<Fr>
//         ) -> Result<(), Error> {
//             self.inner.synthesize(config, layouter)
//         }
//     }

//     impl CircuitExt<Fr> for RecursionCircuit {
//         fn num_instance() -> Vec<usize> {
//             // [..lhs, ..rhs, preprocessed_digest, initial_state, state, round]
//             vec![4 * LIMBS + 4]
//         }

//         fn instances(&self) -> Vec<Vec<Fr>> {
//             vec![self.instances.clone()]
//         }

//         fn accumulator_indices() -> Option<Vec<(usize, usize)>> {
//             Some((0..4 * LIMBS).map(|idx| (0, idx)).collect())
//         }

//         fn selectors(config: &Self::Config) -> Vec<Selector> {
//             config
//                 .gate()
//                 .basic_gates[0].iter()
//                 .map(|gate| gate.q_enable)
//                 .collect()
//         }
//     }

//     pub fn gen_recursion_pk<Vertical: CircuitExt<Fr>, StateTransition: CircuitExt<Fr>>(
//         vertical_params: &ParamsKZG<Bn256>,
//         state_transition_params: &ParamsKZG<Bn256>,
//         recursion_params: &ParamsKZG<Bn256>,
//         vertical_vk: &VerifyingKey<G1Affine>,
//         state_transition_vk: &VerifyingKey<G1Affine>,
//         vertical_config: Vertical::Params,
//         state_transition_config: StateTransition::Params,
//         recursion_config: BaseCircuitParams
//     )
//         -> ProvingKey<G1Affine>
//         where Vertical::Params: Clone, StateTransition::Params: Clone
//     {
//         let vertical_dummy_snark = gen_dummy_snark::<Vertical>(
//             vertical_params,
//             Some(vertical_vk),
//             vertical_config.clone()
//         );
//         let state_transition_dummy_snark = gen_dummy_snark::<StateTransition>(
//             state_transition_params,
//             Some(state_transition_vk),
//             state_transition_config.clone()
//         );
//         let initial_snark = RecursionCircuit::initial_snark(
//             recursion_params,
//             None,
//             recursion_config.clone()
//         );

//         let recursion = RecursionCircuit::new(
//             recursion_params,
//             vertical_dummy_snark,
//             state_transition_dummy_snark,
//             initial_snark,
//             Fr::zero(),
//             Fr::zero(),
//             0,
//             recursion_config
//         );
//         // we cannot auto-configure the circuit because dummy_snark must know the configuration beforehand
//         // uncomment the following line only in development to test and print out the optimal configuration ahead of time
//         // recursion.inner.0.builder.borrow().config(recursion_params.k() as usize, Some(10));
//         gen_pk(recursion_params, &recursion)
//     }

//     pub fn gen_recursion_snark<
//         Vertical: CircuitExt<Fr>,
//         StateTransition: CircuitExt<Fr>
//     >(
//         vertical_params: &ParamsKZG<Bn256>,
//         state_transition_params: &ParamsKZG<Bn256>,
//         recursion_params: &ParamsKZG<Bn256>,
//         vertical_pk: &ProvingKey<G1Affine>,
//         state_transition_pk: &ProvingKey<G1Affine>,
//         recursion_pk: &ProvingKey<G1Affine>,
//         initial_state: StateTranInput<Fr>,
//         initial_app_state: Vertical::Input,
//         inputs: Vec<Vertical::Input>,
//         vertical_config: BaseCircuitParams,
//         state_transition_config: BaseCircuitParams,
//         recursion_config: BaseCircuitParams
//     ) -> (Fr, Snark) {
//         let mut app_state = initial_app_state.clone();
//         let mut state = initial_state;

//         println!(r"init Vo state: {:?}", Vertical::to_fe(app_state.clone()));
//         println!("init state: {:?}", StateTransition::to_fe_fe(state.clone()));

//         let mut app = Vertical::new(vertical_config.clone(), app_state.clone());
//         let mut state_transition = StateTransition::new(state_transition_config.clone(), state); // state is nothing but (0, app_state, 0 + app_state)

//         let mut previous = RecursionCircuit::initial_snark(
//             recursion_params,
//             Some(recursion_pk.get_vk()),
//             recursion_config.clone()
//         );
//         println!("init previous snark instances: {:?}", previous.instances);

//         for (round, input) in inputs.into_iter().enumerate() {
//             println!("round: {}", round);

//             println!("Generate app snark");
//             let app_snark = gen_snark(vertical_params, vertical_pk, app);
//             println!("app snark instances: {:?}", app_snark.instances);
//             let state_transtion_snark = gen_snark(
//                 state_transition_params,
//                 state_transition_pk,
//                 state_transition
//             );
//             println!("state transition snark instances: {:?}", state_transtion_snark.instances);

//             let recursion = RecursionCircuit::new(
//                 recursion_params,
//                 app_snark,
//                 state_transtion_snark.clone(),
//                 previous,
//                 state_transtion_snark.clone().instances[0][0].clone(),
//                 state_transtion_snark.clone().instances[0][2].clone(),
//                 round,
//                 recursion_config.clone()
//             );
//             println!("Generate recursion snark");
//             previous = gen_snark(recursion_params, recursion_pk, recursion);
//             println!("recursion snark instances: {:?}", previous.instances);

//             app_state = input;
//             state = StateTransition::from_fe_fe((
//                 state_transtion_snark.instances[0][2],
//                 Vertical::to_fe(app_state.clone()),
//             ));

//             println!("app state: {:?}", Vertical::to_fe(app_state.clone()));
//             println!("state: {:?}", StateTransition::to_fe_fe(state.clone()));

//             app = Vertical::new(vertical_config.clone(), app_state.clone());
//             state_transition = StateTransition::new(state_transition_config.clone(), state);
//         }

//         (previous.instances[0][previous.instances[0].len() - 2], previous)
//     }
// }

// #[cfg(test)]
// mod test {
//     use ark_std::{ end_timer, start_timer };
//     use halo2_base::{
//         gates::circuit::BaseCircuitParams,
//         halo2_proofs::{
//             dev::MockProver,
//             halo2curves::bn256::Fr,
//             plonk::Circuit,
//             poly::commitment::ParamsProver,
//         },
//         utils::{ fs::gen_srs, testing::base_test },
//     };
//     use snark_verifier_sdk::{ snark_verifier::verifier::SnarkVerifier, NativeLoader };

//     use super::{
//         gen_pk,
//         recursion::{ self, AggregationConfigParams, RecursionExt },
//         state_transition,
//         vertical,
//         PlonkVerifier,
//         PoseidonTranscript,
//     };

//     #[test]
//     fn test_recursion() {
//         let app_params = gen_srs(5);
//         let state_params = gen_srs(5);

//         let recursion_config = AggregationConfigParams {
//             degree: 21,
//             num_advice: 8,
//             num_lookup_advice: 1,
//             num_fixed: 1,
//             lookup_bits: 20,
//         };
//         let k = recursion_config.degree;
//         let recursion_params = gen_srs(k);
//         let config_params = BaseCircuitParams {
//             k: k as usize,
//             num_advice_per_phase: vec![recursion_config.num_advice],
//             num_lookup_advice_per_phase: vec![recursion_config.num_lookup_advice],
//             num_fixed: recursion_config.num_fixed,
//             lookup_bits: Some(recursion_config.lookup_bits),
//             num_instance_columns: 1,
//         };

//         let app_config = BaseCircuitParams {
//             k: 5,
//             num_advice_per_phase: vec![1],
//             num_lookup_advice_per_phase: vec![0, 0, 0],
//             num_fixed: 1,
//             lookup_bits: None,
//             num_instance_columns: 1,
//         };
//         let app = vertical::App::new(app_config.clone(), Fr::from(2u64));
//         let app_pk = gen_pk(&app_params, &app);
//         let app_vk = app_pk.get_vk();

//         let state_config = BaseCircuitParams {
//             k: 5,
//             num_advice_per_phase: vec![1],
//             num_lookup_advice_per_phase: vec![0, 0, 0],
//             num_fixed: 1,
//             lookup_bits: None,
//             num_instance_columns: 1,
//         };
//         let state = state_transition::Add::new(state_config.clone(), (
//             Fr::from(0u64),
//             Fr::from(2u64),
//         ));
//         let state_pk = gen_pk(&state_params, &state);
//         let state_vk = state_pk.get_vk();

//         let pk_time = start_timer!(|| "Generate recursion pk");
//         let recursion_pk = recursion::gen_recursion_pk::<vertical::App, state_transition::Add>(
//             &app_params,
//             &state_params,
//             &recursion_params,
//             app_vk,
//             state_vk,
//             app_config.clone(),
//             state_config.clone(),
//             config_params.clone()
//         );
//         end_timer!(pk_time);

//         let num_round = 3;
//         let pf_time = start_timer!(|| "Generate full recurs ive snark");
//         let (final_state, snark) = recursion::gen_recursion_snark::<
//             vertical::App,
//             state_transition::Add
//         >(
//             &app_params,
//             &state_params,
//             &recursion_params,
//             &app_pk,
//             &state_pk,
//             &recursion_pk,
//             (Fr::from(0u64), Fr::from(0u64)),
//             Fr::from(0u64),
//             (0..num_round).map(|_| Fr::from(2u64)).collect(),
//             app_config.clone(),
//             state_config.clone(),
//             config_params.clone()
//         );
//         end_timer!(pf_time);
//         println!("Final state: {:?}", final_state);
//         println!("Snark Instances: {:?}", snark.instances);

//         {
//             let dk = (
//                 recursion_params.get_g()[0],
//                 recursion_params.g2(),
//                 recursion_params.s_g2(),
//             ).into();
//             let mut transcript = PoseidonTranscript::<NativeLoader, _>::new::<0>(
//                 snark.proof.as_slice()
//             );
//             let proof = PlonkVerifier::read_proof(
//                 &dk,
//                 &snark.protocol,
//                 &snark.instances,
//                 &mut transcript
//             ).unwrap();
//             PlonkVerifier::verify(&dk, &snark.protocol, &snark.instances, &proof).unwrap();
//         }
//     }
// }
