#![allow(clippy::type_complexity)]

use halo2_base::halo2_proofs;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::{Circuit, ConstraintSystem, Error, ProvingKey, Selector, VerifyingKey},
};
use itertools::Itertools;
use rand_chacha::rand_core::OsRng;
use snark_verifier_sdk::snark_verifier::{
    loader::{self, native::NativeLoader, Loader, ScalarLoader},
    pcs::{
        kzg::{Gwc19, KzgAccumulator, KzgAs, KzgSuccinctVerifyingKey, LimbsEncoding},
        AccumulationScheme, AccumulationSchemeProver,
    },
    system::halo2::{self},
    util::{
        arithmetic::{fe_to_fe, fe_to_limbs},
        hash,
    },
    verifier::{self, SnarkVerifier},
};
use std::{iter, rc::Rc};

const LIMBS: usize = 3;
const BITS: usize = 88;
const T: usize = 3;
const RATE: usize = 2;
const R_F: usize = 8;
const R_P: usize = 57;
const SECURE_MDS: usize = 0;

type Svk = KzgSuccinctVerifyingKey<G1Affine>;
type As = KzgAs<Bn256, Gwc19>;
type PlonkVerifier = verifier::plonk::PlonkVerifier<As, LimbsEncoding<LIMBS, BITS>>;
type PlonkSuccinctVerifier = verifier::plonk::PlonkSuccinctVerifier<As, LimbsEncoding<LIMBS, BITS>>;
type Poseidon<L> = hash::Poseidon<Fr, L, T, RATE>;
type PoseidonTranscript<L, S> =
    halo2::transcript::halo2::PoseidonTranscript<G1Affine, L, S, T, RATE, R_F, R_P>;

pub fn poseidon<L: Loader<G1Affine>>(loader: &L, inputs: &[L::LoadedScalar]) -> L::LoadedScalar {
    // warning: generating a new spec is time intensive, use lazy_static in production
    let mut hasher = Poseidon::new::<R_F, R_P, SECURE_MDS>(loader);
    hasher.update(inputs);
    hasher.squeeze()
}

pub mod recursion {
    use std::mem;

    use halo2_base::{
        gates::{
            circuit::{builder::BaseCircuitBuilder, BaseCircuitParams, BaseConfig},
            GateInstructions, RangeInstructions,
        },
        halo2_proofs::poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
        AssignedValue,
    };
    use halo2_ecc::{bn254::FpChip, ecc::EcPoint};
    use snark_verifier_sdk::{
        gen_pk,
        halo2::{gen_dummy_snark, gen_snark_gwc},
        snark_verifier::loader::halo2::{EccInstructions, IntegerInstructions},
        CircuitExt, Snark,
    };

    use super::*;

    type BaseFieldEccChip<'chip> = halo2_ecc::ecc::BaseFieldEccChip<'chip, G1Affine>;
    type Halo2Loader<'chip> = loader::halo2::Halo2Loader<G1Affine, BaseFieldEccChip<'chip>>;

    pub trait StateTransition {
        type Input;

        fn new(state: Vec<Fr>) -> Self;

        fn state_transition(&self, input: Vec<Self::Input>) -> Vec<Fr>;
    }

    fn succinct_verify<'a>(
        svk: &Svk,
        loader: &Rc<Halo2Loader<'a>>,
        snark: &Snark,
        preprocessed_digest: Option<AssignedValue<Fr>>,
    ) -> (
        Vec<Vec<AssignedValue<Fr>>>,
        Vec<KzgAccumulator<G1Affine, Rc<Halo2Loader<'a>>>>,
    ) {
        let protocol = if let Some(preprocessed_digest) = preprocessed_digest {
            let preprocessed_digest = loader.scalar_from_assigned(preprocessed_digest);
            let protocol = snark.protocol.loaded_preprocessed_as_witness(loader, false);
            let inputs = protocol
                .preprocessed
                .iter()
                .flat_map(|preprocessed| {
                    let assigned = preprocessed.assigned();
                    [assigned.x(), assigned.y()]
                        .map(|coordinate| loader.scalar_from_assigned(*coordinate.native()))
                })
                .chain(protocol.transcript_initial_state.clone())
                .collect_vec();
            loader.assert_eq("", &poseidon(loader, &inputs), &preprocessed_digest);
            protocol
        } else {
            snark.protocol.loaded(loader)
        };

        let instances = snark
            .instances
            .iter()
            .map(|instances| {
                instances
                    .iter()
                    .map(|instance| loader.assign_scalar(*instance))
                    .collect_vec()
            })
            .collect_vec();
        let mut transcript =
            PoseidonTranscript::<Rc<Halo2Loader>, _>::new::<SECURE_MDS>(loader, snark.proof());
        let proof =
            PlonkSuccinctVerifier::read_proof(svk, &protocol, &instances, &mut transcript).unwrap();
        let accumulators =
            PlonkSuccinctVerifier::verify(svk, &protocol, &instances, &proof).unwrap();

        (
            instances
                .into_iter()
                .map(|instance| {
                    instance
                        .into_iter()
                        .map(|instance| instance.into_assigned())
                        .collect()
                })
                .collect(),
            accumulators,
        )
    }

    fn select_accumulator<'a>(
        loader: &Rc<Halo2Loader<'a>>,
        condition: &AssignedValue<Fr>,
        lhs: &KzgAccumulator<G1Affine, Rc<Halo2Loader<'a>>>,
        rhs: &KzgAccumulator<G1Affine, Rc<Halo2Loader<'a>>>,
    ) -> Result<KzgAccumulator<G1Affine, Rc<Halo2Loader<'a>>>, Error> {
        let [lhs, rhs]: [_; 2] = [lhs.lhs.assigned(), lhs.rhs.assigned()]
            .iter()
            .zip([rhs.lhs.assigned(), rhs.rhs.assigned()].iter())
            .map(|(lhs, rhs)| {
                loader.ecc_chip().select(
                    loader.ctx_mut().main(),
                    EcPoint::clone(lhs),
                    EcPoint::clone(rhs),
                    *condition,
                )
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        Ok(KzgAccumulator::new(
            loader.ec_point_from_assigned(lhs),
            loader.ec_point_from_assigned(rhs),
        ))
    }

    fn accumulate<'a>(
        loader: &Rc<Halo2Loader<'a>>,
        accumulators: Vec<KzgAccumulator<G1Affine, Rc<Halo2Loader<'a>>>>,
        as_proof: &[u8],
    ) -> KzgAccumulator<G1Affine, Rc<Halo2Loader<'a>>> {
        let mut transcript =
            PoseidonTranscript::<Rc<Halo2Loader>, _>::new::<SECURE_MDS>(loader, as_proof);
        let proof = As::read_proof(&Default::default(), &accumulators, &mut transcript).unwrap();
        As::verify(&Default::default(), &accumulators, &proof).unwrap()
    }

    #[derive(serde::Serialize, serde::Deserialize)]
    pub struct AggregationConfigParams {
        pub degree: u32,
        pub num_advice: usize,
        pub num_lookup_advice: usize,
        pub num_fixed: usize,
        pub lookup_bits: usize,
    }

    #[derive(Clone)]
    pub struct RecursionCircuit {
        svk: Svk,
        default_accumulator: KzgAccumulator<G1Affine, NativeLoader>,
        app: Snark,
        previous: Snark,
        #[allow(dead_code)]
        round: usize,
        instances: Vec<Fr>,
        as_proof: Vec<u8>,

        inner: BaseCircuitBuilder<Fr>,
    }

    impl RecursionCircuit {
        const PREPROCESSED_DIGEST_ROW: usize = 4 * LIMBS;
        const INITIAL_STATE_ROW: usize = 4 * LIMBS + 1;
        const STATE_ROW: usize = 4 * LIMBS + 27;
        const ROUND_ROW: usize = 4 * LIMBS + 53;

        pub fn new(
            params: &ParamsKZG<Bn256>,
            app: Snark,
            previous: Snark,
            initial_state: Vec<Fr>,
            state: Vec<Fr>,
            round: usize,
            config_params: BaseCircuitParams,
        ) -> Self {
            let svk = params.get_g()[0].into();
            let default_accumulator = KzgAccumulator::new(params.get_g()[1], params.get_g()[0]);

            let succinct_verify = |snark: &Snark| {
                let mut transcript = PoseidonTranscript::<NativeLoader, _>::new::<SECURE_MDS>(
                    snark.proof.as_slice(),
                );
                let proof = PlonkSuccinctVerifier::read_proof(
                    &svk,
                    &snark.protocol,
                    &snark.instances,
                    &mut transcript,
                )
                .unwrap();
                PlonkSuccinctVerifier::verify(&svk, &snark.protocol, &snark.instances, &proof)
                    .unwrap()
            };

            let accumulators = iter::empty()
                .chain(succinct_verify(&app))
                .chain(
                    (round > 0)
                        .then(|| succinct_verify(&previous))
                        .unwrap_or_else(|| {
                            let num_accumulator = 1 + previous.protocol.accumulator_indices.len();
                            vec![default_accumulator.clone(); num_accumulator]
                        }),
                )
                .collect_vec();

            let (accumulator, as_proof) = {
                let mut transcript =
                    PoseidonTranscript::<NativeLoader, _>::new::<SECURE_MDS>(Vec::new());
                let accumulator =
                    As::create_proof(&Default::default(), &accumulators, &mut transcript, OsRng)
                        .unwrap();
                (accumulator, transcript.finalize())
            };

            let preprocessed_digest = {
                let inputs = previous
                    .protocol
                    .preprocessed
                    .iter()
                    .flat_map(|preprocessed| [preprocessed.x, preprocessed.y])
                    .map(fe_to_fe)
                    .chain(previous.protocol.transcript_initial_state)
                    .collect_vec();
                poseidon(&NativeLoader, &inputs)
            };
            let instances = [
                accumulator.lhs.x,
                accumulator.lhs.y,
                accumulator.rhs.x,
                accumulator.rhs.y,
            ]
            .into_iter()
            .flat_map(fe_to_limbs::<_, _, LIMBS, BITS>)
            .chain([preprocessed_digest])
            .chain(initial_state)
            .chain(state)
            .chain([Fr::from(round as u64)])
            .collect();

            let inner = BaseCircuitBuilder::new(false).use_params(config_params);
            let mut circuit = Self {
                svk,
                default_accumulator,
                app,
                previous,
                round,
                instances,
                as_proof,
                inner,
            };
            circuit.build();
            circuit
        }

        fn build(&mut self) {
            let range = self.inner.range_chip();
            let main_gate = range.gate();
            let pool = self.inner.pool(0);

            let preprocessed_digest =
                main_gate.assign_integer(pool, self.instances[Self::PREPROCESSED_DIGEST_ROW]);
            let initial_state = self.instances[Self::INITIAL_STATE_ROW..Self::STATE_ROW]
                .iter()
                .map(|instance| main_gate.assign_integer(pool, *instance))
                .collect_vec();
            let state = self.instances[Self::STATE_ROW..Self::ROUND_ROW]
                .iter()
                .map(|instance| main_gate.assign_integer(pool, *instance))
                .collect_vec();
            let round = main_gate.assign_integer(pool, self.instances[Self::ROUND_ROW]);

            let first_round = main_gate.is_zero(pool.main(), round);
            let not_first_round = main_gate.not(pool.main(), first_round);

            let fp_chip = FpChip::<Fr>::new(&range, BITS, LIMBS);
            let ecc_chip = BaseFieldEccChip::new(&fp_chip);
            let loader = Halo2Loader::new(ecc_chip, mem::take(self.inner.pool(0)));
            let (mut app_instances, app_accumulators) =
                succinct_verify(&self.svk, &loader, &self.app, None);
            let (mut previous_instances, previous_accumulators) = succinct_verify(
                &self.svk,
                &loader,
                &self.previous,
                Some(preprocessed_digest),
            );

            let default_accmulator = self.load_default_accumulator(&loader).unwrap();
            let previous_accumulators = previous_accumulators
                .iter()
                .map(|previous_accumulator| {
                    select_accumulator(
                        &loader,
                        &first_round,
                        &default_accmulator,
                        previous_accumulator,
                    )
                    .unwrap()
                })
                .collect::<Vec<_>>();

            let KzgAccumulator { lhs, rhs } = accumulate(
                &loader,
                [app_accumulators, previous_accumulators].concat(),
                self.as_proof(),
            );

            let lhs = lhs.into_assigned();
            let rhs = rhs.into_assigned();
            let app_instances = app_instances.pop().unwrap();
            let previous_instances = previous_instances.pop().unwrap();

            let mut pool = loader.take_ctx();
            let ctx = pool.main();

            let lhs_preprocessed_digest = main_gate.mul(ctx, preprocessed_digest, not_first_round);
            ctx.constrain_equal(
                &lhs_preprocessed_digest,
                &previous_instances[Self::PREPROCESSED_DIGEST_ROW],
            );

            for (lhs, rhs) in initial_state
                .iter()
                .zip(previous_instances[Self::INITIAL_STATE_ROW..Self::STATE_ROW].iter())
            {
                let lhs = main_gate.mul(ctx, *lhs, not_first_round);
                ctx.constrain_equal(&lhs, rhs);
            }

            for (lhs, rhs) in state.iter().zip(app_instances.iter()) {
                ctx.constrain_equal(lhs, rhs);
            }

            let rhs_round =
                main_gate.add(ctx, not_first_round, previous_instances[Self::ROUND_ROW]);
            ctx.constrain_equal(&round, &rhs_round);

            *self.inner.pool(0) = pool;

            self.inner.assigned_instances[0].extend(
                [lhs.x(), lhs.y(), rhs.x(), rhs.y()]
                    .into_iter()
                    .flat_map(|coordinate| coordinate.limbs())
                    .chain([&preprocessed_digest])
                    .chain(&initial_state)
                    .chain(&state)
                    .chain([&round])
                    .copied(),
            );
        }

        fn initial_snark(
            params: &ParamsKZG<Bn256>,
            vk: Option<&VerifyingKey<G1Affine>>,
            config_params: BaseCircuitParams,
        ) -> Snark {
            let mut snark = gen_dummy_snark::<RecursionCircuit, As>(
                params,
                vk,
                vec![4 * LIMBS + 54],
                config_params,
            );
            let g = params.get_g();
            snark.instances = vec![[g[1].x, g[1].y, g[0].x, g[0].y]
                .into_iter()
                .flat_map(fe_to_limbs::<_, _, LIMBS, BITS>)
                .chain([Fr::zero(); 54])
                .collect_vec()];
            snark
        }

        fn as_proof(&self) -> &[u8] {
            &self.as_proof[..]
        }

        fn load_default_accumulator<'a>(
            &self,
            loader: &Rc<Halo2Loader<'a>>,
        ) -> Result<KzgAccumulator<G1Affine, Rc<Halo2Loader<'a>>>, Error> {
            let [lhs, rhs] =
                [self.default_accumulator.lhs, self.default_accumulator.rhs].map(|default| {
                    let assigned = loader
                        .ecc_chip()
                        .assign_constant(&mut loader.ctx_mut(), default);
                    loader.ec_point_from_assigned(assigned)
                });
            Ok(KzgAccumulator::new(lhs, rhs))
        }
    }

    impl Circuit<Fr> for RecursionCircuit {
        type Config = BaseConfig<Fr>;
        type FloorPlanner = SimpleFloorPlanner;
        type Params = BaseCircuitParams;

        fn params(&self) -> Self::Params {
            self.inner.params()
        }

        fn without_witnesses(&self) -> Self {
            unimplemented!()
        }

        fn configure_with_params(
            meta: &mut ConstraintSystem<Fr>,
            params: Self::Params,
        ) -> Self::Config {
            BaseCircuitBuilder::configure_with_params(meta, params)
        }

        fn configure(_: &mut ConstraintSystem<Fr>) -> Self::Config {
            unreachable!()
        }

        fn synthesize(
            &self,
            config: Self::Config,
            layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            self.inner.synthesize(config, layouter)
        }
    }

    impl CircuitExt<Fr> for RecursionCircuit {
        fn num_instance(&self) -> Vec<usize> {
            // [..lhs, ..rhs, preprocessed_digest, initial_state, state, round]
            vec![4 * LIMBS + 54]
        }

        fn instances(&self) -> Vec<Vec<Fr>> {
            vec![self.instances.clone()]
        }

        fn accumulator_indices() -> Option<Vec<(usize, usize)>> {
            Some((0..4 * LIMBS).map(|idx| (0, idx)).collect())
        }

        fn selectors(config: &Self::Config) -> Vec<Selector> {
            config.gate().basic_gates[0]
                .iter()
                .map(|gate| gate.q_enable)
                .collect()
        }
    }

    pub fn gen_recursion_pk<ConcreteCircuit: CircuitExt<Fr>>(
        recursion_params: &ParamsKZG<Bn256>,
        app_params: &ParamsKZG<Bn256>,
        app_vk: &VerifyingKey<G1Affine>,
        recursion_config: BaseCircuitParams,
        app_config: ConcreteCircuit::Params,
    ) -> ProvingKey<G1Affine>
    where
        ConcreteCircuit::Params: Clone,
    {
        let recursion = RecursionCircuit::new(
            recursion_params,
            gen_dummy_snark::<ConcreteCircuit, As>(
                app_params,
                Some(app_vk),
                vec![4 * LIMBS + 54],
                app_config,
            ),
            RecursionCircuit::initial_snark(recursion_params, None, recursion_config.clone()),
            vec![Fr::zero(); 26],
            vec![Fr::zero(); 26],
            0,
            recursion_config,
        );
        // we cannot auto-configure the circuit because dummy_snark must know the configuration beforehand
        // uncomment the following line only in development to test and print out the optimal configuration ahead of time
        // recursion.inner.0.builder.borrow().config(recursion_params.k() as usize, Some(10));
        gen_pk(recursion_params, &recursion, None)
    }

    pub fn gen_recursion_snark<ConcreteCircuit: CircuitExt<Fr> + StateTransition>(
        app_params: &ParamsKZG<Bn256>,
        recursion_params: &ParamsKZG<Bn256>,
        app_pk: &ProvingKey<G1Affine>,
        recursion_pk: &ProvingKey<G1Affine>,
        initial_state: Vec<Fr>,
        inputs: Vec<Vec<ConcreteCircuit::Input>>,
        config_params: BaseCircuitParams,
    ) -> (Vec<Fr>, Snark) {
        let mut state = initial_state.clone();
        let mut app = ConcreteCircuit::new(state.clone());
        let mut previous = RecursionCircuit::initial_snark(
            recursion_params,
            Some(recursion_pk.get_vk()),
            config_params.clone(),
        );
        for (round, input) in inputs.into_iter().enumerate() {
            state = app.state_transition(input);
            println!("Generate app snark");
            let app_snark = gen_snark_gwc(app_params, app_pk, app, None::<&str>);
            let recursion = RecursionCircuit::new(
                recursion_params,
                app_snark,
                previous,
                initial_state.clone(),
                state.clone(),
                round,
                config_params.clone(),
            );
            println!("Generate recursion snark");
            previous = gen_snark_gwc(recursion_params, recursion_pk, recursion, None::<&str>);
            app = ConcreteCircuit::new(state.clone());
        }
        (state, previous)
    }
}
