use halo2_base::{
    gates::{
        circuit::{
            builder::BaseCircuitBuilder,
            BaseCircuitParams,
            BaseConfig,
            CircuitBuilderStage,
        },
        GateInstructions,
        RangeInstructions,
    }, halo2_proofs::{
        arithmetic::Field,
        circuit::{ Layouter, SimpleFloorPlanner },
        halo2curves::{ bn256::{ Bn256, G1Affine, Fq }, grumpkin::Fq as Fr },
        plonk::{ Circuit, ConstraintSystem, Error, ProvingKey, Selector, VerifyingKey },
        poly::{ commitment::ParamsProver, kzg::commitment::ParamsKZG },
    }, utils::fs::gen_srs, AssignedValue
};
use halo2_ecc::{ ecc::EcPoint, fields::fp };
use itertools::Itertools;
use snark_verifier_sdk::{
    gen_pk, halo2::{
        aggregation::{ AggregationCircuit, AggregationConfigParams, VerifierUniversality }, gen_dummy_snark, gen_dummy_snark_from_vk, gen_snark, gen_snark_shplonk
    }, snark_verifier::{
        loader::{ halo2::{ EccInstructions, IntegerInstructions }, Loader, ScalarLoader },
        pcs::{
            kzg::{ Gwc19, KzgAccumulator, KzgAs, KzgSuccinctVerifyingKey, LimbsEncoding },
            AccumulationScheme,
            AccumulationSchemeProver,
        },
        util::arithmetic::{ fe_to_fe, fe_to_limbs },
        verifier::SnarkVerifier,
    }, CircuitExt, NativeLoader, Snark, SHPLONK
};
use std::{ iter, mem, ops::Add, rc::Rc };
use rand_chacha::rand_core::OsRng;
pub mod aggregator;
pub mod merkletree;
pub mod utils;

const LIMBS: usize = 3;
const BITS: usize = 88;
const T: usize = 3;
const RATE: usize = 2;
const R_F: usize = 8;
const R_P: usize = 57;
const SECURE_MDS: usize = 0;

type Svk = KzgSuccinctVerifyingKey<G1Affine>;
type As = KzgAs<Bn256, Gwc19>;
type PlonkVerifier = snark_verifier_sdk::snark_verifier::verifier::plonk::PlonkVerifier<
    As,
    LimbsEncoding<LIMBS, BITS>
>;
type PlonkSuccinctVerifier =
    snark_verifier_sdk::snark_verifier::verifier::plonk::PlonkSuccinctVerifier<
        As,
        LimbsEncoding<LIMBS, BITS>
    >;
type Poseidon<L> = snark_verifier_sdk::snark_verifier::util::hash::Poseidon<Fr, L, T, RATE>;
type PoseidonTranscript<L, S> =
    snark_verifier_sdk::snark_verifier::system::halo2::transcript::halo2::PoseidonTranscript<
        G1Affine,
        L,
        S,
        T,
        RATE,
        R_F,
        R_P
    >;
type BaseFieldEccChip<'chip> = halo2_ecc::ecc::BaseFieldEccChip<'chip, G1Affine>;
pub type FpChip<'range, F> = fp::FpChip<'range, F, Fq>;
type Halo2Loader<'chip> = snark_verifier_sdk::snark_verifier::loader::halo2::Halo2Loader<
    G1Affine,
    BaseFieldEccChip<'chip>
>;

fn succinct_verify<'a>(
    svk: &Svk,
    loader: &Rc<Halo2Loader<'a>>,
    snark: &Snark,
    preprocessed_digest: Option<AssignedValue<Fr>>
) -> (Vec<Vec<AssignedValue<Fr>>>, Vec<KzgAccumulator<G1Affine, Rc<Halo2Loader<'a>>>>) {
    let protocol = if let Some(preprocessed_digest) = preprocessed_digest {
        let preprocessed_digest = loader.scalar_from_assigned(preprocessed_digest);
        let protocol = snark.protocol.loaded_preprocessed_as_witness(loader, false);
        let inputs = protocol.preprocessed
            .iter()
            .flat_map(|preprocessed| {
                let assigned = preprocessed.assigned();
                [assigned.x(), assigned.y()].map(|coordinate|
                    loader.scalar_from_assigned(*coordinate.native())
                )
            })
            .chain(protocol.transcript_initial_state.clone())
            .collect_vec();
        loader.assert_eq("", &poseidon(loader, &inputs), &preprocessed_digest);
        protocol
    } else {
        snark.protocol.loaded(loader)
    };

    let instances = snark.instances
        .iter()
        .map(|instances| {
            instances
                .iter()
                .map(|instance| loader.assign_scalar(*instance))
                .collect_vec()
        })
        .collect_vec();
    let mut transcript = PoseidonTranscript::<Rc<Halo2Loader>, _>::new::<SECURE_MDS>(
        loader,
        snark.proof()
    );
    let proof = PlonkSuccinctVerifier::read_proof(
        svk,
        &protocol,
        &instances,
        &mut transcript
    ).unwrap();
    let accumulators = PlonkSuccinctVerifier::verify(svk, &protocol, &instances, &proof).unwrap();

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
pub fn poseidon<L: Loader<G1Affine>>(loader: &L, inputs: &[L::LoadedScalar]) -> L::LoadedScalar {
    // warning: generating a new spec is time intensive, use lazy_static in production
    let mut hasher = Poseidon::new::<R_F, R_P, SECURE_MDS>(loader);
    hasher.update(inputs);
    hasher.squeeze()
}
fn select_accumulator<'a>(
    loader: &Rc<Halo2Loader<'a>>,
    condition: &AssignedValue<Fr>,
    lhs: &KzgAccumulator<G1Affine, Rc<Halo2Loader<'a>>>,
    rhs: &KzgAccumulator<G1Affine, Rc<Halo2Loader<'a>>>
) -> Result<KzgAccumulator<G1Affine, Rc<Halo2Loader<'a>>>, Error> {
    let [lhs, rhs]: [_; 2] = [lhs.lhs.assigned(), lhs.rhs.assigned()]
        .iter()
        .zip([rhs.lhs.assigned(), rhs.rhs.assigned()].iter())
        .map(|(lhs, rhs)| {
            loader
                .ecc_chip()
                .select(
                    loader.ctx_mut().main(),
                    EcPoint::clone(lhs),
                    EcPoint::clone(rhs),
                    *condition
                )
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    Ok(KzgAccumulator::new(loader.ec_point_from_assigned(lhs), loader.ec_point_from_assigned(rhs)))
}

fn accumulate<'a>(
    loader: &Rc<Halo2Loader<'a>>,
    accumulators: Vec<KzgAccumulator<G1Affine, Rc<Halo2Loader<'a>>>>,
    as_proof: &[u8]
) -> KzgAccumulator<G1Affine, Rc<Halo2Loader<'a>>> {
    let mut transcript = PoseidonTranscript::<Rc<Halo2Loader>, _>::new::<SECURE_MDS>(
        loader,
        as_proof
    );
    let proof = As::read_proof(&Default::default(), &accumulators, &mut transcript).unwrap();
    As::verify(&Default::default(), &accumulators, &proof).unwrap()
}

#[derive(Clone, Debug)]
pub struct RecursionCircuit {
    svk: Svk,
    default_accumulator: KzgAccumulator<G1Affine, NativeLoader>,
    prev_snark: Snark,
    voter_snark: Snark,
    #[allow(dead_code)]
    round: usize,
    instances: Vec<Fr>,
    as_proof: Vec<u8>,
    inner: BaseCircuitBuilder<Fr>,
}

impl RecursionCircuit {
    pub fn new(
        params: &ParamsKZG<Bn256>,
        prev_snark: Snark,
        voter_snark: Snark,
        sum: Fr,
        round: usize,
        config_params: BaseCircuitParams
    ) -> Self {
        let svk = params.get_g()[0].into();
        let default_accumulator = KzgAccumulator::new(params.get_g()[1], params.get_g()[0]);

        let succinct_verify = |snark: &Snark| {
            let mut transcript = PoseidonTranscript::<NativeLoader, _>::new::<0>(
                snark.proof.as_slice()
            );
            let proof = PlonkSuccinctVerifier::read_proof(
                &svk,
                &snark.protocol,
                &snark.instances,
                &mut transcript
            ).unwrap();
            PlonkSuccinctVerifier::verify(&svk, &snark.protocol, &snark.instances, &proof).unwrap()
        };

        let accumulators = iter
            ::empty()
            .chain(succinct_verify(&voter_snark))
            .chain(
                (round > 0)
                    .then(|| succinct_verify(&prev_snark))
                    .unwrap_or_else(|| {
                        let num_accumulator = 1 + prev_snark.protocol.accumulator_indices.len();
                        vec![default_accumulator.clone(); num_accumulator]
                    })
            )
            .collect_vec();

        let (accumulator, as_proof) = {
            let mut transcript = PoseidonTranscript::<NativeLoader, _>::new::<SECURE_MDS>(
                Vec::new()
            );
            let accumulator = As::create_proof(
                &Default::default(),
                &accumulators,
                &mut transcript,
                OsRng
            ).unwrap();
            (accumulator, transcript.finalize())
        };

        let preprocessed_digest = {
            let inputs = prev_snark.protocol.preprocessed
                .iter()
                .flat_map(|preprocessed| [preprocessed.x, preprocessed.y])
                .map(fe_to_fe)
                .chain(prev_snark.protocol.transcript_initial_state)
                .collect_vec();

            let mut hasher = Poseidon::new::<R_F, R_P, SECURE_MDS>(&NativeLoader);
            hasher.update(&inputs);
            hasher.squeeze()
        };
        let instances = [accumulator.lhs.x, accumulator.lhs.y, accumulator.rhs.x, accumulator.rhs.y]
            .into_iter()
            .flat_map(fe_to_limbs::<_, _, LIMBS, BITS>)
            .chain([preprocessed_digest, Fr::ZERO, sum, Fr::from(round as u64)])
            .collect();

        let inner = BaseCircuitBuilder::new(false).use_params(config_params);
        let mut circuit = Self {
            svk,
            default_accumulator,
            prev_snark,
            voter_snark,
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
        let [preprocessed_digest, initial_state, state, round] = [
            self.instances[12],
            self.instances[13],
            self.instances[14],
            self.instances[15],
        ].map(|instance| main_gate.assign_integer(pool, instance));
        let first_round = main_gate.is_zero(pool.main(), round);
        let not_first_round = main_gate.not(pool.main(), first_round);

        let fp_chip = FpChip::<Fr>::new(&range, BITS, LIMBS);
        let ecc_chip = BaseFieldEccChip::new(&fp_chip);
        let loader = Halo2Loader::new(ecc_chip, mem::take(self.inner.pool(0)));
        let (mut app_instances, app_accumulators) = succinct_verify(
            &self.svk,
            &loader,
            &self.voter_snark,
            None
        );
        let (mut previous_instances, previous_accumulators) = succinct_verify(
            &self.svk,
            &loader,
            &self.prev_snark,
            Some(preprocessed_digest)
        );

        let default_accmulator = self.load_default_accumulator(&loader).unwrap();
        let previous_accumulators = previous_accumulators
            .iter()
            .map(|previous_accumulator| {
                select_accumulator(
                    &loader,
                    &first_round,
                    &default_accmulator,
                    previous_accumulator
                ).unwrap()
            })
            .collect::<Vec<_>>();

        let KzgAccumulator { lhs, rhs } = accumulate(
            &loader,
            [app_accumulators, previous_accumulators].concat(),
            self.as_proof()
        );

        let lhs = lhs.into_assigned();
        let rhs = rhs.into_assigned();
        let app_instances = app_instances.pop().unwrap();
        let previous_instances = previous_instances.pop().unwrap();

        let mut pool = loader.take_ctx();
        let ctx = pool.main();
        for (lhs, rhs) in [
            // Propagate preprocessed_digest
            (&main_gate.mul(ctx, preprocessed_digest, not_first_round), &previous_instances[12]),
            // Propagate initial_state
            (&main_gate.mul(ctx, initial_state, not_first_round), &previous_instances[13]),
            // Verify initial_state is same as the first application snark
            (
                &main_gate.mul(ctx, initial_state, first_round),
                &main_gate.mul(ctx, app_instances[0], first_round),
            ),
            // Verify current state is same as the current application snark
            (&state, &app_instances[1]),
            // Verify previous state is same as the current application snark
            (&main_gate.mul(ctx, app_instances[0], not_first_round), &previous_instances[14]),
            // Verify round is increased by 1 when not at first round
            (&round, &main_gate.add(ctx, not_first_round, previous_instances[15])),
        ] {
            ctx.constrain_equal(lhs, rhs);
        }
        *self.inner.pool(0) = pool;

        self.inner.assigned_instances[0].extend(
            [lhs.x(), lhs.y(), rhs.x(), rhs.y()]
                .into_iter()
                .flat_map(|coordinate| coordinate.limbs())
                .chain([preprocessed_digest, initial_state, state, round].iter())
                .copied()
        );
    }

    fn initial_snark(
        params: &ParamsKZG<Bn256>,
        vk: Option<&VerifyingKey<G1Affine>>,
        config_params: BaseCircuitParams
    ) -> Snark {
        let mut snark = gen_dummy_snark::<RecursionCircuit, As>(
            params,
            vk,
            vec![4 * LIMBS + 4],
            config_params
        );
        let g = params.get_g();
        snark.instances = vec![
            [g[1].x, g[1].y, g[0].x, g[0].y]
                .into_iter()
                .flat_map(fe_to_limbs::<_, _, LIMBS, BITS>)
                .chain([Fr::zero(); 4])
                .collect_vec()
        ];
        snark
    }

    fn as_proof(&self) -> &[u8] {
        &self.as_proof[..]
    }

    fn load_default_accumulator<'a>(
        &self,
        loader: &Rc<Halo2Loader<'a>>
    ) -> Result<KzgAccumulator<G1Affine, Rc<Halo2Loader<'a>>>, Error> {
        let [lhs, rhs] = [self.default_accumulator.lhs, self.default_accumulator.rhs].map(
            |default| {
                let assigned = loader.ecc_chip().assign_constant(&mut loader.ctx_mut(), default);
                loader.ec_point_from_assigned(assigned)
            }
        );
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
        params: Self::Params
    ) -> Self::Config {
        BaseCircuitBuilder::configure_with_params(meta, params)
    }

    fn configure(_: &mut ConstraintSystem<Fr>) -> Self::Config {
        unreachable!()
    }

    fn synthesize(&self, config: Self::Config, layouter: impl Layouter<Fr>) -> Result<(), Error> {
        self.inner.synthesize(config, layouter)
    }
}

impl CircuitExt<Fr> for RecursionCircuit {
    fn num_instance(&self) -> Vec<usize> {
        vec![4 * LIMBS + 4]
    }

    fn instances(&self) -> Vec<Vec<Fr>> {
        vec![self.instances.clone()]
    }

    fn accumulator_indices() -> Option<Vec<(usize, usize)>> {
        Some((0..4 * LIMBS).map(|idx| (0, idx)).collect())
    }

    fn selectors(config: &Self::Config) -> Vec<Selector> {
        config
            .gate()
            .basic_gates[0].iter()
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
            gen_dummy_snark::<ConcreteCircuit,As>(app_params, Some(app_vk), vec![4 * LIMBS + 4],app_config),
            RecursionCircuit::initial_snark(recursion_params, None, recursion_config.clone()),
            Fr::zero(),
            0,
            recursion_config,
        );
        // we cannot auto-configure the circuit because dummy_snark must know the configuration beforehand
        // uncomment the following line only in development to test and print out the optimal configuration ahead of time
        // recursion.inner.0.builder.borrow().config(recursion_params.k() as usize, Some(10));
        gen_pk(recursion_params, &recursion,None)
    }

      pub fn gen_recursion_snark<ConcreteCircuit: CircuitExt<Fr>>(
        app_params: &ParamsKZG<Bn256>,
        recursion_params: &ParamsKZG<Bn256>,
        app_pk: &ProvingKey<G1Affine>,
        recursion_pk: &ProvingKey<G1Affine>,
        initial_sum: Fr,
        inputs: Vec<Fr>,
        config_params: BaseCircuitParams,
    ) -> (Fr, Snark) {
        let mut sum = initial_sum;
        let mut app = Addition::new(initial_sum,sum);
        let mut previous = RecursionCircuit::initial_snark(
            recursion_params,
            Some(recursion_pk.get_vk()),
            config_params.clone(),
        );
        for (round, input) in inputs.into_iter().enumerate() {
            sum = sum + input;
            println!("Generate app snark");
            let app_snark = gen_snark_shplonk(app_params, app_pk, app,None::<&str>);
            let recursion = RecursionCircuit::new(
                recursion_params,
                app_snark,
                previous,
                sum,
                round,
                config_params.clone(),
            );
            println!("Generate recursion snark");
            previous = gen_snark_shplonk(recursion_params, recursion_pk, recursion,None::<&str>);
            app = Addition::new(initial_sum,sum);
        }
        (sum, previous)
    }

#[derive(Clone, Default)]
pub struct Addition {
    sum: Fr,
    instances:Vec<Fr>,
    inner: BaseCircuitBuilder<Fr>,
}
impl Addition {

    fn new(sum: Fr,value:Fr) -> Self {
        let mut inner = BaseCircuitBuilder::new(false);
        let range=inner.range_chip();
        let gate=range.gate();
        let instances = vec![sum.add(value.clone())];
        let assign_sum=inner.pool(0).main().load_witness(sum);
        let assign_value=inner.pool(0).main().load_witness(value);
        let res=gate.add(inner.pool(0).main(),assign_sum,assign_value);
        inner.assigned_instances[0].append(&mut vec![res]);
        Self {
            sum,
            instances,
            inner,
        }
    }


}


impl Circuit<Fr> for Addition {
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
        params: Self::Params
    ) -> Self::Config {
        BaseCircuitBuilder::configure_with_params(meta, params)
    }

    fn configure(_: &mut ConstraintSystem<Fr>) -> Self::Config {
        unreachable!()
    }

    fn synthesize(&self, config: Self::Config, layouter: impl Layouter<Fr>) -> Result<(), Error> {
        self.inner.synthesize(config, layouter)
    }
}
impl CircuitExt<Fr> for Addition {

    fn num_instance(&self) -> Vec<usize> {
        vec![1]
    }

    fn instances(&self) -> Vec<Vec<Fr>> {
        vec![self.instances.clone()]
    }

    fn accumulator_indices() -> Option<Vec<(usize, usize)>> {
        unimplemented!()
    }

}


fn addition_ivc() {
    let app_params = gen_srs(5);
    let recursion_config= AggregationConfigParams {
        degree: 21,
        num_advice: 4,
        num_lookup_advice: 1,
        num_fixed: 1,
        lookup_bits: 20
    };
 

        
    let k = recursion_config.degree;
    let recursion_params = gen_srs(k);
    let config_params = BaseCircuitParams {
        k: k as usize,
        num_advice_per_phase: vec![recursion_config.num_advice],
        num_lookup_advice_per_phase: vec![recursion_config.num_lookup_advice],
        num_fixed: recursion_config.num_fixed,
        lookup_bits: Some(recursion_config.lookup_bits),
        num_instance_columns: 1,
    };

    let app_pk = gen_pk(&app_params, &Addition::default(),None);

    
    let recursion_pk = gen_recursion_pk::<Addition>(
        &recursion_params,
        &app_params,
        app_pk.get_vk(),
        config_params.clone(),
        Default::default(),
    );
  

    let num_round = 1;

    let (final_state, snark) = gen_recursion_snark::<Addition>(
        &app_params,
        &recursion_params,
        &app_pk,
        &recursion_pk,
        Fr::from(2u64),
        vec![Fr::ONE],
        config_params.clone(),
    );
  
   println!("Final state={:?}",final_state);

    {
        let dk =
            (recursion_params.get_g()[0], recursion_params.g2(), recursion_params.s_g2()).into();
        let mut transcript =
            PoseidonTranscript::<NativeLoader, _>::new::<SECURE_MDS>(snark.proof.as_slice());
        let proof =
            PlonkVerifier::read_proof(&dk, &snark.protocol, &snark.instances, &mut transcript)
                .unwrap();
        PlonkVerifier::verify(&dk, &snark.protocol, &snark.instances, &proof).unwrap()
    };
}
#[test]
fn test_addition_ivc() {
    addition_ivc();
}