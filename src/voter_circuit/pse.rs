use getset::Getters;
use halo2_base::{
    gates::circuit::{builder::BaseCircuitBuilder, BaseCircuitParams, BaseConfig},
    halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        halo2curves::grumpkin::Fq as Fr,
        plonk::{self, Circuit, ConstraintSystem, Selector},
    },
};
use serde::{Deserialize, Serialize};
use snark_verifier_sdk::CircuitExt;

pub const LIMBS: usize = 3;
pub const BITS: usize = 88;

#[derive(Clone, Copy, Default, Debug, Serialize, Deserialize)]
pub struct VoterCircuitConfigParams {
    pub degree: u32,
    pub num_advice: usize,
    pub num_lookup_advice: usize,
    pub num_fixed: usize,
    pub lookup_bits: usize,
}

impl From<VoterCircuitConfigParams> for BaseCircuitParams {
    fn from(params: VoterCircuitConfigParams) -> Self {
        BaseCircuitParams {
            k: params.degree as usize,
            num_advice_per_phase: vec![params.num_advice],
            num_lookup_advice_per_phase: vec![params.num_lookup_advice],
            num_fixed: params.num_fixed,
            lookup_bits: Some(params.lookup_bits),
            num_instance_columns: 1,
        }
    }
}

impl TryFrom<&BaseCircuitParams> for VoterCircuitConfigParams {
    type Error = &'static str;

    fn try_from(params: &BaseCircuitParams) -> Result<Self, Self::Error> {
        if params.num_advice_per_phase.iter().skip(1).any(|&n| n != 0) {
            return Err("VoterCircuitConfigParams only supports 1 phase");
        }
        if params
            .num_lookup_advice_per_phase
            .iter()
            .skip(1)
            .any(|&n| n != 0)
        {
            return Err("VoterCircuitConfigParams only supports 1 phase");
        }
        if params.lookup_bits.is_none() {
            return Err("VoterCircuitConfigParams requires lookup_bits");
        }
        if params.num_instance_columns != 1 {
            return Err("VoterCircuitConfigParams only supports 1 instance column");
        }
        Ok(Self {
            degree: params.k as u32,
            num_advice: params.num_advice_per_phase[0],
            num_lookup_advice: params.num_lookup_advice_per_phase[0],
            num_fixed: params.num_fixed,
            lookup_bits: params.lookup_bits.unwrap(),
        })
    }
}

impl TryFrom<BaseCircuitParams> for VoterCircuitConfigParams {
    type Error = &'static str;

    fn try_from(value: BaseCircuitParams) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

#[derive(Clone, Debug, Getters, Default)]
pub struct VoterCircuit {
    pub builder: BaseCircuitBuilder<Fr>,
}

impl Circuit<Fr> for VoterCircuit {
    type Config = BaseConfig<Fr>;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = VoterCircuitConfigParams;

    fn params(&self) -> Self::Params {
        (&self.builder.config_params).try_into().unwrap()
    }

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure_with_params(
        meta: &mut ConstraintSystem<Fr>,
        params: Self::Params,
    ) -> Self::Config {
        BaseCircuitBuilder::configure_with_params(meta, params.into())
    }

    fn configure(_: &mut ConstraintSystem<Fr>) -> Self::Config {
        unreachable!()
    }

    fn synthesize(
        &self,
        config: Self::Config,
        layouter: impl Layouter<Fr>,
    ) -> Result<(), plonk::Error> {
        self.builder.synthesize(config, layouter)
    }
}

impl CircuitExt<Fr> for VoterCircuit {
    fn num_instance(&self) -> Vec<usize> {
        self.builder.num_instance()
    }

    fn instances(&self) -> Vec<Vec<Fr>> {
        self.builder.instances()
    }

    fn accumulator_indices() -> Option<Vec<(usize, usize)>> {
        Some((0..4 * LIMBS).map(|idx| (0, idx)).collect())
    }

    fn selectors(config: &Self::Config) -> Vec<Selector> {
        BaseCircuitBuilder::selectors(config)
    }
}
