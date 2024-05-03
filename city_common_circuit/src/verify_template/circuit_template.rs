use std::sync::Arc;

use plonky2::field::types::{Field, PrimeField64};
use plonky2::plonk::circuit_builder::CircuitBuilder;

use plonky2::plonk::{
    circuit_data::{CircuitConfig, CommonCircuitData, VerifierOnlyCircuitData},
    config::GenericConfig,
    plonk_common::salt_size,
};
use serde::{Deserialize, Serialize};

use crate::circuits::traits::qstandard::QStandardCircuit;

use super::ser_data::VTFriParams;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct QEDCircuitVerifyTemplate {
    pub verifier_data_cap_height: usize,
    pub fri_cap_height: usize,
    pub num_public_inputs: usize,
    pub num_leaves_per_oracle: Vec<usize>,
    pub vt_fri_params: VTFriParams,
    pub num_challenges: usize,
    pub total_partial_products: usize,
    pub num_lookups: usize,
    pub num_constants: usize,
    pub num_routed_wires: usize,
    pub num_wires: usize,
    pub num_quotient_polys: usize,
    pub num_gate_constraints: usize,
    pub quotient_degree_factor: usize,
    pub k_is: Vec<u64>,
    /// The number of partial products needed to compute the `Z` polynomials.
    pub num_partial_products: usize,

    /// The number of lookup polynomials.
    pub num_lookup_polys: usize,

    /// The number of lookup selectors.
    pub num_lookup_selectors: usize,

    /// The stored lookup tables.
    pub luts: Vec<Vec<[u16; 2]>>,
}
pub fn luts_to_string(luts: &Vec<Vec<[u16; 2]>>) -> String {
    let base_luts = luts
        .iter()
        .map(|lut| format!("vec!{},", serde_json::to_string(lut).unwrap()))
        .collect::<Vec<String>>();
    let mut string_base = String::new();
    string_base.push_str("vec![");
    for lut in base_luts {
        string_base.push_str(&lut);
    }
    string_base.push_str("]");
    string_base
}
impl QEDCircuitVerifyTemplate {
    pub fn from_common_and_verifier_only<C: GenericConfig<D>, const D: usize>(
        common_data: &CommonCircuitData<C::F, D>,
        verifier_only: &VerifierOnlyCircuitData<C, D>,
    ) -> Self {
        let verifier_data_cap_height = verifier_only.constants_sigmas_cap.height();
        let num_public_inputs = common_data.num_public_inputs;

        let config = &common_data.config;
        let fri_params = &common_data.fri_params;
        let fri_cap_height = fri_params.config.cap_height;
        let salt = salt_size(common_data.fri_params.hiding);

        let num_preprocessed_polys = common_data.sigmas_range().end;
        let num_zs_partial_products_polys =
            common_data.config.num_challenges * (1 + common_data.num_partial_products);
        let num_all_lookup_polys = common_data.config.num_challenges * common_data.num_lookup_polys;
        let quotient_degree_factor = common_data.quotient_degree_factor;
        let num_quotient_polys = common_data.config.num_challenges * quotient_degree_factor;
        let num_gate_constraints = common_data.num_gate_constraints;
        let mut num_leaves_per_oracle = vec![
            num_preprocessed_polys,
            config.num_wires + salt,
            num_zs_partial_products_polys + num_all_lookup_polys + salt,
        ];
        if num_quotient_polys > 0 {
            num_leaves_per_oracle.push(num_quotient_polys + salt);
        }
        let vt_fri_params: VTFriParams = common_data.fri_params.clone().into();
        let num_challenges = config.num_challenges;
        let total_partial_products = num_challenges * common_data.num_partial_products;
        let has_lookup = common_data.num_lookup_polys != 0;
        let num_lookups = if has_lookup { num_all_lookup_polys } else { 0 };
        let num_constants = common_data.num_constants;
        let num_wires = config.num_wires;
        let num_routed_wires = config.num_routed_wires;
        let k_is = common_data
            .k_is
            .iter()
            .map(|f| f.to_canonical_u64())
            .collect();
        let num_partial_products = common_data.num_partial_products;
        let num_lookup_polys = common_data.num_lookup_polys;
        let num_lookup_selectors = common_data.num_lookup_selectors;
        let luts = common_data
            .luts
            .iter()
            .map(|lut| lut.iter().map(|x| [x.0, x.1]).collect())
            .collect();
        Self {
            verifier_data_cap_height,
            fri_cap_height,
            num_public_inputs,
            num_leaves_per_oracle,
            vt_fri_params,
            num_challenges,
            total_partial_products,
            num_lookups,
            num_constants,
            num_routed_wires,
            num_wires,
            num_quotient_polys,
            quotient_degree_factor,
            num_gate_constraints,
            k_is,
            num_partial_products,
            num_lookup_polys,
            num_lookup_selectors,
            luts,
        }
    }
    pub fn from_standard_circuit<Q: QStandardCircuit<C, D>, C: GenericConfig<D>, const D: usize>(
        circuit: &Q,
    ) -> Self {
        Self::from_common_and_verifier_only(
            circuit.get_common_circuit_data_ref(),
            circuit.get_verifier_config_ref(),
        )
    }
    pub fn to_code(&self) -> String {
        let luts_str = luts_to_string(&self.luts);
        format!(
            "QEDCircuitVerifyTemplate {{
            verifier_data_cap_height: {},
            fri_cap_height: {},
            num_public_inputs: {},
            num_leaves_per_oracle: vec!{},
            vt_fri_params: {},
            num_challenges: {},
            total_partial_products: {},
            num_lookups: {},
            num_constants: {},
            num_routed_wires: {},
            num_wires: {},
            num_quotient_polys: {},
            quotient_degree_factor: {},
            num_gate_constraints: {},
            k_is: vec!{},
            num_partial_products: {},
            num_lookup_polys: {},
            num_lookup_selectors: {},
            luts: {},
        }}",
            self.verifier_data_cap_height,
            self.fri_cap_height,
            self.num_public_inputs,
            serde_json::to_string(&self.num_leaves_per_oracle).unwrap(),
            self.vt_fri_params.to_code(),
            self.num_challenges,
            self.total_partial_products,
            self.num_lookups,
            self.num_constants,
            self.num_routed_wires,
            self.num_wires,
            self.num_quotient_polys,
            self.quotient_degree_factor,
            self.num_gate_constraints,
            serde_json::to_string(&self.k_is).unwrap(),
            self.num_partial_products,
            self.num_lookup_polys,
            self.num_lookup_selectors,
            luts_str
        )
    }
    pub fn get_circuit_config(&self) -> CircuitConfig {
        let mut base = CircuitConfig::standard_recursion_config();
        base.fri_config = self.vt_fri_params.config.clone().into();
        base.num_wires = self.num_wires;
        base.num_challenges = self.num_challenges;
        base.num_constants = self.num_constants;
        base.num_routed_wires = self.num_routed_wires;

        base
    }
    pub fn get_common_data<C: GenericConfig<D>, const D: usize>(
        &self,
    ) -> CommonCircuitData<C::F, D> {
        let circuit_config = self.get_circuit_config();
        let fri_params = self.vt_fri_params.clone().into();

        let donor_circuit_data =
            CircuitBuilder::<C::F, D>::new(CircuitConfig::standard_recursion_config()).build::<C>();
        let k_is = self
            .k_is
            .iter()
            .map(|x| C::F::from_noncanonical_u64(*x))
            .collect::<Vec<C::F>>();
        let luts = self
            .luts
            .iter()
            .map(|lut| Arc::new(lut.iter().map(|x| (x[0], x[1])).collect::<Vec<_>>()))
            .collect();
        CommonCircuitData {
            config: circuit_config,
            fri_params,
            gates: vec![],
            selectors_info: donor_circuit_data.common.selectors_info,
            quotient_degree_factor: self.quotient_degree_factor,
            num_gate_constraints: self.num_gate_constraints,
            num_constants: self.num_constants,
            num_public_inputs: self.num_public_inputs,
            k_is,
            num_partial_products: self.num_partial_products,
            num_lookup_polys: self.num_lookup_polys,
            num_lookup_selectors: self.num_lookup_selectors,
            luts,
        }
    }
}
