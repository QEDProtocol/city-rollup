use std::collections::HashMap;

use city_crypto::hash::qhashout::QHashOut;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::generator::generate_partial_witness;
use plonky2::iop::target::Target;
use plonky2::iop::witness::PartialWitness;
use plonky2::iop::witness::PartitionWitness;
use plonky2::iop::witness::Witness;
use plonky2::plonk::circuit_data::CommonCircuitData;
use plonky2::plonk::circuit_data::ProverOnlyCircuitData;
use plonky2::plonk::config::GenericConfig;
use serde::Deserialize;
use serde::Serialize;
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct DebugCircuitTraceResult<F: RichField> {
    pub trace_groups: HashMap<String, Vec<F>>,
    pub trace_groups_hash: HashMap<String, QHashOut<F>>,
}

#[derive(Debug, Clone)]
pub struct DebugCircuitTracer {
    pub trace_groups: HashMap<String, Vec<Target>>,
    pub trace_groups_hash: HashMap<String, HashOutTarget>,
}

impl DebugCircuitTracer {
    pub fn new() -> Self {
        Self {
            trace_groups: HashMap::new(),
            trace_groups_hash: HashMap::new(),
        }
    }
    pub fn trace_vec(&mut self, name: &str, value: &[Target]) {
        self.trace_groups.insert(name.to_string(), value.to_vec());
    }
    pub fn trace_hash(&mut self, name: &str, value: HashOutTarget) {
        self.trace_groups
            .insert(name.to_string(), value.elements.to_vec());
        self.trace_groups_hash.insert(name.to_string(), value);
    }
    pub fn trace_hash_s(&mut self, name: String, value: HashOutTarget) {
        self.trace_groups
            .insert(name.to_string(), value.elements.to_vec());
        self.trace_groups_hash.insert(name, value);
    }
    pub fn trace_vec_s(&mut self, name: String, value: &[Target]) {
        self.trace_groups.insert(name, value.to_vec());
    }
    pub fn trace(&mut self, name: &str, value: Target) {
        self.trace_groups.insert(name.to_string(), vec![value]);
    }
    pub fn trace_s(&mut self, name: &str, value: Target) {
        self.trace_groups.insert(name.to_string(), vec![value]);
    }

    pub fn resolve<W: Witness<F>, F: RichField>(
        &self,
        witness: &W,
        targets_to_constants: &hashbrown::HashMap<Target, F>,
    ) -> HashMap<String, Vec<F>> {
        let mut result = HashMap::<String, Vec<F>>::new();
        self.trace_groups.iter().for_each(|(name, targets)| {
            let values = targets
                .iter()
                .map(|target| {
                    witness.try_get_target(*target).unwrap_or_else(|| {
                        *targets_to_constants.get(target).unwrap_or_else(|| {
                            println!("error value constant for {}", name);
                            panic!("error getting value for {}", name);
                        })
                    })
                })
                .collect::<Vec<_>>();
            result.insert(name.to_string(), values);
        });
        result
    }
    pub fn resolve_partition<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
        const D: usize,
    >(
        &self,
        witness: &PartialWitness<F>,
        prover_data: &ProverOnlyCircuitData<F, C, D>,
        common_data: &CommonCircuitData<F, D>,
        targets_to_constants: &hashbrown::HashMap<Target, F>,
    ) -> DebugCircuitTraceResult<F> {
        let parition_witness = generate_partial_witness(witness.clone(), prover_data, common_data);
        let trace_groups =
            self.resolve::<PartitionWitness<F>, F>(&parition_witness, targets_to_constants);
        let mut trace_groups_hash: HashMap<String, QHashOut<F>> = HashMap::new();
        self.trace_groups_hash.iter().for_each(|(k, _v)| {
            let val_vec = trace_groups.get(k).unwrap();
            trace_groups_hash.insert(k.to_string(), QHashOut::from_felt_slice(&val_vec));
        });

        DebugCircuitTraceResult {
            trace_groups,
            trace_groups_hash,
        }
    }

    pub fn resolve_u64<W: Witness<F>, F: RichField>(
        &self,
        witness: &W,
        targets_to_constants: hashbrown::HashMap<Target, F>,
    ) -> HashMap<String, Vec<u64>> {
        let mut result = HashMap::<String, Vec<u64>>::new();
        self.trace_groups.iter().for_each(|(name, targets)| {
            let values = targets
                .iter()
                .map(|target| {
                    witness
                        .try_get_target(*target)
                        .unwrap_or_else(|| *targets_to_constants.get(target).unwrap())
                        .to_canonical_u64()
                })
                .collect::<Vec<_>>();
            result.insert(name.to_string(), values);
        });
        result
    }
    pub fn reset(&mut self) {
        self.trace_groups.clear();
    }
}
