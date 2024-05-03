use std::collections::HashMap;

use plonky2::{
    hash::hash_types::RichField,
    iop::{target::Target, witness::Witness},
};

#[derive(Debug, Clone)]
pub struct DebugCircuitTracer {
    pub trace_groups: HashMap<String, Vec<Target>>,
}

impl DebugCircuitTracer {
    pub fn new() -> Self {
        Self {
            trace_groups: HashMap::new(),
        }
    }
    pub fn trace_vec(&mut self, name: &str, value: &[Target]) {
        self.trace_groups.insert(name.to_string(), value.to_vec());
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
        targets_to_constants: hashbrown::HashMap<Target, F>,
    ) -> HashMap<String, Vec<F>> {
        let mut result = HashMap::<String, Vec<F>>::new();
        self.trace_groups.iter().for_each(|(name, targets)| {
            let values = targets
                .iter()
                .map(|target| {
                    witness
                        .try_get_target(*target)
                        .unwrap_or_else(|| *targets_to_constants.get(target).unwrap())
                })
                .collect::<Vec<_>>();
            result.insert(name.to_string(), values);
        });
        result
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
