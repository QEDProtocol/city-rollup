use city_common::logging::trace_timer::TraceTimer;
use city_common_circuit::{
    circuits::traits::qstandard::{QStandardCircuit, QStandardCircuitWithDefaultMinified},
    treeprover::{
        aggregation::state_transition::AggStateTransitionCircuit, traits::TreeProverAggCircuit,
    },
};
use city_crypto::hash::{
    merkle::treeprover::TPCircuitFingerprintConfig, traits::hasher::MerkleZeroHasher,
};
use plonky2::{
    gates::{coset_interpolation::CosetInterpolationGate, gate::GateRef},
    hash::hash_types::HashOut,
    plonk::config::{AlgebraicHasher, GenericConfig},
};

use crate::block_circuits::ops::register_user::{
    CRUserRegistrationCircuit, WCRUserRegistrationCircuit,
};

use city_crypto::hash::qhashout::QHashOut;
use plonky2::hash::hash_types::RichField;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct CRWorkerTestToolboxCoreCircuitFingerprints<F: RichField> {
    pub network_magic: u64,

    // state transition operations
    pub op_register_user: TPCircuitFingerprintConfig<F>,
    // operation aggregators
    pub agg_state_transition: QHashOut<F>,
}

pub struct CRWorkerTestToolboxCoreCircuits<C: GenericConfig<D> + 'static, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    pub network_magic: u64,

    // state transition operations
    pub op_register_user: WCRUserRegistrationCircuit<C, D>,

    // operation aggregators
    pub agg_state_transition: AggStateTransitionCircuit<C, D>,
}

impl<C: GenericConfig<D> + 'static, const D: usize> CRWorkerTestToolboxCoreCircuits<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    pub fn new(network_magic: u64) -> Self {
        let mut trace_timer = TraceTimer::new("CRWorkerToolboxCoreCircuits");
        trace_timer.lap("start => build core toolbox circuits");
        // state transition operations
        let op_register_user =
            CRUserRegistrationCircuit::new(&GateRef::new(CosetInterpolationGate::new(4)));
        trace_timer.lap("built op_register_user");

        // operation aggregators
        let agg_state_transition = AggStateTransitionCircuit::new(
            op_register_user.get_common_circuit_data_ref(),
            op_register_user
                .get_verifier_config_ref()
                .constants_sigmas_cap
                .height(),
        );
        trace_timer.lap("built agg_state_transition");

        Self {
            network_magic,
            op_register_user,
            agg_state_transition,
        }
    }
    pub fn get_fingerprint_config(&self) -> CRWorkerTestToolboxCoreCircuitFingerprints<C::F> {
        let agg_state_transition_fingerprint = self.agg_state_transition.get_fingerprint();

        CRWorkerTestToolboxCoreCircuitFingerprints {
            network_magic: self.network_magic,

            op_register_user: TPCircuitFingerprintConfig::from_leaf_and_agg_fingerprints::<C::Hasher>(
                self.op_register_user.get_fingerprint(),
                agg_state_transition_fingerprint,
                QHashOut::ZERO,
            ),
            agg_state_transition: agg_state_transition_fingerprint,
        }
    }
    pub fn print_op_common_data(&self) {
        self.op_register_user
            .print_config_with_name("op_register_user");

        self.agg_state_transition
            .print_config_with_name("agg_state_transition");
    }
}
