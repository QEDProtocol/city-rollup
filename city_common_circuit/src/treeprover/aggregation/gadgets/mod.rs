use city_crypto::hash::{
    merkle::treeprover::{
        AggStateTransition, AggStateTransitionWithEvents, TPCircuitFingerprintConfig,
    },
    qhashout::QHashOut,
};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::{target::Target, witness::Witness},
    plonk::{
        circuit_builder::CircuitBuilder, circuit_data::VerifierCircuitTarget,
        config::AlgebraicHasher, proof::ProofWithPublicInputsTarget,
    },
};

use crate::builder::{
    connect::CircuitBuilderConnectHelpers, hash::core::CircuitBuilderHashCore,
    verify::CircuitBuilderVerifyProofHelpers,
};

#[derive(Debug, Clone, Copy)]
pub struct AggStateTransitionGadget {
    pub state_transition_start: HashOutTarget,
    pub state_transition_end: HashOutTarget,
}

impl AggStateTransitionGadget {
    pub fn add_virtual_to<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let state_transition_start = builder.add_virtual_hash();
        let state_transition_end = builder.add_virtual_hash();
        Self {
            state_transition_start,
            state_transition_end,
        }
    }

    pub fn get_combined_hash<
        H: AlgebraicHasher<F>,
        F: RichField + Extendable<D>,
        const D: usize,
    >(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> HashOutTarget {
        builder.hash_two_to_one::<H>(self.state_transition_start, self.state_transition_end)
    }

    pub fn combine_many<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        transitions: &[Self],
    ) -> Self {
        assert!(
            transitions.len() > 0,
            "you can only compute combined hash for 1 or more transition"
        );
        if transitions.len() == 1 {
            transitions[0]
        } else {
            let mut state_transition_start = transitions[0].state_transition_start;
            let mut state_transition_end = transitions[0].state_transition_end;
            for i in 1..transitions.len() {
                let transition = &transitions[i];
                state_transition_start = builder.hash_two_to_one::<H>(
                    state_transition_start,
                    transition.state_transition_start,
                );
                state_transition_end = builder
                    .hash_two_to_one::<H>(state_transition_end, transition.state_transition_end);
            }
            Self {
                state_transition_start,
                state_transition_end,
            }
        }
    }

    pub fn set_witness<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        transition: &AggStateTransition<F>,
    ) {
        witness.set_hash_target(
            self.state_transition_start,
            transition.state_transition_start.0,
        );
        witness.set_hash_target(self.state_transition_end, transition.state_transition_end.0);
    }
    pub fn set_witness_with_events<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        transition: &AggStateTransitionWithEvents<F>,
    ) {
        witness.set_hash_target(
            self.state_transition_start,
            transition.state_transition_start.0,
        );
        witness.set_hash_target(self.state_transition_end, transition.state_transition_end.0);
    }
    pub fn set_witness_values<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        state_transition_start: QHashOut<F>,
        state_transition_end: QHashOut<F>,
    ) {
        witness.set_hash_target(self.state_transition_start, state_transition_start.0);
        witness.set_hash_target(self.state_transition_end, state_transition_end.0);
    }
}

#[derive(Debug, Copy, Clone)]
pub struct AggStateTransitionProofPublicInputsGadget {
    pub allowed_circuit_hashes_root: HashOutTarget,
    pub state_transition_combined_hash: HashOutTarget,
}

impl AggStateTransitionProofPublicInputsGadget {
    pub fn from_public_inputs(public_inputs: &[Target]) -> Self {
        assert_eq!(
            public_inputs.len(),
            8,
            "AggStateTransitionProof should have 12 public inputs"
        );
        let allowed_circuit_hashes_root = HashOutTarget {
            elements: [
                public_inputs[0],
                public_inputs[1],
                public_inputs[2],
                public_inputs[3],
            ],
        };
        let state_transition_combined_hash = HashOutTarget {
            elements: [
                public_inputs[4],
                public_inputs[5],
                public_inputs[6],
                public_inputs[7],
            ],
        };
        Self {
            state_transition_combined_hash,
            allowed_circuit_hashes_root,
        }
    }
    pub fn to_public_inputs(&self) -> [Target; 8] {
        [
            self.allowed_circuit_hashes_root.elements[0],
            self.allowed_circuit_hashes_root.elements[1],
            self.allowed_circuit_hashes_root.elements[2],
            self.allowed_circuit_hashes_root.elements[3],
            self.state_transition_combined_hash.elements[0],
            self.state_transition_combined_hash.elements[1],
            self.state_transition_combined_hash.elements[2],
            self.state_transition_combined_hash.elements[3],
        ]
    }
}

#[derive(Debug, Copy, Clone)]
pub struct AggStateTransitionWithEventsProofPublicInputsGadget {
    pub state_transition_combined_hash: HashOutTarget,
    pub events_hash: HashOutTarget,
    pub allowed_circuit_hashes_root: HashOutTarget,
}

impl AggStateTransitionWithEventsProofPublicInputsGadget {
    pub fn from_public_inputs(public_inputs: &[Target]) -> Self {
        assert_eq!(
            public_inputs.len(),
            12,
            "AggStateTransitionWithEventsProof should have 12 public inputs"
        );
        let allowed_circuit_hashes_root = HashOutTarget {
            elements: [
                public_inputs[0],
                public_inputs[1],
                public_inputs[2],
                public_inputs[3],
            ],
        };
        let state_transition_combined_hash = HashOutTarget {
            elements: [
                public_inputs[4],
                public_inputs[5],
                public_inputs[6],
                public_inputs[7],
            ],
        };
        let events_hash = HashOutTarget {
            elements: [
                public_inputs[8],
                public_inputs[9],
                public_inputs[10],
                public_inputs[11],
            ],
        };
        Self {
            state_transition_combined_hash,
            events_hash,
            allowed_circuit_hashes_root,
        }
    }
    pub fn to_public_inputs(&self) -> [Target; 12] {
        [
            self.allowed_circuit_hashes_root.elements[0],
            self.allowed_circuit_hashes_root.elements[1],
            self.allowed_circuit_hashes_root.elements[2],
            self.allowed_circuit_hashes_root.elements[3],
            self.state_transition_combined_hash.elements[0],
            self.state_transition_combined_hash.elements[1],
            self.state_transition_combined_hash.elements[2],
            self.state_transition_combined_hash.elements[3],
            self.events_hash.elements[0],
            self.events_hash.elements[1],
            self.events_hash.elements[2],
            self.events_hash.elements[3],
        ]
    }
}

pub struct AggStateTransitionProofValidityGadget {
    pub state_transition_combined_hash: HashOutTarget,
}

impl AggStateTransitionProofValidityGadget {
    pub fn add_virtual_to<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        proof_target: &ProofWithPublicInputsTarget<D>,
        verifier_data_target: &VerifierCircuitTarget,
        fingerprint: &TPCircuitFingerprintConfig<F>,
    ) -> HashOutTarget {
        let allowed_fingerprints = [
            builder.constant_whash(fingerprint.aggregator_fingerprint),
            builder.constant_whash(fingerprint.leaf_fingerprint),
            builder.constant_whash(fingerprint.dummy_fingerprint),
        ];
        let actual_fingerprint = builder.get_circuit_fingerprint::<H>(verifier_data_target);
        builder.connect_hashes_enum(actual_fingerprint, &allowed_fingerprints);
        let allowed_circuit_hashes_root =
            builder.constant_whash(fingerprint.allowed_circuit_hashes_root);
        let pub_gadget = AggStateTransitionProofPublicInputsGadget::from_public_inputs(
            &proof_target.public_inputs,
        );
        builder.connect_hashes(
            pub_gadget.allowed_circuit_hashes_root,
            allowed_circuit_hashes_root,
        );

        pub_gadget.state_transition_combined_hash
    }
}

pub struct AggStateTransitionWithEventsProofValidityGadget {
    pub state_transition_combined_hash: HashOutTarget,
    pub events_hash: HashOutTarget,
}

impl AggStateTransitionWithEventsProofValidityGadget {
    pub fn add_virtual_to<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        proof_target: &ProofWithPublicInputsTarget<D>,
        verifier_data_target: &VerifierCircuitTarget,
        fingerprint: &TPCircuitFingerprintConfig<F>,
    ) -> Self {
        let allowed_fingerprints = [
            builder.constant_whash(fingerprint.aggregator_fingerprint),
            builder.constant_whash(fingerprint.leaf_fingerprint),
            builder.constant_whash(fingerprint.dummy_fingerprint),
        ];
        let actual_fingerprint = builder.get_circuit_fingerprint::<H>(verifier_data_target);
        builder.connect_hashes_enum(actual_fingerprint, &allowed_fingerprints);
        let allowed_circuit_hashes_root =
            builder.constant_whash(fingerprint.allowed_circuit_hashes_root);
        let pub_gadget = AggStateTransitionWithEventsProofPublicInputsGadget::from_public_inputs(
            &proof_target.public_inputs,
        );

        builder.connect_hashes(
            pub_gadget.allowed_circuit_hashes_root,
            allowed_circuit_hashes_root,
        );

        Self {
            state_transition_combined_hash: pub_gadget.state_transition_combined_hash,
            events_hash: pub_gadget.events_hash,
        }
    }
}
