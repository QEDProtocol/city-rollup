use city_crypto::hash::qhashout::QHashOut;
use plonky2::{
    field::extension::Extendable,
    hash::{
        hash_types::{HashOutTarget, RichField},
        poseidon::PoseidonHash,
    },
    iop::witness::{PartialWitness, Witness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{
            CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget,
            VerifierOnlyCircuitData,
        },
        config::{AlgebraicHasher, GenericConfig, Hasher},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};
use serde::{Deserialize, Serialize};

use crate::{
    builder::{hash::core::CircuitBuilderHashCore, verify::CircuitBuilderVerifyProofHelpers},
    circuits::traits::qstandard::QStandardCircuit,
    proof_minifier::pm_core::get_circuit_fingerprint_generic,
    treeprover::traits::{TPLeafAggregator, TreeProverAggCircuit},
};

pub trait AggStateTrackableWithEventsInput<F: RichField> {
    fn get_state_transition_with_events(&self) -> StateTransitionWithEvents<F>;
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(bound = "")]
pub struct StateTransitionWithEvents<F: RichField> {
    pub state_transition_start: QHashOut<F>,
    pub state_transition_end: QHashOut<F>,
    pub event_hash: QHashOut<F>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(bound = "")]
pub struct AggStateTransitionWithEventsInput<F: RichField> {
    pub left_input: StateTransitionWithEvents<F>,
    pub right_input: StateTransitionWithEvents<F>,
    pub left_proof_is_leaf: bool,
    pub right_proof_is_leaf: bool,
}
impl<F: RichField> AggStateTransitionWithEventsInput<F> {
    pub fn condense(&self) -> StateTransitionWithEvents<F> {
        StateTransitionWithEvents {
            state_transition_start: self.left_input.state_transition_start,
            state_transition_end: self.right_input.state_transition_end,
            event_hash: QHashOut(PoseidonHash::two_to_one(
                self.left_input.event_hash.0,
                self.right_input.event_hash.0,
            )),
        }
    }
    pub fn combine_with_right_leaf<T: AggStateTrackableWithEventsInput<F>>(
        &self,
        right: &T,
    ) -> Self {
        Self {
            left_input: self.condense(),
            right_input: right.get_state_transition_with_events(),
            left_proof_is_leaf: false,
            right_proof_is_leaf: true,
        }
    }
    pub fn combine_with_left_leaf<T: AggStateTrackableWithEventsInput<F>>(&self, left: &T) -> Self {
        Self {
            left_input: left.get_state_transition_with_events(),
            right_input: self.condense(),
            left_proof_is_leaf: true,
            right_proof_is_leaf: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AggStateTrackableWithEventsCircuitHeaderGadget {
    pub left_state_transition_start: HashOutTarget,
    pub left_state_transition_end: HashOutTarget,
    pub right_state_transition_start: HashOutTarget,
    pub right_state_transition_end: HashOutTarget,
    pub left_event_hash: HashOutTarget,
    pub right_event_hash: HashOutTarget,

    pub leaf_fingerprint: HashOutTarget,
    pub agg_fingerprint: HashOutTarget,

    // end inputs
    // start outputs
    pub allowed_circuit_hashes_root: HashOutTarget,
    pub state_transition_hash: HashOutTarget,
    pub event_transition_hash: HashOutTarget,
}
impl AggStateTrackableWithEventsCircuitHeaderGadget {
    pub fn add_virtual_to<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let left_state_transition_start = builder.add_virtual_hash();
        let left_state_transition_end = builder.add_virtual_hash();
        let right_state_transition_start = builder.add_virtual_hash();
        let right_state_transition_end = builder.add_virtual_hash();
        let left_event_hash = builder.add_virtual_hash();
        let right_event_hash = builder.add_virtual_hash();

        let leaf_fingerprint = builder.add_virtual_hash();
        let agg_fingerprint = builder.add_virtual_hash();

        let allowed_circuit_hashes_root =
            builder.hash_two_to_one::<H>(leaf_fingerprint, agg_fingerprint);
        let state_transition_hash =
            builder.hash_two_to_one::<H>(left_state_transition_start, right_state_transition_end);
        let event_transition_hash = builder.hash_two_to_one::<H>(left_event_hash, right_event_hash);

        // start constraints
        builder.connect_hashes(left_state_transition_end, right_state_transition_start);
        // end constraints

        Self {
            left_state_transition_start,
            left_state_transition_end,
            right_state_transition_start,
            right_state_transition_end,
            left_event_hash,
            right_event_hash,
            leaf_fingerprint,
            agg_fingerprint,

            allowed_circuit_hashes_root,
            state_transition_hash,
            event_transition_hash,
        }
    }
    pub fn set_witness<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        input: &AggStateTransitionWithEventsInput<F>,
        agg_fingerprint: QHashOut<F>,
        leaf_fingerprint: QHashOut<F>,
    ) {
        witness.set_hash_target(self.agg_fingerprint, agg_fingerprint.0);
        witness.set_hash_target(self.leaf_fingerprint, leaf_fingerprint.0);

        witness.set_hash_target(
            self.left_state_transition_start,
            input.left_input.state_transition_start.0,
        );
        witness.set_hash_target(
            self.left_state_transition_end,
            input.left_input.state_transition_end.0,
        );
        witness.set_hash_target(
            self.right_state_transition_start,
            input.right_input.state_transition_start.0,
        );
        witness.set_hash_target(
            self.right_state_transition_end,
            input.right_input.state_transition_end.0,
        );
        witness.set_hash_target(self.left_event_hash, input.left_input.event_hash.0);
        witness.set_hash_target(self.right_event_hash, input.right_input.event_hash.0);
    }
}

#[derive(Debug)]
pub struct AggStateTransitionWithEventsCircuit<C: GenericConfig<D>, const D: usize> {
    pub header_gadget: AggStateTrackableWithEventsCircuitHeaderGadget,

    pub left_proof: ProofWithPublicInputsTarget<D>,
    pub left_verifier_data: VerifierCircuitTarget,

    pub right_proof: ProofWithPublicInputsTarget<D>,
    pub right_verifier_data: VerifierCircuitTarget,

    // end circuit targets
    pub circuit_data: CircuitData<C::F, C, D>,
    pub fingerprint: QHashOut<C::F>,
}
impl<C: GenericConfig<D>, const D: usize> Clone for AggStateTransitionWithEventsCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn clone(&self) -> Self {
        Self::new(
            &self.circuit_data.common,
            self.circuit_data
                .verifier_only
                .constants_sigmas_cap
                .height(),
        )
    }
}
impl<C: GenericConfig<D>, const D: usize> AggStateTransitionWithEventsCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub fn new_base(
        child_common_data: &CommonCircuitData<C::F, D>,
        verifier_cap_height: usize,
    ) -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);

        let header_gadget = AggStateTrackableWithEventsCircuitHeaderGadget::add_virtual_to::<
            PoseidonHash,
            C::F,
            D,
        >(&mut builder);

        let left_proof = builder.add_virtual_proof_with_pis(child_common_data);
        let left_verifier_data = builder.add_virtual_verifier_data(verifier_cap_height);

        let right_proof = builder.add_virtual_proof_with_pis(child_common_data);
        let right_verifier_data = builder.add_virtual_verifier_data(verifier_cap_height);

        builder.verify_proof_with_fingerprint_enum::<C>(
            &left_proof,
            &left_verifier_data,
            child_common_data,
            &[
                header_gadget.agg_fingerprint,
                header_gadget.leaf_fingerprint,
            ],
        );
        builder.verify_proof_with_fingerprint_enum::<C>(
            &right_proof,
            &right_verifier_data,
            child_common_data,
            &[
                header_gadget.agg_fingerprint,
                header_gadget.leaf_fingerprint,
            ],
        );
        builder.register_public_inputs(&header_gadget.allowed_circuit_hashes_root.elements);
        builder.register_public_inputs(&header_gadget.state_transition_hash.elements);
        builder.register_public_inputs(&header_gadget.event_transition_hash.elements);

        let circuit_data = builder.build::<C>();

        let fingerprint = QHashOut(get_circuit_fingerprint_generic(&circuit_data.verifier_only));

        Self {
            header_gadget,
            left_proof,
            left_verifier_data,
            right_proof,
            right_verifier_data,
            circuit_data,
            fingerprint,
        }
    }
    pub fn prove_base(
        &self,
        agg_fingerprint: QHashOut<C::F>,
        agg_verifier_data: &VerifierOnlyCircuitData<C, D>,
        leaf_fingerprint: QHashOut<C::F>,
        leaf_verifier_data: &VerifierOnlyCircuitData<C, D>,
        left_proof: &ProofWithPublicInputs<C::F, C, D>,
        right_proof: &ProofWithPublicInputs<C::F, C, D>,
        input: &AggStateTransitionWithEventsInput<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut pw = PartialWitness::<C::F>::new();
        self.header_gadget
            .set_witness(&mut pw, input, agg_fingerprint, leaf_fingerprint);

        pw.set_proof_with_pis_target(&self.left_proof, left_proof);
        pw.set_verifier_data_target(
            &self.left_verifier_data,
            if input.left_proof_is_leaf {
                leaf_verifier_data
            } else {
                agg_verifier_data
            },
        );
        pw.set_proof_with_pis_target(&self.right_proof, right_proof);
        pw.set_verifier_data_target(
            &self.right_verifier_data,
            if input.right_proof_is_leaf {
                leaf_verifier_data
            } else {
                agg_verifier_data
            },
        );
        let result = self.circuit_data.prove(pw);

        if result.is_err() {
            println!("error: {}", serde_json::to_string(&input).unwrap());
        }
        result
    }
}
impl<C: GenericConfig<D>, const D: usize> QStandardCircuit<C, D>
    for AggStateTransitionWithEventsCircuit<C, D>
{
    fn get_fingerprint(&self) -> QHashOut<C::F> {
        self.fingerprint
    }
    fn get_verifier_config_ref(&self) -> &VerifierOnlyCircuitData<C, D> {
        &self.circuit_data.verifier_only
    }
    fn get_common_circuit_data_ref(&self) -> &CommonCircuitData<C::F, D> {
        &self.circuit_data.common
    }
}

pub struct AggWTTELeafAggregator;

impl<IL: AggStateTrackableWithEventsInput<F>, F: RichField>
    TPLeafAggregator<IL, AggStateTransitionWithEventsInput<F>> for AggWTTELeafAggregator
{
    fn get_output_from_inputs(
        left: &AggStateTransitionWithEventsInput<F>,
        right: &AggStateTransitionWithEventsInput<F>,
    ) -> AggStateTransitionWithEventsInput<F> {
        AggStateTransitionWithEventsInput {
            left_input: left.condense(),
            right_input: right.condense(),
            left_proof_is_leaf: false,
            right_proof_is_leaf: false,
        }
    }

    fn get_output_from_left_leaf(
        left: &IL,
        right: &AggStateTransitionWithEventsInput<F>,
    ) -> AggStateTransitionWithEventsInput<F> {
        right.combine_with_left_leaf(left)
    }

    fn get_output_from_right_leaf(
        left: &AggStateTransitionWithEventsInput<F>,
        right: &IL,
    ) -> AggStateTransitionWithEventsInput<F> {
        left.combine_with_right_leaf(right)
    }

    fn get_output_from_leaves(left: &IL, right: &IL) -> AggStateTransitionWithEventsInput<F> {
        AggStateTransitionWithEventsInput {
            left_input: left.get_state_transition_with_events(),
            right_input: right.get_state_transition_with_events(),
            left_proof_is_leaf: true,
            right_proof_is_leaf: true,
        }
    }
}

impl<C: GenericConfig<D>, const D: usize>
    TreeProverAggCircuit<AggStateTransitionWithEventsInput<C::F>, C, D>
    for AggStateTransitionWithEventsCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn new(child_common_data: &CommonCircuitData<C::F, D>, verifier_cap_height: usize) -> Self {
        Self::new_base(child_common_data, verifier_cap_height)
    }

    fn prove_full(
        &self,
        agg_fingerprint: QHashOut<C::F>,
        agg_verifier_data: &VerifierOnlyCircuitData<C, D>,
        leaf_fingerprint: QHashOut<C::F>,
        leaf_verifier_data: &VerifierOnlyCircuitData<C, D>,
        left_proof: &ProofWithPublicInputs<C::F, C, D>,
        right_proof: &ProofWithPublicInputs<C::F, C, D>,
        input: &AggStateTransitionWithEventsInput<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.prove_base(
            agg_fingerprint,
            agg_verifier_data,
            leaf_fingerprint,
            leaf_verifier_data,
            left_proof,
            right_proof,
            input,
        )
    }
}
