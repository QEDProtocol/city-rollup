use city_crypto::hash::merkle::treeprover::AggStateTransitionInput;
use city_crypto::hash::qhashout::QHashOut;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::hash::hash_types::RichField;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::witness::PartialWitness;
use plonky2::iop::witness::Witness;
use plonky2::iop::witness::WitnessWrite;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::circuit_data::CircuitData;
use plonky2::plonk::circuit_data::CommonCircuitData;
use plonky2::plonk::circuit_data::VerifierCircuitTarget;
use plonky2::plonk::circuit_data::VerifierOnlyCircuitData;
use plonky2::plonk::config::AlgebraicHasher;
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::plonk::proof::ProofWithPublicInputsTarget;

use crate::builder::hash::core::CircuitBuilderHashCore;
use crate::builder::verify::CircuitBuilderVerifyProofHelpers;
use crate::circuits::traits::qstandard::QStandardCircuit;
use crate::proof_minifier::pm_core::get_circuit_fingerprint_generic;
use crate::treeprover::traits::TreeProverAggCircuit;

#[derive(Debug, Clone)]
pub struct AggStateTrackableCircuitHeaderGadget {
    pub left_state_transition_start: HashOutTarget,
    pub left_state_transition_end: HashOutTarget,
    pub right_state_transition_start: HashOutTarget,
    pub right_state_transition_end: HashOutTarget,
    pub leaf_fingerprint: HashOutTarget,
    pub agg_fingerprint: HashOutTarget,

    // end inputs
    // start outputs
    pub expected_left_child_transition_hash: HashOutTarget,
    pub expected_right_child_transition_hash: HashOutTarget,
    pub allowed_circuit_hashes_root: HashOutTarget,
    pub state_transition_hash: HashOutTarget,
}
impl AggStateTrackableCircuitHeaderGadget {
    pub fn add_virtual_to<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let left_state_transition_start = builder.add_virtual_hash();
        let left_state_transition_end = builder.add_virtual_hash();
        let right_state_transition_start = builder.add_virtual_hash();
        let right_state_transition_end = builder.add_virtual_hash();
        let leaf_fingerprint = builder.add_virtual_hash();
        let agg_fingerprint = builder.add_virtual_hash();

        let allowed_circuit_hashes_root =
            builder.hash_two_to_one::<H>(leaf_fingerprint, agg_fingerprint);

        let expected_left_child_transition_hash =
            builder.hash_two_to_one::<H>(left_state_transition_start, left_state_transition_end);

        let expected_right_child_transition_hash =
            builder.hash_two_to_one::<H>(right_state_transition_start, right_state_transition_end);

        let state_transition_hash =
            builder.hash_two_to_one::<H>(left_state_transition_start, right_state_transition_end);

        // start constraints
        builder.connect_hashes(left_state_transition_end, right_state_transition_start);
        // end constraints

        Self {
            left_state_transition_start,
            left_state_transition_end,
            right_state_transition_start,
            right_state_transition_end,
            leaf_fingerprint,
            agg_fingerprint,

            expected_left_child_transition_hash,
            expected_right_child_transition_hash,
            allowed_circuit_hashes_root,
            state_transition_hash,
        }
    }
    pub fn set_witness<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        input: &AggStateTransitionInput<F>,
        agg_fingerprint: QHashOut<F>,
        leaf_fingerprint: QHashOut<F>,
    ) {
        println!("set_witness: {}", serde_json::to_string(input).unwrap());
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
    }
}

#[derive(Debug)]
pub struct AggStateTransitionCircuit<C: GenericConfig<D>, const D: usize> {
    pub header_gadget: AggStateTrackableCircuitHeaderGadget,

    pub left_proof: ProofWithPublicInputsTarget<D>,
    pub left_verifier_data: VerifierCircuitTarget,

    pub right_proof: ProofWithPublicInputsTarget<D>,
    pub right_verifier_data: VerifierCircuitTarget,

    // end circuit targets
    pub circuit_data: CircuitData<C::F, C, D>,
    pub fingerprint: QHashOut<C::F>,
}
impl<C: GenericConfig<D>, const D: usize> Clone for AggStateTransitionCircuit<C, D>
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
impl<C: GenericConfig<D>, const D: usize> AggStateTransitionCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub fn new_base(
        child_common_data: &CommonCircuitData<C::F, D>,
        verifier_cap_height: usize,
    ) -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);

        let header_gadget =
            AggStateTrackableCircuitHeaderGadget::add_virtual_to::<PoseidonHash, C::F, D>(
                &mut builder,
            );

        let left_proof = builder.add_virtual_proof_with_pis(child_common_data);
        let left_verifier_data = builder.add_virtual_verifier_data(verifier_cap_height);

        let right_proof = builder.add_virtual_proof_with_pis(child_common_data);
        let right_verifier_data = builder.add_virtual_verifier_data(verifier_cap_height);

        let left_child_allowed_circuit_hashes_root = HashOutTarget {
            elements: [
                left_proof.public_inputs[0],
                left_proof.public_inputs[1],
                left_proof.public_inputs[2],
                left_proof.public_inputs[3],
            ],
        };
        let left_child_transition_hash = HashOutTarget {
            elements: [
                left_proof.public_inputs[4],
                left_proof.public_inputs[5],
                left_proof.public_inputs[6],
                left_proof.public_inputs[7],
            ],
        };
        let right_child_allowed_circuit_hashes_root = HashOutTarget {
            elements: [
                right_proof.public_inputs[0],
                right_proof.public_inputs[1],
                right_proof.public_inputs[2],
                right_proof.public_inputs[3],
            ],
        };
        let right_child_transition_hash = HashOutTarget {
            elements: [
                right_proof.public_inputs[4],
                right_proof.public_inputs[5],
                right_proof.public_inputs[6],
                right_proof.public_inputs[7],
            ],
        };
        builder.connect_hashes(
            left_child_allowed_circuit_hashes_root,
            header_gadget.allowed_circuit_hashes_root,
        );
        builder.connect_hashes(
            right_child_allowed_circuit_hashes_root,
            header_gadget.allowed_circuit_hashes_root,
        );
        builder.connect_hashes(
            left_child_transition_hash,
            header_gadget.expected_left_child_transition_hash,
        );
        builder.connect_hashes(
            right_child_transition_hash,
            header_gadget.expected_right_child_transition_hash,
        );
        /*
        let x = builder.constant(C::F::ONE);
        let y = builder.constant(C::F::ZERO);
        let is_geq = builder.is_greater_than(32, x, y);
        builder.connect(is_geq.target, x);*/
        //builder.verify_proof::<C>(&left_proof, &left_verifier_data,
        // &child_common_data); builder.verify_proof::<C>(&right_proof,
        // &right_verifier_data, &child_common_data);

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
        input: &AggStateTransitionInput<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut pw = PartialWitness::<C::F>::new();
        //println!("agg_fingerprint: {}", agg_fingerprint.to_string());
        //println!("leaf_fingerprint: {}", leaf_fingerprint.to_string());
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
    for AggStateTransitionCircuit<C, D>
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

impl<C: GenericConfig<D>, const D: usize> TreeProverAggCircuit<AggStateTransitionInput<C::F>, C, D>
    for AggStateTransitionCircuit<C, D>
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
        input: &AggStateTransitionInput<C::F>,
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
