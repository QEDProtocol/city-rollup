use city_common_circuit::{
    circuits::{
        l1_secp256k1_signature::L1Secp256K1SignatureCircuit,
        traits::qstandard::{QStandardCircuit, QStandardCircuitProvableWithProofStoreSync},
    },
    proof_minifier::pm_core::get_circuit_fingerprint_generic,
    treeprover::aggregation::state_transition::{AggStateTrackableInput, AggStateTransition},
};
use city_crypto::hash::{merkle::core::DeltaMerkleProofCore, qhashout::QHashOut};
use city_rollup_common::{
    introspection::rollup::introspection_result::BTCRollupIntrospectionResultDeposit,
    qworker::{job_id::QProvingJobDataID, proof_store::QProofStoreReaderSync},
};
use plonky2::{
    hash::{
        hash_types::{HashOutTarget, RichField},
        poseidon::PoseidonHash,
    },
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig, Hasher},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};
use serde::{Deserialize, Serialize};

use crate::state::user::claim_l1_deposit::ClaimL1DepositSingleGadget;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(bound = "")]
pub struct CRClaimL1DepositCircuitInput<F: RichField> {
    pub deposit: BTCRollupIntrospectionResultDeposit<F>,
    pub user_tree_delta_merkle_proof: DeltaMerkleProofCore<QHashOut<F>>,
    pub deposit_tree_delta_merkle_proof: DeltaMerkleProofCore<QHashOut<F>>,
    pub allowed_circuit_hashes: QHashOut<F>,
    pub signature_proof_id: QProvingJobDataID,
}
impl<F: RichField> AggStateTrackableInput<F> for CRClaimL1DepositCircuitInput<F> {
    fn get_state_transition(&self) -> AggStateTransition<F> {
        AggStateTransition {
            state_transition_start: QHashOut(PoseidonHash::two_to_one(
                self.user_tree_delta_merkle_proof.old_root.0,
                self.deposit_tree_delta_merkle_proof.old_root.0,
            )),
            state_transition_end: QHashOut(PoseidonHash::two_to_one(
                self.user_tree_delta_merkle_proof.new_root.0,
                self.deposit_tree_delta_merkle_proof.new_root.0,
            )),
        }
    }
}

#[derive(Debug)]
pub struct CRClaimL1DepositCircuit<C: GenericConfig<D> + 'static, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub claim_single_gadget: ClaimL1DepositSingleGadget,
    pub signature_proof_target: ProofWithPublicInputsTarget<D>,

    pub allowed_circuit_hashes_target: HashOutTarget,
    // end circuit targets
    pub circuit_data: CircuitData<C::F, C, D>,
    pub fingerprint: QHashOut<C::F>,
    pub network_magic: u64,

    // start dependencies
    pub signature_circuit_common_data: CommonCircuitData<C::F, D>,
    pub signature_circuit_verifier_data: VerifierOnlyCircuitData<C, D>,
}
impl<C: GenericConfig<D> + 'static, const D: usize> Clone for CRClaimL1DepositCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn clone(&self) -> Self {
        Self::new_with_signature_circuit_data(
            self.network_magic,
            self.signature_circuit_common_data.clone(),
            self.signature_circuit_verifier_data.clone(),
        )
    }
}
impl<C: GenericConfig<D> + 'static, const D: usize> CRClaimL1DepositCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub fn new(network_magic: u64) -> Self {
        let l1_signature_circuit_data = L1Secp256K1SignatureCircuit::<C, D>::new()
            .minifier_chain
            .get_into_circuit_data();

        Self::new_with_signature_circuit_data(
            network_magic,
            l1_signature_circuit_data.common,
            l1_signature_circuit_data.verifier_only,
        )
    }
    pub fn new_with_signature_circuit_data(
        network_magic: u64,
        signature_circuit_common_data: CommonCircuitData<C::F, D>,
        signature_circuit_verifier_data: VerifierOnlyCircuitData<C, D>,
    ) -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);
        let claim_single_gadget = ClaimL1DepositSingleGadget::add_virtual_to::<C::Hasher, C::F, D>(
            &mut builder,
            network_magic,
        );
        let expected_signature_combined_hash = claim_single_gadget.expected_l1_signature_hash;

        let signature_proof_target =
            builder.add_virtual_proof_with_pis(&signature_circuit_common_data);
        let signature_verifier_data_target =
            builder.constant_verifier_data(&signature_circuit_verifier_data);

        let signature_proof_combined_hash = HashOutTarget {
            elements: [
                signature_proof_target.public_inputs[0],
                signature_proof_target.public_inputs[1],
                signature_proof_target.public_inputs[2],
                signature_proof_target.public_inputs[3],
            ],
        };

        // ensure the claim is signed with the correct public key for L1 deposit
        builder.connect_hashes(
            signature_proof_combined_hash,
            expected_signature_combined_hash,
        );

        // verify the signature proof
        builder.verify_proof::<C>(
            &signature_proof_target,
            &signature_verifier_data_target,
            &signature_circuit_common_data,
        );

        let allowed_circuit_hashes_target = builder.add_virtual_hash();

        builder.register_public_inputs(&allowed_circuit_hashes_target.elements);
        builder
            .register_public_inputs(&claim_single_gadget.combined_state_transition_hash.elements);

        let circuit_data = builder.build::<C>();

        let fingerprint = QHashOut(get_circuit_fingerprint_generic(&circuit_data.verifier_only));
        Self {
            claim_single_gadget,
            signature_proof_target,
            allowed_circuit_hashes_target,
            circuit_data,
            fingerprint,
            network_magic,
            signature_circuit_common_data,
            signature_circuit_verifier_data,
        }
    }
    pub fn prove_base(
        &self,
        input: &CRClaimL1DepositCircuitInput<C::F>,
        signature_proof: &ProofWithPublicInputs<C::F, C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut pw = PartialWitness::new();
        self.claim_single_gadget.claim_gadget.set_witness(
            &mut pw,
            &input.deposit,
            &input.deposit_tree_delta_merkle_proof,
            &input.user_tree_delta_merkle_proof,
        );

        pw.set_proof_with_pis_target(&self.signature_proof_target, signature_proof);

        pw.set_hash_target(
            self.allowed_circuit_hashes_target,
            input.allowed_circuit_hashes.0,
        );

        self.circuit_data.prove(pw)
    }
}
impl<C: GenericConfig<D> + 'static, const D: usize> QStandardCircuit<C, D>
    for CRClaimL1DepositCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
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
impl<S: QProofStoreReaderSync, C: GenericConfig<D> + 'static, const D: usize>
    QStandardCircuitProvableWithProofStoreSync<S, CRClaimL1DepositCircuitInput<C::F>, C, D>
    for CRClaimL1DepositCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn prove_with_proof_store_sync(
        &self,
        store: &S,
        input: &CRClaimL1DepositCircuitInput<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let signature_proof = store.get_proof_by_id(input.signature_proof_id)?;
        self.prove_base(input, &signature_proof)
    }
}
