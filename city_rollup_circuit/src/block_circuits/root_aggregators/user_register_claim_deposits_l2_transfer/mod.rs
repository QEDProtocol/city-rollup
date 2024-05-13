use city_common_circuit::{
    circuits::traits::qstandard::QStandardCircuit, proof_minifier::pm_chain::OASProofMinifierChain,
    treeprover::aggregation::gadgets::AggStateTransitionProofValidityGadget,
};
use city_crypto::hash::{merkle::treeprover::TPCircuitFingerprintConfig, qhashout::QHashOut};
use city_rollup_common::qworker::{
    job_id::QProvingJobDataID,
    job_witnesses::agg::CRAggUserRegisterClaimDepositL2TransferCircuitInput,
    proof_store::QProofStoreReaderSync, verifier::QWorkerVerifyHelper,
};
use plonky2::{
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{
            CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget,
            VerifierOnlyCircuitData,
        },
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};

use crate::{
    state::agg::user_register_claim_deposits_l2_transfer::AggUserRegisterClaimDepositL2TransferGadget,
    worker::traits::QWorkerCircuitCustomWithDataSync,
};

#[derive(Debug)]
pub struct CRAggUserRegisterClaimDepositL2TransferCircuit<
    C: GenericConfig<D> + 'static,
    const D: usize,
> where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub op_register_user_proof: ProofWithPublicInputsTarget<D>,
    pub op_register_user_verifier_data: VerifierCircuitTarget,

    pub op_claim_l1_deposit_proof: ProofWithPublicInputsTarget<D>,
    pub op_claim_l1_deposit_verifier_data: VerifierCircuitTarget,

    pub op_l2_transfer_proof: ProofWithPublicInputsTarget<D>,
    pub op_l2_transfer_verifier_data: VerifierCircuitTarget,

    pub transition_gadget: AggUserRegisterClaimDepositL2TransferGadget,
    // end circuit targets
    pub minifier_chain: OASProofMinifierChain<D, C::F, C>,
    pub op_register_user_fingerprint: TPCircuitFingerprintConfig<C::F>,
    pub op_claim_l1_deposit_fingerprint: TPCircuitFingerprintConfig<C::F>,
    pub op_l2_transfer_fingerprint: TPCircuitFingerprintConfig<C::F>,
    pub circuit_data: CircuitData<C::F, C, D>,
}
impl<C: GenericConfig<D> + 'static, const D: usize>
    CRAggUserRegisterClaimDepositL2TransferCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub fn new(
        op_register_user_fingerprint: TPCircuitFingerprintConfig<C::F>,
        op_claim_l1_deposit_fingerprint: TPCircuitFingerprintConfig<C::F>,
        op_l2_transfer_fingerprint: TPCircuitFingerprintConfig<C::F>,
        child_common_data: &CommonCircuitData<C::F, D>,
        child_verifier_cap_height: usize,
    ) -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);

        let op_register_user_proof = builder.add_virtual_proof_with_pis(child_common_data);
        let op_register_user_verifier_data =
            builder.add_virtual_verifier_data(child_verifier_cap_height);

        let op_claim_l1_deposit_proof = builder.add_virtual_proof_with_pis(child_common_data);
        let op_claim_l1_deposit_verifier_data =
            builder.add_virtual_verifier_data(child_verifier_cap_height);

        let op_l2_transfer_proof = builder.add_virtual_proof_with_pis(child_common_data);
        let op_l2_transfer_verifier_data =
            builder.add_virtual_verifier_data(child_verifier_cap_height);

        builder.verify_proof::<C>(
            &op_register_user_proof,
            &op_register_user_verifier_data,
            child_common_data,
        );

        builder.verify_proof::<C>(
            &op_claim_l1_deposit_proof,
            &op_claim_l1_deposit_verifier_data,
            child_common_data,
        );

        builder.verify_proof::<C>(
            &op_l2_transfer_proof,
            &op_l2_transfer_verifier_data,
            child_common_data,
        );

        let actual_op_register_user_combined_state_transition =
            AggStateTransitionProofValidityGadget::add_virtual_to::<C::Hasher, C::F, D>(
                &mut builder,
                &op_register_user_proof,
                &op_register_user_verifier_data,
                &op_register_user_fingerprint,
            );

        let actual_op_claim_l1_deposit_combined_state_transition =
            AggStateTransitionProofValidityGadget::add_virtual_to::<C::Hasher, C::F, D>(
                &mut builder,
                &op_claim_l1_deposit_proof,
                &op_claim_l1_deposit_verifier_data,
                &op_claim_l1_deposit_fingerprint,
            );
        let actual_op_l2_transfer_combined_state_transition =
            AggStateTransitionProofValidityGadget::add_virtual_to::<C::Hasher, C::F, D>(
                &mut builder,
                &op_l2_transfer_proof,
                &op_l2_transfer_verifier_data,
                &op_l2_transfer_fingerprint,
            );

        let transition_gadget =
            AggUserRegisterClaimDepositL2TransferGadget::add_virtual_to::<C::Hasher, C::F, D>(
                &mut builder,
            );

        transition_gadget.connect_to_proof_results::<C::Hasher, C::F, D>(
            &mut builder,
            actual_op_register_user_combined_state_transition,
            actual_op_claim_l1_deposit_combined_state_transition,
            actual_op_l2_transfer_combined_state_transition,
        );

        builder.register_public_inputs(&transition_gadget.combined_state_transition_hash.elements);
        let circuit_data = builder.build::<C>();
        let minifier_chain =
            OASProofMinifierChain::new(&circuit_data.verifier_only, &circuit_data.common, 1);
        Self {
            op_register_user_proof,
            op_register_user_verifier_data,
            op_claim_l1_deposit_proof,
            op_claim_l1_deposit_verifier_data,
            op_l2_transfer_proof,
            op_l2_transfer_verifier_data,
            transition_gadget,
            op_register_user_fingerprint,
            op_claim_l1_deposit_fingerprint,
            op_l2_transfer_fingerprint,
            circuit_data,
            minifier_chain,
        }
    }
    pub fn prove_base(
        &self,
        input: &CRAggUserRegisterClaimDepositL2TransferCircuitInput<C::F>,
        op_register_user_proof: &ProofWithPublicInputs<C::F, C, D>,
        op_register_user_verifier_data: &VerifierOnlyCircuitData<C, D>,
        op_claim_l1_deposit_proof: &ProofWithPublicInputs<C::F, C, D>,
        op_claim_l1_deposit_verifier_data: &VerifierOnlyCircuitData<C, D>,
        op_l2_transfer_proof: &ProofWithPublicInputs<C::F, C, D>,
        op_l2_transfer_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut pw = PartialWitness::new();
        println!("setting proof for op_register_user_proof");

        pw.set_proof_with_pis_target::<C, D>(&self.op_register_user_proof, op_register_user_proof);
        println!("setting verifier data for op_register_user_proof");
        pw.set_verifier_data_target::<C, D>(
            &self.op_register_user_verifier_data,
            op_register_user_verifier_data,
        );

        println!("setting proof for op_claim_l1_deposit_proof");

        pw.set_proof_with_pis_target::<C, D>(
            &self.op_claim_l1_deposit_proof,
            op_claim_l1_deposit_proof,
        );
        println!("setting verifier data for op_claim_l1_deposit_verifier_data");

        pw.set_verifier_data_target::<C, D>(
            &self.op_claim_l1_deposit_verifier_data,
            op_claim_l1_deposit_verifier_data,
        );

        println!("setting proof for op_l2_transfer_proof");

        pw.set_proof_with_pis_target::<C, D>(&self.op_l2_transfer_proof, op_l2_transfer_proof);

        println!("setting verifier data for op_l2_transfer_verifier_data");
        pw.set_verifier_data_target::<C, D>(
            &self.op_l2_transfer_verifier_data,
            op_l2_transfer_verifier_data,
        );
        println!("proofs finished!");

        self.transition_gadget.set_witness(&mut pw, input);

        self.circuit_data.prove(pw)
    }
}

impl<C: GenericConfig<D> + 'static, const D: usize> QStandardCircuit<C, D>
    for CRAggUserRegisterClaimDepositL2TransferCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn get_fingerprint(&self) -> QHashOut<C::F> {
        QHashOut(self.minifier_chain.get_fingerprint())
    }

    fn get_verifier_config_ref(&self) -> &VerifierOnlyCircuitData<C, D> {
        self.minifier_chain.get_verifier_data()
    }

    fn get_common_circuit_data_ref(&self) -> &CommonCircuitData<C::F, D> {
        self.minifier_chain.get_common_data()
    }
}

impl<
        V: QWorkerVerifyHelper<C, D>,
        S: QProofStoreReaderSync,
        C: GenericConfig<D> + 'static,
        const D: usize,
    > QWorkerCircuitCustomWithDataSync<V, S, C, D>
    for CRAggUserRegisterClaimDepositL2TransferCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn prove_q_worker_custom(
        &self,
        verify_helper: &V,
        store: &S,
        job_id: QProvingJobDataID,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let input_data = store.get_bytes_by_id(job_id)?;
        let input = bincode::deserialize::<
            CRAggUserRegisterClaimDepositL2TransferCircuitInput<C::F>,
        >(&input_data)?;

        let (_, op_register_user_verifier_data, _) = verify_helper
            .get_verifier_triplet_for_circuit_type(
                input.op_register_user_proof_id.circuit_type.try_into()?,
            );
        let (_, op_claim_l1_deposit_verifier_data, _) = verify_helper
            .get_verifier_triplet_for_circuit_type(
                input.op_claim_l1_deposit_proof_id.circuit_type.try_into()?,
            );
        let (_, op_l2_transfer_verifier_data, _) = verify_helper
            .get_verifier_triplet_for_circuit_type(
                input.op_l2_transfer_proof_id.circuit_type.try_into()?,
            );

        let op_register_user_proof = store.get_proof_by_id(input.op_register_user_proof_id)?;
        let op_claim_l1_deposit_proof =
            store.get_proof_by_id(input.op_claim_l1_deposit_proof_id)?;
        let op_l2_transfer_proof = store.get_proof_by_id(input.op_l2_transfer_proof_id)?;

        let inner_proof = self.prove_base(
            &input,
            &op_register_user_proof,
            &op_register_user_verifier_data,
            &op_claim_l1_deposit_proof,
            &op_claim_l1_deposit_verifier_data,
            &op_l2_transfer_proof,
            &op_l2_transfer_verifier_data,
        )?;
        self.minifier_chain.prove(&inner_proof)
    }
}
