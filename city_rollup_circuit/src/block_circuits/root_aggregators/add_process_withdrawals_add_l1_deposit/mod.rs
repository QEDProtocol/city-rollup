use city_common_circuit::{
    circuits::traits::qstandard::QStandardCircuit,
    proof_minifier::pm_chain::OASProofMinifierChain,
    treeprover::aggregation::gadgets::{
        AggStateTransitionProofValidityGadget, AggStateTransitionWithEventsProofValidityGadget,
    },
};
use city_crypto::hash::{merkle::treeprover::TPCircuitFingerprintConfig, qhashout::QHashOut};
use city_rollup_common::qworker::{
    job_id::QProvingJobDataID,
    job_witnesses::agg::CRAggAddProcessL1WithdrawalAddL1DepositCircuitInput,
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
    state::agg::add_process_withdrawals_add_l1_deposit::AggAddProcessL1WithdrawalAddL1DepositGadget,
    worker::traits::QWorkerCircuitCustomWithDataSync,
};

#[derive(Debug)]
pub struct CRAggAddProcessL1WithdrawalAddL1DepositCircuit<
    C: GenericConfig<D> + 'static,
    const D: usize,
> where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub op_add_l1_withdrawal_proof: ProofWithPublicInputsTarget<D>,
    pub op_add_l1_withdrawal_verifier_data: VerifierCircuitTarget,

    pub op_process_l1_withdrawal_proof: ProofWithPublicInputsTarget<D>,
    pub op_process_l1_withdrawal_verifier_data: VerifierCircuitTarget,

    pub op_add_l1_deposit_proof: ProofWithPublicInputsTarget<D>,
    pub op_add_l1_deposit_verifier_data: VerifierCircuitTarget,

    pub transition_gadget: AggAddProcessL1WithdrawalAddL1DepositGadget,
    // end circuit targets
    pub minifier_chain: OASProofMinifierChain<D, C::F, C>,
    pub op_add_l1_withdrawal_fingerprint: TPCircuitFingerprintConfig<C::F>,
    pub op_process_l1_withdrawal_fingerprint: TPCircuitFingerprintConfig<C::F>,
    pub op_add_l1_deposit_fingerprint: TPCircuitFingerprintConfig<C::F>,
    pub circuit_data: CircuitData<C::F, C, D>,
}
impl<C: GenericConfig<D> + 'static, const D: usize>
    CRAggAddProcessL1WithdrawalAddL1DepositCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub fn new(
        op_add_l1_withdrawal_fingerprint: TPCircuitFingerprintConfig<C::F>,
        op_process_l1_withdrawal_fingerprint: TPCircuitFingerprintConfig<C::F>,
        op_add_l1_deposit_fingerprint: TPCircuitFingerprintConfig<C::F>,
        child_common_data: &CommonCircuitData<C::F, D>,
        child_verifier_cap_height: usize,
        child_with_events_common_data: &CommonCircuitData<C::F, D>,
        child_with_events_verifier_cap_height: usize,
    ) -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);

        let op_add_l1_withdrawal_proof = builder.add_virtual_proof_with_pis(child_common_data);
        let op_add_l1_withdrawal_verifier_data =
            builder.add_virtual_verifier_data(child_verifier_cap_height);

        let op_process_l1_withdrawal_proof =
            builder.add_virtual_proof_with_pis(child_with_events_common_data);
        let op_process_l1_withdrawal_verifier_data =
            builder.add_virtual_verifier_data(child_with_events_verifier_cap_height);

        let op_add_l1_deposit_proof =
            builder.add_virtual_proof_with_pis(child_with_events_common_data);
        let op_add_l1_deposit_verifier_data =
            builder.add_virtual_verifier_data(child_with_events_verifier_cap_height);

        builder.verify_proof::<C>(
            &op_add_l1_withdrawal_proof,
            &op_add_l1_withdrawal_verifier_data,
            child_common_data,
        );

        builder.verify_proof::<C>(
            &op_process_l1_withdrawal_proof,
            &op_process_l1_withdrawal_verifier_data,
            child_with_events_common_data,
        );

        builder.verify_proof::<C>(
            &op_add_l1_deposit_proof,
            &op_add_l1_deposit_verifier_data,
            child_with_events_common_data,
        );

        let actual_op_add_l1_withdrawal_combined_state_transition =
            AggStateTransitionProofValidityGadget::add_virtual_to::<C::Hasher, C::F, D>(
                &mut builder,
                &op_add_l1_withdrawal_proof,
                &op_add_l1_withdrawal_verifier_data,
                &op_add_l1_withdrawal_fingerprint,
            );

        let actual_op_process_l1_withdrawal_combined_state_transition =
            AggStateTransitionWithEventsProofValidityGadget::add_virtual_to::<C::Hasher, C::F, D>(
                &mut builder,
                &op_process_l1_withdrawal_proof,
                &op_process_l1_withdrawal_verifier_data,
                &op_process_l1_withdrawal_fingerprint,
            );
        let actual_op_add_l1_deposit_combined_state_transition =
            AggStateTransitionWithEventsProofValidityGadget::add_virtual_to::<C::Hasher, C::F, D>(
                &mut builder,
                &op_add_l1_deposit_proof,
                &op_add_l1_deposit_verifier_data,
                &op_add_l1_deposit_fingerprint,
            );

        let transition_gadget =
            AggAddProcessL1WithdrawalAddL1DepositGadget::add_virtual_to::<C::Hasher, C::F, D>(
                &mut builder,
            );

        transition_gadget.connect_to_proof_results::<C::Hasher, C::F, D>(
            &mut builder,
            actual_op_add_l1_withdrawal_combined_state_transition,
            actual_op_process_l1_withdrawal_combined_state_transition
                .state_transition_combined_hash,
            actual_op_add_l1_deposit_combined_state_transition.state_transition_combined_hash,
        );

        builder.register_public_inputs(&transition_gadget.combined_state_transition_hash.elements);
        builder.register_public_inputs(
            &actual_op_process_l1_withdrawal_combined_state_transition
                .events_hash
                .elements,
        );
        builder.register_public_inputs(
            &actual_op_add_l1_deposit_combined_state_transition
                .events_hash
                .elements,
        );

        let circuit_data = builder.build::<C>();
        let minifier_chain =
            OASProofMinifierChain::new(&circuit_data.verifier_only, &circuit_data.common, 1);
        Self {
            op_add_l1_withdrawal_proof,
            op_add_l1_withdrawal_verifier_data,
            op_process_l1_withdrawal_proof,
            op_process_l1_withdrawal_verifier_data,
            op_add_l1_deposit_proof,
            op_add_l1_deposit_verifier_data,
            transition_gadget,
            op_add_l1_withdrawal_fingerprint,
            op_process_l1_withdrawal_fingerprint,
            op_add_l1_deposit_fingerprint,
            circuit_data,
            minifier_chain,
        }
    }
    pub fn prove_base(
        &self,
        input: &CRAggAddProcessL1WithdrawalAddL1DepositCircuitInput<C::F>,
        op_add_l1_withdrawal_proof: &ProofWithPublicInputs<C::F, C, D>,
        op_add_l1_withdrawal_verifier_data: &VerifierOnlyCircuitData<C, D>,
        op_process_l1_withdrawal_proof: &ProofWithPublicInputs<C::F, C, D>,
        op_process_l1_withdrawal_verifier_data: &VerifierOnlyCircuitData<C, D>,
        op_add_l1_deposit_proof: &ProofWithPublicInputs<C::F, C, D>,
        op_add_l1_deposit_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut pw = PartialWitness::new();
        println!("setting proof for op_add_l1_withdrawal_proof");

        pw.set_proof_with_pis_target::<C, D>(
            &self.op_add_l1_withdrawal_proof,
            op_add_l1_withdrawal_proof,
        );
        println!("setting verifier data for op_add_l1_withdrawal_proof");
        pw.set_verifier_data_target::<C, D>(
            &self.op_add_l1_withdrawal_verifier_data,
            op_add_l1_withdrawal_verifier_data,
        );

        println!("setting proof for op_process_l1_withdrawal_proof");

        pw.set_proof_with_pis_target::<C, D>(
            &self.op_process_l1_withdrawal_proof,
            op_process_l1_withdrawal_proof,
        );
        println!("setting verifier data for op_process_l1_withdrawal_verifier_data");

        pw.set_verifier_data_target::<C, D>(
            &self.op_process_l1_withdrawal_verifier_data,
            op_process_l1_withdrawal_verifier_data,
        );

        println!("setting proof for op_add_l1_deposit_proof");

        pw.set_proof_with_pis_target::<C, D>(
            &self.op_add_l1_deposit_proof,
            op_add_l1_deposit_proof,
        );

        println!("setting verifier data for op_add_l1_deposit_verifier_data");
        pw.set_verifier_data_target::<C, D>(
            &self.op_add_l1_deposit_verifier_data,
            op_add_l1_deposit_verifier_data,
        );
        println!("proofs finished!");

        self.transition_gadget.set_witness(&mut pw, input);

        self.circuit_data.prove(pw)
    }
}

impl<C: GenericConfig<D> + 'static, const D: usize> QStandardCircuit<C, D>
    for CRAggAddProcessL1WithdrawalAddL1DepositCircuit<C, D>
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
    for CRAggAddProcessL1WithdrawalAddL1DepositCircuit<C, D>
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
            CRAggAddProcessL1WithdrawalAddL1DepositCircuitInput<C::F>,
        >(&input_data)?;

        let (_, op_add_l1_withdrawal_verifier_data, _) = verify_helper
            .get_verifier_triplet_for_circuit_type(
                input
                    .op_add_l1_withdrawal_proof_id
                    .circuit_type
                    .try_into()?,
            );
        let (_, op_process_l1_withdrawal_verifier_data, _) = verify_helper
            .get_verifier_triplet_for_circuit_type(
                input
                    .op_process_l1_withdrawal_proof_id
                    .circuit_type
                    .try_into()?,
            );
        let (_, op_add_l1_deposit_verifier_data, _) = verify_helper
            .get_verifier_triplet_for_circuit_type(
                input.op_add_l1_deposit_proof_id.circuit_type.try_into()?,
            );

        let op_add_l1_withdrawal_proof =
            store.get_proof_by_id(input.op_add_l1_withdrawal_proof_id)?;
        let op_process_l1_withdrawal_proof =
            store.get_proof_by_id(input.op_process_l1_withdrawal_proof_id)?;
        let op_add_l1_deposit_proof = store.get_proof_by_id(input.op_add_l1_deposit_proof_id)?;

        let inner_proof = self.prove_base(
            &input,
            &op_add_l1_withdrawal_proof,
            &op_add_l1_withdrawal_verifier_data,
            &op_process_l1_withdrawal_proof,
            &op_process_l1_withdrawal_verifier_data,
            &op_add_l1_deposit_proof,
            &op_add_l1_deposit_verifier_data,
        )?;
        self.minifier_chain.prove(&inner_proof)
    }
}
