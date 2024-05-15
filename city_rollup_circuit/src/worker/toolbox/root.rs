use std::borrow::BorrowMut;

use city_common_circuit::circuits::traits::qstandard::QStandardCircuit;
use city_common_circuit::field::cubic::CubicExtendable;
use city_crypto::field::qfield::QRichField;
use city_crypto::hash::merkle::treeprover::TPCircuitFingerprintConfig;
use city_crypto::hash::qhashout::QHashOut;
use city_crypto::hash::traits::hasher::MerkleZeroHasher;
use city_rollup_common::qworker::fingerprints::CRWorkerToolboxRootCircuitFingerprints;
use city_rollup_common::qworker::job_id::ProvingJobCircuitType;
use city_rollup_common::qworker::job_id::QProvingJobDataID;
use city_rollup_common::qworker::proof_store::QProofStoreReaderSync;
use city_rollup_common::qworker::verifier::QWorkerVerifyHelper;
use plonky2::hash::hash_types::HashOut;
use plonky2::plonk::circuit_data::CommonCircuitData;
use plonky2::plonk::circuit_data::VerifierOnlyCircuitData;
use plonky2::plonk::config::AlgebraicHasher;
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;

use super::circuits::CRWorkerToolboxCoreCircuits;
use crate::block_circuits::root_aggregators::add_process_withdrawals_add_l1_deposit::CRAggAddProcessL1WithdrawalAddL1DepositCircuit;
use crate::block_circuits::root_aggregators::user_register_claim_deposits_l2_transfer::CRAggUserRegisterClaimDepositL2TransferCircuit;
use crate::block_circuits::root_state_transition::block_state_transition::CRBlockStateTransitionCircuit;
use crate::sighash_circuits::sighash_wrapper::CRSigHashWrapperCircuit;
use crate::worker::traits::QWorkerCircuitCustomWithDataSync;
use crate::worker::traits::QWorkerCircuitMutCustomWithDataSync;
use crate::worker::traits::QWorkerGenericProver;
use crate::worker::traits::QWorkerGenericProverMut;

pub struct CRWorkerToolboxRootCircuits<C: GenericConfig<D> + 'static, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
    C::F: CubicExtendable + QRichField,
{
    pub core: CRWorkerToolboxCoreCircuits<C, D>,
    // block aggreagtors
    pub block_agg_register_claim_deposit_transfer:
        CRAggUserRegisterClaimDepositL2TransferCircuit<C, D>,
    pub block_agg_add_process_withdrawal_add_deposit:
        CRAggAddProcessL1WithdrawalAddL1DepositCircuit<C, D>,
    pub block_state_transition: CRBlockStateTransitionCircuit<C, D>,
    pub sighash_wrapper: CRSigHashWrapperCircuit<C, D>,
    pub fingerprints: CRWorkerToolboxRootCircuitFingerprints<C::F>,
}

impl<C: GenericConfig<D> + 'static, const D: usize> CRWorkerToolboxRootCircuits<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
    C::F: CubicExtendable + QRichField,
{
    pub fn new(network_magic: u64, sighash_whitelist_root: QHashOut<C::F>) -> Self {
        let core = CRWorkerToolboxCoreCircuits::<C, D>::new(network_magic);
        let sighash_wrapper = CRSigHashWrapperCircuit::<C, D>::new(sighash_whitelist_root);

        let block_agg_register_claim_deposit_transfer =
            CRAggUserRegisterClaimDepositL2TransferCircuit::<C, D>::new(
                core.fingerprints.op_register_user,
                core.fingerprints.op_claim_l1_deposit,
                core.fingerprints.op_l2_transfer,
                core.agg_state_transition.get_common_circuit_data_ref(),
                core.agg_state_transition
                    .get_verifier_config_ref()
                    .constants_sigmas_cap
                    .height(),
            );
        let block_agg_add_process_withdrawal_add_deposit =
            CRAggAddProcessL1WithdrawalAddL1DepositCircuit::<C, D>::new(
                core.fingerprints.op_add_l1_withdrawal,
                core.fingerprints.op_process_l1_withdrawal,
                core.fingerprints.op_add_l1_deposit,
                core.agg_state_transition.get_common_circuit_data_ref(),
                core.agg_state_transition
                    .get_verifier_config_ref()
                    .constants_sigmas_cap
                    .height(),
                core.agg_state_transition_with_events
                    .get_common_circuit_data_ref(),
                core.agg_state_transition_with_events
                    .get_verifier_config_ref()
                    .constants_sigmas_cap
                    .height(),
            );

        let block_state_transition = CRBlockStateTransitionCircuit::<C, D>::new(
            &block_agg_register_claim_deposit_transfer.get_common_circuit_data_ref(),
            &block_agg_register_claim_deposit_transfer.get_verifier_config_ref(),
            &block_agg_add_process_withdrawal_add_deposit.get_common_circuit_data_ref(),
            &block_agg_add_process_withdrawal_add_deposit.get_verifier_config_ref(),
        );

        let fingerprints = CRWorkerToolboxRootCircuitFingerprints::<C::F> {
            network_magic,
            block_agg_register_claim_deposit_transfer: block_agg_register_claim_deposit_transfer
                .get_fingerprint(),
            block_agg_add_process_withdrawal_add_deposit:
                block_agg_add_process_withdrawal_add_deposit.get_fingerprint(),
            block_state_transition: block_state_transition.get_fingerprint(),
        };

        Self {
            core,
            block_agg_register_claim_deposit_transfer,
            block_agg_add_process_withdrawal_add_deposit,
            block_state_transition,
            sighash_wrapper,
            fingerprints,
        }
    }
    pub fn print_op_common_data(&self) {
        self.core.print_op_common_data();

        self.block_agg_register_claim_deposit_transfer
            .print_config_with_name("block_agg_register_claim_deposit_transfer");
    }
}

impl<C: GenericConfig<D> + 'static, const D: usize> QWorkerVerifyHelper<C, D>
    for CRWorkerToolboxRootCircuits<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
    C::F: CubicExtendable + QRichField,
{
    fn get_verifier_triplet_for_circuit_type(
        &self,
        circuit_type: ProvingJobCircuitType,
    ) -> (
        &CommonCircuitData<C::F, D>,
        &VerifierOnlyCircuitData<C, D>,
        QHashOut<C::F>,
    ) {
        match circuit_type {
            ProvingJobCircuitType::AggUserRegisterClaimDepositL2Transfer => self
                .block_agg_register_claim_deposit_transfer
                .get_verifier_triplet(),
            ProvingJobCircuitType::AggAddProcessL1WithdrawalAddL1Deposit => self
                .block_agg_add_process_withdrawal_add_deposit
                .get_verifier_triplet(),
            ProvingJobCircuitType::GenerateRollupStateTransitionProof => {
                self.block_state_transition.get_verifier_triplet()
            }
            ProvingJobCircuitType::GenerateSigHashIntrospectionProof => {
                self.sighash_wrapper.get_verifier_triplet()
            }
            other => self.core.get_verifier_triplet_for_circuit_type(other),
        }
    }

    fn get_tree_prover_fingerprint_config(
        &self,
        circuit_type: ProvingJobCircuitType,
    ) -> anyhow::Result<TPCircuitFingerprintConfig<C::F>> {
        self.core.get_tree_prover_fingerprint_config(circuit_type)
    }
}

impl<S: QProofStoreReaderSync, C: GenericConfig<D> + 'static, const D: usize>
    QWorkerGenericProver<S, C, D> for CRWorkerToolboxRootCircuits<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
    C::F: CubicExtendable + QRichField,
{
    fn worker_prove(
        &self,
        store: &S,
        job_id: QProvingJobDataID,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let circuit_type = job_id.circuit_type;
        match circuit_type {
            ProvingJobCircuitType::AggUserRegisterClaimDepositL2Transfer => self
                .block_agg_register_claim_deposit_transfer
                .prove_q_worker_custom(self, store, job_id),
            ProvingJobCircuitType::AggAddProcessL1WithdrawalAddL1Deposit => self
                .block_agg_add_process_withdrawal_add_deposit
                .prove_q_worker_custom(self, store, job_id),
            ProvingJobCircuitType::GenerateSigHashIntrospectionProof => self
                .sighash_wrapper
                .prove_q_worker_custom(self, store, job_id),
            ProvingJobCircuitType::GenerateRollupStateTransitionProof => self
                .block_state_transition
                .prove_q_worker_custom(self, store, job_id),
            _ => self.core.worker_prove(store, job_id),
        }
    }
}

impl<S: QProofStoreReaderSync, C: GenericConfig<D> + 'static, const D: usize>
    QWorkerGenericProverMut<S, C, D> for CRWorkerToolboxRootCircuits<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
    C::F: CubicExtendable + QRichField,
{
    fn worker_prove_mut(
        &mut self,
        store: &S,
        job_id: QProvingJobDataID,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let circuit_type = job_id.circuit_type;
        match circuit_type {
            ProvingJobCircuitType::AggUserRegisterClaimDepositL2Transfer => self
                .block_agg_register_claim_deposit_transfer
                .prove_q_worker_custom(self, store, job_id),
            ProvingJobCircuitType::AggAddProcessL1WithdrawalAddL1Deposit => self
                .block_agg_add_process_withdrawal_add_deposit
                .prove_q_worker_custom(self, store, job_id),
            ProvingJobCircuitType::GenerateSigHashIntrospectionProof => (self.sighash_wrapper)
                .borrow_mut()
                .prove_q_worker_mut_custom(store, job_id),
            ProvingJobCircuitType::GenerateRollupStateTransitionProof => self
                .block_state_transition
                .prove_q_worker_custom(self, store, job_id),
            _ => self.core.worker_prove(store, job_id),
        }
    }
}
