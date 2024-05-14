use city_common_circuit::circuits::traits::qstandard::QStandardCircuit;
use city_crypto::hash::{
    merkle::treeprover::TPCircuitFingerprintConfig, qhashout::QHashOut,
    traits::hasher::MerkleZeroHasher,
};
use city_rollup_common::qworker::{
    fingerprints::CRWorkerToolboxRootCircuitFingerprints,
    job_id::{ProvingJobCircuitType, QProvingJobDataID},
    proof_store::QProofStoreReaderSync,
    verifier::QWorkerVerifyHelper,
};
use plonky2::{
    hash::hash_types::HashOut,
    plonk::{
        circuit_data::{CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::{
    block_circuits::{
        root_aggregators::{
            add_process_withdrawals_add_l1_deposit::CRAggAddProcessL1WithdrawalAddL1DepositCircuit,
            user_register_claim_deposits_l2_transfer::CRAggUserRegisterClaimDepositL2TransferCircuit,
        },
        root_state_transition::block_state_transition::CRBlockStateTransitionCircuit,
    },
    worker::traits::{QWorkerCircuitCustomWithDataSync, QWorkerGenericProver},
};

use super::circuits::CRWorkerToolboxCoreCircuits;

pub struct CRWorkerToolboxRootCircuits<C: GenericConfig<D> + 'static, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    pub core: CRWorkerToolboxCoreCircuits<C, D>,
    // block aggreagtors
    pub block_agg_register_claim_deposit_transfer:
        CRAggUserRegisterClaimDepositL2TransferCircuit<C, D>,
    pub block_agg_add_process_withdrawal_add_deposit:
        CRAggAddProcessL1WithdrawalAddL1DepositCircuit<C, D>,
    pub block_state_transition: CRBlockStateTransitionCircuit<C, D>,
    pub fingerprints: CRWorkerToolboxRootCircuitFingerprints<C::F>,
}

impl<C: GenericConfig<D> + 'static, const D: usize> CRWorkerToolboxRootCircuits<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    pub fn new(network_magic: u64) -> Self {
        let core = CRWorkerToolboxCoreCircuits::<C, D>::new(network_magic);

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
            ProvingJobCircuitType::GenerateRollupStateTransitionProof => self
                .block_state_transition
                .prove_q_worker_custom(self, store, job_id),
            _ => self.core.worker_prove(store, job_id),
        }
    }
}
