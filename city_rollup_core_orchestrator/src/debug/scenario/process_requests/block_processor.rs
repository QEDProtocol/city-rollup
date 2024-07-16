use std::marker::PhantomData;

use city_rollup_common::{
    api::data::{
        block::requested_actions::{
            CityAddDepositRequest, CityAddWithdrawalRequest, CityClaimDepositRequest,
            CityProcessWithdrawalRequest, CityRegisterUserRequest, CityTokenTransferRequest,
        },
        store::CityL2BlockState,
    },
    qworker::{
        fingerprints::CRWorkerToolboxCoreCircuitFingerprints,
        job_id::{ProvingJobCircuitType, QProvingJobDataID},
        job_witnesses::op::{
            CRAddL1DepositCircuitInput, CRAddL1WithdrawalCircuitInput,
            CRClaimL1DepositCircuitInput, CRL2TransferCircuitInput,
            CRProcessL1WithdrawalCircuitInput, CRUserRegistrationCircuitInput,
            CircuitInputWithJobId,
        },
        proof_store::QProofStore,
    },
};
use city_store::config::F;
use kvq::traits::{KVQBinaryStore, KVQSerializable};

use super::op_processor::CityOrchestratorOpRequestProcessor;

pub struct CityOrchestratorBlockProcessor<S: KVQBinaryStore, PS: QProofStore> {
    pub checkpoint_id: u64,
    pub block_add_deposit_count: u64,
    pub block_add_withdrawal_count: u64,
    pub block_claim_deposit_count: u64,
    pub block_l2_transfer_count: u64,
    pub block_process_withdrawal_count: u64,
    pub block_register_user_count: u64,

    pub op_processor: CityOrchestratorOpRequestProcessor<S>,
    _proof_store: PhantomData<PS>,
}

impl<S: KVQBinaryStore, PS: QProofStore> CityOrchestratorBlockProcessor<S, PS> {
    pub fn new(
        last_block_state: CityL2BlockState,
        fingerprints: CRWorkerToolboxCoreCircuitFingerprints<F>,
    ) -> Self {
        Self {
            checkpoint_id: last_block_state.checkpoint_id + 1,
            block_add_deposit_count: 0,
            block_add_withdrawal_count: 0,
            block_claim_deposit_count: 0,
            block_l2_transfer_count: 0,
            block_process_withdrawal_count: 0,
            block_register_user_count: 0,

            op_processor: CityOrchestratorOpRequestProcessor::new(last_block_state, fingerprints),
            _proof_store: PhantomData,
        }
    }

    pub fn process_register_user(
        &mut self,
        store: &mut S,
        proof_store: &mut PS,
        req: &CityRegisterUserRequest<F>,
    ) -> anyhow::Result<CircuitInputWithJobId<CRUserRegistrationCircuitInput<F>>> {
        let op_result = self
            .op_processor
            .process_register_user_request(store, req)?;

        let job_id = QProvingJobDataID::core_op_witness(
            ProvingJobCircuitType::RegisterUser,
            self.checkpoint_id,
            self.block_register_user_count as u32,
        );

        proof_store.set_bytes_by_id(job_id, &op_result.to_bytes()?)?;
        self.block_register_user_count += 1;
        Ok(CircuitInputWithJobId::new(op_result, job_id))
    }

    pub fn process_l2_transfer(
        &mut self,
        store: &mut S,
        proof_store: &mut PS,
        req: &CityTokenTransferRequest,
    ) -> anyhow::Result<CircuitInputWithJobId<CRL2TransferCircuitInput<F>>> {
        let op_result = self.op_processor.process_l2_transfer_request(store, req)?;
        let job_id = QProvingJobDataID::core_op_witness(
            ProvingJobCircuitType::TransferTokensL2,
            self.checkpoint_id,
            self.block_l2_transfer_count as u32,
        );

        proof_store.set_bytes_by_id(job_id, &op_result.to_bytes()?)?;
        self.block_l2_transfer_count += 1;
        Ok(CircuitInputWithJobId::new(op_result, job_id))
    }

    pub fn process_add_withdrawal(
        &mut self,
        store: &mut S,
        proof_store: &mut PS,
        req: &CityAddWithdrawalRequest,
    ) -> anyhow::Result<CircuitInputWithJobId<CRAddL1WithdrawalCircuitInput<F>>> {
        let op_result = self
            .op_processor
            .process_add_withdrawal_request(store, req)?;


        let job_id = QProvingJobDataID::core_op_witness(
            ProvingJobCircuitType::AddL1Withdrawal,
            self.checkpoint_id,
            self.block_add_withdrawal_count as u32,
        );

        proof_store.set_bytes_by_id(job_id, &op_result.to_bytes()?)?;
        self.block_add_withdrawal_count += 1;
        Ok(CircuitInputWithJobId::new(op_result, job_id))
    }

    pub fn process_complete_l1_withdrawal(
        &mut self,
        store: &mut S,
        proof_store: &mut PS,
        req: &CityProcessWithdrawalRequest,
    ) -> anyhow::Result<CircuitInputWithJobId<CRProcessL1WithdrawalCircuitInput<F>>> {
        let op_result = self
            .op_processor
            .process_complete_l1_withdrawal_request(store, req)?;


        let job_id = QProvingJobDataID::core_op_witness(
            ProvingJobCircuitType::ProcessL1Withdrawal,
            self.checkpoint_id,
            self.block_process_withdrawal_count as u32,
        );

        proof_store.set_bytes_by_id(job_id, &op_result.to_bytes()?)?;
        self.block_process_withdrawal_count += 1;
        Ok(CircuitInputWithJobId::new(op_result, job_id))
    }

    pub fn process_add_deposit(
        &mut self,
        store: &mut S,
        proof_store: &mut PS,
        req: &CityAddDepositRequest,
    ) -> anyhow::Result<CircuitInputWithJobId<CRAddL1DepositCircuitInput<F>>> {
        let op_result = self.op_processor.process_add_deposit_request(store, req)?;

        let job_id = QProvingJobDataID::core_op_witness(
            ProvingJobCircuitType::AddL1Deposit,
            self.checkpoint_id,
            self.block_add_deposit_count as u32,
        );

        proof_store.set_bytes_by_id(job_id, &op_result.to_bytes()?)?;
        self.block_add_deposit_count += 1;
        Ok(CircuitInputWithJobId::new(op_result, job_id))
    }

    pub fn process_claim_deposit(
        &mut self,
        store: &mut S,
        proof_store: &mut PS,
        req: &CityClaimDepositRequest,
    ) -> anyhow::Result<CircuitInputWithJobId<CRClaimL1DepositCircuitInput<F>>> {
        let op_result = self
            .op_processor
            .process_claim_deposit_request(store, req)?;

        let job_id = QProvingJobDataID::core_op_witness(
            ProvingJobCircuitType::ClaimL1Deposit,
            self.checkpoint_id,
            self.block_claim_deposit_count as u32,
        );
        

        proof_store.set_bytes_by_id(job_id, &op_result.to_bytes()?)?;
        self.block_claim_deposit_count += 1;
        Ok(CircuitInputWithJobId::new(op_result, job_id))
    }
}
