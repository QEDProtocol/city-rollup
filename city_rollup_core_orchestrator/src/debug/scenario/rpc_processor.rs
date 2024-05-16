use city_rollup_common::api::data::block::requested_actions::CityAddWithdrawalRequest;
use city_rollup_common::api::data::block::requested_actions::CityClaimDepositRequest;
use city_rollup_common::api::data::block::requested_actions::CityRegisterUserRequest;
use city_rollup_common::api::data::block::requested_actions::CityTokenTransferRequest;
use city_rollup_common::api::data::block::rpc_request::CityAddWithdrawalRPCRequest;
use city_rollup_common::api::data::block::rpc_request::CityClaimDepositRPCRequest;
use city_rollup_common::api::data::block::rpc_request::CityRegisterUserRPCRequest;
use city_rollup_common::api::data::block::rpc_request::CityTokenTransferRPCRequest;
use city_rollup_common::qworker::job_id::QProvingJobDataID;
use city_rollup_common::qworker::proof_store::QProofStore;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct CityScenarioRequestedActionsFromRPC<F: RichField> {
    pub token_transfers: Vec<CityTokenTransferRequest>,
    pub register_users: Vec<CityRegisterUserRequest<F>>,
    pub claim_l1_deposits: Vec<CityClaimDepositRequest>,
    pub add_withdrawals: Vec<CityAddWithdrawalRequest>,
}
impl<F: RichField> CityScenarioRequestedActionsFromRPC<F> {
    pub fn new() -> Self {
        Self {
            token_transfers: Vec::new(),
            register_users: Vec::new(),
            claim_l1_deposits: Vec::new(),
            add_withdrawals: Vec::new(),
        }
    }
}

pub struct DebugRPCProcessor<F: RichField + Extendable<D>, const D: usize> {
    pub checkpoint_id: u64,
    pub rpc_node_id: u32,
    pub output: CityScenarioRequestedActionsFromRPC<F>,
}

impl<F: RichField + Extendable<D>, const D: usize> DebugRPCProcessor<F, D> {
    pub fn new(checkpoint_id: u64) -> Self {
        Self {
            checkpoint_id: checkpoint_id,
            rpc_node_id: 0,
            output: CityScenarioRequestedActionsFromRPC::new(),
        }
    }
    pub fn injest_rpc_claim_deposit<PS: QProofStore>(
        &self,
        ps: &mut PS,
        req: &CityClaimDepositRPCRequest,
    ) -> anyhow::Result<CityClaimDepositRequest> {
        let count = self.output.claim_l1_deposits.len() as u32;
        let signature_proof_id = QProvingJobDataID::claim_deposit_l1_signature_proof(
            self.rpc_node_id,
            self.checkpoint_id,
            count,
        );
        ps.set_bytes_by_id(signature_proof_id, &req.signature_proof)?;

        Ok(CityClaimDepositRequest::new(
            req.user_id,
            req.deposit_id,
            req.value,
            req.txid,
            req.public_key,
            signature_proof_id,
        ))
    }
    pub fn injest_rpc_register_user(
        &self,
        req: &CityRegisterUserRPCRequest<F>,
    ) -> anyhow::Result<CityRegisterUserRequest<F>> {
        Ok(CityRegisterUserRequest::new(req.public_key))
    }
    pub fn injest_rpc_token_transfer<PS: QProofStore>(
        &self,
        ps: &mut PS,
        req: &CityTokenTransferRPCRequest,
    ) -> anyhow::Result<CityTokenTransferRequest> {
        let count = self.output.token_transfers.len() as u32;
        let signature_proof_id = QProvingJobDataID::transfer_signature_proof(
            self.rpc_node_id,
            self.checkpoint_id,
            count,
        );
        ps.set_bytes_by_id(signature_proof_id, &req.signature_proof)?;

        Ok(CityTokenTransferRequest::new(
            req.user_id,
            req.to,
            req.value,
            req.nonce,
            signature_proof_id,
        ))
    }
    pub fn injest_rpc_add_withdrawal<PS: QProofStore>(
        &self,
        ps: &mut PS,
        req: &CityAddWithdrawalRPCRequest,
    ) -> anyhow::Result<CityAddWithdrawalRequest> {
        let count = self.output.add_withdrawals.len() as u64;
        let signature_proof_id = QProvingJobDataID::withdrawal_signature_proof(
            self.rpc_node_id,
            self.checkpoint_id,
            count as u32,
        );
        ps.set_bytes_by_id(signature_proof_id, &req.signature_proof)?;

        Ok(CityAddWithdrawalRequest::new(
            req.user_id,
            req.value,
            req.nonce,
            count,
            req.destination_type,
            req.destination,
            signature_proof_id,
        ))
    }
    pub fn process_withdrawals<PS: QProofStore>(
        &mut self,
        ps: &mut PS,
        reqs: &[CityAddWithdrawalRPCRequest],
    ) -> anyhow::Result<()> {
        for req in reqs {
            let withdrawal = self.injest_rpc_add_withdrawal(ps, req)?;
            self.output.add_withdrawals.push(withdrawal);
        }
        Ok(())
    }
    pub fn process_deposits<PS: QProofStore>(
        &mut self,
        ps: &mut PS,
        reqs: &[CityClaimDepositRPCRequest],
    ) -> anyhow::Result<()> {
        for req in reqs {
            let deposit = self.injest_rpc_claim_deposit(ps, req)?;
            self.output.claim_l1_deposits.push(deposit);
        }
        Ok(())
    }
    pub fn process_transfers<PS: QProofStore>(
        &mut self,
        ps: &mut PS,
        reqs: &[CityTokenTransferRPCRequest],
    ) -> anyhow::Result<()> {
        for req in reqs {
            let xfer = self.injest_rpc_token_transfer(ps, req)?;
            self.output.token_transfers.push(xfer);
        }
        Ok(())
    }
    pub fn process_register_users(
        &mut self,
        reqs: &[CityRegisterUserRPCRequest<F>],
    ) -> anyhow::Result<()> {
        for req in reqs {
            let register = self.injest_rpc_register_user(req)?;
            self.output.register_users.push(register);
        }
        Ok(())
    }
}
