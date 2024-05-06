use std::marker::PhantomData;

use city_rollup_common::{
    api::data::block::{
        requested_actions::{
            CityAddDepositRequest, CityAddWithdrawalRequest, CityClaimDepositRequest,
            CityProcessWithdrawalRequest, CityRegisterUserRequest, CityTokenTransferRequest,
        },
        rpc_request::{
            CityAddWithdrawalRPCRequest, CityClaimDepositRPCRequest, CityRegisterUserRPCRequest,
            CityTokenTransferRPCRequest,
        },
    },
    introspection::transaction::BTCTransaction,
    qworker::{
        job_id::{ProvingJobCircuitType, QJobTopic, QProvingJobDataID},
        proof_store::{QProofStoreReaderAsync, QProofStoreReaderSync, QProofStoreWriterSync},
    },
};
use kvq::traits::KVQBinaryStore;
use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField},
    hash::hash_types::RichField,
    plonk::config::{AlgebraicHasher, GenericConfig, PoseidonGoldilocksConfig},
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct DebugScenarioRequestedActionsFromRPC<F: RichField> {
    pub token_transfers: Vec<CityTokenTransferRequest>,
    pub register_users: Vec<CityRegisterUserRequest<F>>,
    pub claim_l1_deposits: Vec<CityClaimDepositRequest>,
    pub withdrawals: Vec<CityAddWithdrawalRequest>,
}
impl<F: RichField> DebugScenarioRequestedActionsFromRPC<F> {
    pub fn new() -> Self {
        Self {
            token_transfers: Vec::new(),
            register_users: Vec::new(),
            claim_l1_deposits: Vec::new(),
            withdrawals: Vec::new(),
        }
    }
}

pub struct DebugRPCProcessor<
    PS: QProofStoreWriterSync + QProofStoreReaderSync,
    F: RichField + Extendable<D>,
    const D: usize,
> {
    _ps: PhantomData<PS>,
    pub checkpoint_id: u64,
    pub rpc_node_id: u32,
    pub output: DebugScenarioRequestedActionsFromRPC<F>,
}

impl<
        PS: QProofStoreWriterSync + QProofStoreReaderSync,
        F: RichField + Extendable<D>,
        const D: usize,
    > DebugRPCProcessor<PS, F, D>
{
    pub fn new() -> Self {
        Self {
            _ps: PhantomData,
            checkpoint_id: 1,
            rpc_node_id: 0,
            output: DebugScenarioRequestedActionsFromRPC::new(),
        }
    }
    pub fn injest_rpc_claim_deposit(
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
            req.nonce,
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
    pub fn injest_rpc_token_transfer(
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
    pub fn injest_rpc_add_withdrawal(
        &self,
        ps: &mut PS,
        req: &CityAddWithdrawalRPCRequest,
    ) -> anyhow::Result<CityAddWithdrawalRequest> {
        let count = self.output.withdrawals.len() as u32;
        let signature_proof_id = QProvingJobDataID::transfer_signature_proof(
            self.rpc_node_id,
            self.checkpoint_id,
            count,
        );
        ps.set_bytes_by_id(signature_proof_id, &req.signature_proof)?;

        Ok(CityAddWithdrawalRequest::new(
            req.user_id,
            req.value,
            req.nonce,
            req.destination_type,
            req.destination,
            signature_proof_id,
        ))
    }
    pub fn process_withdrawals(
        &mut self,
        ps: &mut PS,
        reqs: &[CityAddWithdrawalRPCRequest],
    ) -> anyhow::Result<()> {
        for req in reqs {
            let withdrawal = self.injest_rpc_add_withdrawal(ps, req)?;
            self.output.withdrawals.push(withdrawal);
        }
        Ok(())
    }
    pub fn process_deposits(
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
    pub fn process_transfers(
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
