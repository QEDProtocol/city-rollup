use kvq::traits::KVQBinaryStore;
use plonky2::{field::extension::Extendable, hash::hash_types::RichField};

use crate::{
    actors::{rpc_processor::QRPCProcessor, traits::OrchestratorRPCEventSenderSync},
    api::data::block::rpc_request::{
        CityAddWithdrawalRPCRequest, CityClaimDepositRPCRequest, CityRegisterUserRPCRequest,
        CityTokenTransferRPCRequest,
    },
    qworker::proof_store::QProofStore,
};

pub struct DevMemoryCoordinatatorRPCQueue<F: RichField> {
    pub claim_deposits: Vec<CityClaimDepositRPCRequest>,
    pub register_users: Vec<CityRegisterUserRPCRequest<F>>,
    pub add_withdrawals: Vec<CityAddWithdrawalRPCRequest>,
    pub token_transfers: Vec<CityTokenTransferRPCRequest>,
}

impl<F: RichField> OrchestratorRPCEventSenderSync<F> for DevMemoryCoordinatatorRPCQueue<F> {
    fn notify_rpc_claim_deposit(
        &mut self,
        event: &CityClaimDepositRPCRequest,
    ) -> anyhow::Result<()> {
        self.claim_deposits.push(event.clone());
        Ok(())
    }

    fn notify_rpc_register_user(
        &mut self,
        event: &CityRegisterUserRPCRequest<F>,
    ) -> anyhow::Result<()> {
        self.register_users.push(event.clone());
        Ok(())
    }

    fn notify_rpc_add_withdrawal(
        &mut self,
        event: &CityAddWithdrawalRPCRequest,
    ) -> anyhow::Result<()> {
        self.add_withdrawals.push(event.clone());
        Ok(())
    }

    fn notify_rpc_token_transfer(
        &mut self,
        event: &CityTokenTransferRPCRequest,
    ) -> anyhow::Result<()> {
        self.token_transfers.push(event.clone());
        Ok(())
    }
}

pub struct DevMemoryCoordinatator<
    PS: QProofStore,
    S: KVQBinaryStore,
    F: RichField + Extendable<D>,
    const D: usize,
> {
    pub proof_store: PS,
    pub binary_store: S,
    pub rpc_processor: QRPCProcessor<F, D>,
}
