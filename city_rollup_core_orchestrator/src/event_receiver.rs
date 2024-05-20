use std::time::Duration;

use city_redis_store::RedisStore;
use city_rollup_common::actors::rpc_processor::{
    CityScenarioRequestedActionsFromRPC, QRPCProcessor,
};
use city_rollup_common::actors::traits::{
    OrchestratorEventReceiverSync, OrchestratorRPCEventSenderSync,
};
use city_rollup_common::api::data::block::requested_actions::*;
use city_rollup_common::api::data::block::rpc_request::{
    CityAddWithdrawalRPCRequest, CityClaimDepositRPCRequest, CityRegisterUserRPCRequest,
    CityTokenTransferRPCRequest,
};
use city_rollup_common::qworker::proof_store::QProofStore;
use city_rollup_worker_dispatch::implementations::redis::{
    QueueCmd, RedisDispatcher, Q_ADD_WITHDRAWAL, Q_CLAIM_DEPOSIT, Q_CMD, Q_REGISTER_USER,
    Q_RPC_ADD_WITHDRAWAL, Q_RPC_CLAIM_DEPOSIT, Q_RPC_REGISTER_USER, Q_RPC_TOKEN_TRANSFER,
    Q_TOKEN_TRANSFER,
};
use city_rollup_worker_dispatch::traits::proving_dispatcher::ProvingDispatcher;
use city_rollup_worker_dispatch::traits::proving_worker::ProvingWorkerListener;
use plonky2::hash::hash_types::RichField;
use serde::de::DeserializeOwned;
use serde::Deserialize;

pub struct CityEventReceiver<F: RichField> {
    dispatcher: RedisDispatcher,
    rpc_processor: QRPCProcessor<F>,
    proof_store: RedisStore,
}

impl<F: RichField> CityEventReceiver<F> {
    pub fn new(
        dispatcher: RedisDispatcher,
        rpc_processor: QRPCProcessor<F>,
        proof_store: RedisStore,
    ) -> Self {
        Self {
            dispatcher,
            rpc_processor,
            proof_store,
        }
    }

    pub fn flush_rpc_requests<T: DeserializeOwned>(
        &mut self,
        topic: &str,
    ) -> anyhow::Result<Vec<T>> {
        Ok(self
            .dispatcher
            .pop_all(topic)?
            .into_iter()
            .map(|v| Ok(serde_json::from_slice(&v)?))
            .collect::<anyhow::Result<Vec<_>>>()?)
    }

    pub fn get_requested_actions_from_rpc<PS: QProofStore>(
        &mut self,
        proof_store: &mut PS,
        checkpoint_id: u64,
    ) -> anyhow::Result<CityScenarioRequestedActionsFromRPC<F>> {
        let mut rpc_processor = QRPCProcessor::new(checkpoint_id);
        rpc_processor.process_register_users(
            0,
            &self.flush_rpc_requests::<CityRegisterUserRPCRequest<F>>(Q_RPC_REGISTER_USER)?,
        )?;
        rpc_processor.process_deposits(
            proof_store,
            0,
            &self.flush_rpc_requests::<CityClaimDepositRPCRequest>(Q_RPC_CLAIM_DEPOSIT)?,
        )?;
        rpc_processor.process_transfers(
            proof_store,
            0,
            &self.flush_rpc_requests::<CityTokenTransferRPCRequest>(Q_RPC_TOKEN_TRANSFER)?,
        )?;
        rpc_processor.process_withdrawals(
            proof_store,
            0,
            &self.flush_rpc_requests::<CityAddWithdrawalRPCRequest>(Q_RPC_ADD_WITHDRAWAL)?,
        )?;
        Ok(rpc_processor.output)
    }
}

impl<F: RichField> OrchestratorEventReceiverSync<F> for CityEventReceiver<F> {
    fn flush_claim_deposits(&mut self) -> anyhow::Result<Vec<CityClaimDepositRequest>> {
        let reqs = self.flush_rpc_requests::<CityClaimDepositRPCRequest>(Q_RPC_CLAIM_DEPOSIT)?;

        let mut res = Vec::with_capacity(reqs.len());
        for req in reqs {
            res.push(self.rpc_processor.injest_rpc_claim_deposit(
                &mut self.proof_store,
                0,
                &req,
            )?);
        }

        Ok(res)
    }

    fn flush_register_users(&mut self) -> anyhow::Result<Vec<CityRegisterUserRequest<F>>> {
        let reqs = self.flush_rpc_requests::<CityRegisterUserRPCRequest<F>>(Q_RPC_REGISTER_USER)?;

        let mut res = Vec::with_capacity(reqs.len());
        for req in reqs {
            res.push(self.rpc_processor.injest_rpc_register_user(0, &req)?);
        }

        Ok(res)
    }

    fn flush_add_withdrawals(&mut self) -> anyhow::Result<Vec<CityAddWithdrawalRequest>> {
        let reqs = self.flush_rpc_requests::<CityAddWithdrawalRPCRequest>(Q_RPC_ADD_WITHDRAWAL)?;

        let mut res = Vec::with_capacity(reqs.len());
        for req in reqs {
            res.push(self.rpc_processor.injest_rpc_add_withdrawal(
                &mut self.proof_store,
                0,
                &req,
            )?);
        }

        Ok(res)
    }

    fn flush_token_transfers(&mut self) -> anyhow::Result<Vec<CityTokenTransferRequest>> {
        let reqs = self.flush_rpc_requests::<CityTokenTransferRPCRequest>(Q_RPC_TOKEN_TRANSFER)?;

        let mut res = Vec::with_capacity(reqs.len());
        for req in reqs {
            res.push(self.rpc_processor.injest_rpc_token_transfer(
                &mut self.proof_store,
                0,
                &req,
            )?);
        }

        Ok(res)
    }

    fn wait_for_produce_block(&mut self) -> anyhow::Result<bool> {
        loop {
            match self
                .dispatcher
                .pop_one(Q_CMD)?
                .map(|v| serde_json::from_slice::<QueueCmd>(&v))
            {
                Some(Ok(QueueCmd::ProduceBlock)) => return Ok::<_, anyhow::Error>(true),
                Some(Err(_)) | None => {
                    std::thread::sleep(Duration::from_millis(500));
                    continue;
                }
            }
        }
    }
}

// Dev only
impl<F: RichField> OrchestratorRPCEventSenderSync<F> for CityEventReceiver<F> {
    fn notify_rpc_claim_deposit(
        &mut self,
        event: &CityClaimDepositRPCRequest,
    ) -> anyhow::Result<()> {
        self.dispatcher
            .dispatch(Q_RPC_CLAIM_DEPOSIT, event.clone())?;
        Ok(())
    }

    fn notify_rpc_register_user(
        &mut self,
        event: &CityRegisterUserRPCRequest<F>,
    ) -> anyhow::Result<()> {
        self.dispatcher
            .dispatch(Q_RPC_REGISTER_USER, event.clone())?;
        Ok(())
    }

    fn notify_rpc_add_withdrawal(
        &mut self,
        event: &CityAddWithdrawalRPCRequest,
    ) -> anyhow::Result<()> {
        self.dispatcher
            .dispatch(Q_RPC_ADD_WITHDRAWAL, event.clone())?;
        Ok(())
    }

    fn notify_rpc_token_transfer(
        &mut self,
        event: &CityTokenTransferRPCRequest,
    ) -> anyhow::Result<()> {
        self.dispatcher
            .dispatch(Q_RPC_TOKEN_TRANSFER, event.clone())?;
        Ok(())
    }

    fn notify_rpc_produce_block(&mut self) -> anyhow::Result<()> {
        self.dispatcher.dispatch(Q_CMD, QueueCmd::ProduceBlock)?;
        Ok(())
    }
}
