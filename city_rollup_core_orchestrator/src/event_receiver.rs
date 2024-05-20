use std::time::Duration;

use city_redis_store::RedisStore;
use city_rollup_common::actors::rpc_processor::QRPCProcessor;
use city_rollup_common::actors::traits::OrchestratorEventReceiverSync;
use city_rollup_common::api::data::block::requested_actions::*;
use city_rollup_worker_dispatch::implementations::redis::{
    QueueCmd, RedisDispatcher, Q_ADD_WITHDRAWAL, Q_CLAIM_DEPOSIT, Q_CMD, Q_REGISTER_USER,
    Q_TOKEN_TRANSFER,
};
use city_rollup_worker_dispatch::traits::proving_worker::ProvingWorkerListener;
use plonky2::hash::hash_types::RichField;

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
}

impl<F: RichField> OrchestratorEventReceiverSync<F> for CityEventReceiver<F> {
    fn flush_claim_deposits(&mut self) -> anyhow::Result<Vec<CityClaimDepositRequest>> {
        let reqs = self
            .dispatcher
            .pop_all(Q_CLAIM_DEPOSIT)?
            .into_iter()
            .map(|v| Ok(serde_json::from_slice(&v)?))
            .collect::<anyhow::Result<Vec<_>>>()?;

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
        let reqs = self
            .dispatcher
            .pop_all(Q_REGISTER_USER)?
            .into_iter()
            .map(|v| Ok(serde_json::from_slice(&v)?))
            .collect::<anyhow::Result<Vec<_>>>()?;

        let mut res = Vec::with_capacity(reqs.len());
        for req in reqs {
            res.push(self.rpc_processor.injest_rpc_register_user(0, &req)?);
        }

        Ok(res)
    }

    fn flush_add_withdrawals(&mut self) -> anyhow::Result<Vec<CityAddWithdrawalRequest>> {
        let reqs = self
            .dispatcher
            .pop_all(Q_ADD_WITHDRAWAL)?
            .into_iter()
            .map(|v| Ok(serde_json::from_slice(&v)?))
            .collect::<anyhow::Result<Vec<_>>>()?;

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
        let reqs = self
            .dispatcher
            .pop_all(Q_TOKEN_TRANSFER)?
            .into_iter()
            .map(|v| Ok(serde_json::from_slice(&v)?))
            .collect::<anyhow::Result<Vec<_>>>()?;

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
