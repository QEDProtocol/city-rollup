use std::{sync::Arc, time::Duration};

use city_common::cli::args::OrchestratorArgs;
use city_crypto::hash::qhashout::QHashOut;
use city_macros::{async_infinite_loop, define_table, spawn_async_infinite_loop};
use city_rollup_circuit::block_circuits::ops::{
    claim_l1_deposit::CRClaimL1DepositCircuitInput, l2_transfer::circuit::CRL2TransferCircuitInput,
    process_l1_withdrawal::CRProcessL1WithdrawalCircuitInput,
    register_user::CRUserRegistrationCircuitInput,
};
use city_rollup_common::{
    api::data::block::requested_actions::{
        CityAddWithdrawalRequest, CityClaimDepositRequest, CityRegisterUserRequest,
        CityTokenTransferRequest,
    },
    qworker::job_id::{ProvingJobCircuitType, QJobTopic, QProvingJobDataID},
};
use city_rollup_worker_dispatch::{
    implementations::redis::{
        rollup_key::{LAST_BLOCK_ID, LAST_BLOCK_TIMESTAMP, LAST_ORCHESTOR_ID, PROVING_JOB_COUNTER}, RedisStore, Q_JOB, Q_TX
    },
    traits::{proving_dispatcher::ProvingDispatcher, proving_worker::ProvingWorkerListener},
};
use city_store::{config::F, store::city::base::CityStore};
use kvq_store_redb::KVQReDBStore;
use redb::{Database, TableDefinition};
use redis::AsyncCommands;

pub const DEFAULT_BLOCK_TIME_IN_SECS: u32 = 4;

define_table! { KV, &[u8], &[u8] }

pub async fn run(args: OrchestratorArgs) -> anyhow::Result<()> {
    let redis_store = RedisStore::new(&args.redis_uri).await?;
    let redis_storec = redis_store.clone();
    let db = Arc::new(Database::create(args.db_path)?);

    spawn_async_infinite_loop!(100, {
        let redis_storec = redis_storec.clone();
        let mut conn = redis_storec.get_connection().await?;

        let last_block_id: u64 = conn.get(LAST_BLOCK_ID).await.unwrap_or(0);
        let last_block_timestamp: u32 = conn.get(LAST_BLOCK_TIMESTAMP).await.unwrap_or(0);
        let (timestamp, _): (u32, u32) = redis::cmd("time").query_async(&mut *conn).await?;

        let mut pipeline = redis::pipe();
        pipeline.atomic();

        if last_block_timestamp == 0 {
            pipeline
                .set(LAST_BLOCK_ID, 0)
                .ignore()
                .set(LAST_BLOCK_TIMESTAMP, timestamp)
                .ignore()
                .query_async(&mut *conn)
                .await?;
        } else if timestamp - last_block_timestamp >= DEFAULT_BLOCK_TIME_IN_SECS {
            let nblocks = ((timestamp - last_block_timestamp) / DEFAULT_BLOCK_TIME_IN_SECS) as u64;
            let block_id: u64 = last_block_id + nblocks;
            pipeline
                .set(LAST_BLOCK_ID, block_id)
                .ignore()
                .set(LAST_BLOCK_TIMESTAMP, timestamp)
                .ignore()
                .query_async(&mut *conn)
                .await?;
        }
    });

    async_infinite_loop!(2000, {
        let db = db.clone();
        let mut redis_store = redis_store.clone();

        let wxn = db.begin_write()?;

        let last_orchestrator_block_id: u64 = redis_store
            .get_connection()
            .await?
            .get(LAST_ORCHESTOR_ID)
            .await
            .unwrap_or(0);
        let last_block_id: u64 = redis_store.get_connection().await?.get(LAST_BLOCK_ID).await.unwrap_or(0);

        // keep us to be 2 blocks before the latest block to ensure the queue is filled with
        // all block transactions
        if last_orchestrator_block_id + 2 >= last_block_id {
            return Ok(());
        }

        let mut token_transfers: Vec<(QProvingJobDataID, CRL2TransferCircuitInput<F>)> = vec![];
        let mut register_users: Vec<(QProvingJobDataID, CRUserRegistrationCircuitInput<F>)> =
            vec![];
        let mut claim_l1_deposits: Vec<(QProvingJobDataID, CRClaimL1DepositCircuitInput<F>)> =
            vec![];
        let mut withdrawals: Vec<(QProvingJobDataID, CRProcessL1WithdrawalCircuitInput<F>)> =
            vec![];

        {
            let mut store = KVQReDBStore::new(wxn.open_table(KV)?);
            while let Ok(message) = redis_store
                .get_next_message::<Q_TX>(last_orchestrator_block_id)
                .await
            {
                let task_index: u32 = redis_store
                    .get_connection()
                    .await?
                    .incr(PROVING_JOB_COUNTER, 1)
                    .await
                    .unwrap_or(1)
                    - 1;

                if let Ok(add_withdrawal) =
                    serde_json::from_slice::<CityAddWithdrawalRequest>(&message)
                {
                    let delta_merkle_proof = CityStore::add_withdrawal_to_tree_from_request(
                        &mut store,
                        last_orchestrator_block_id,
                        &add_withdrawal,
                    )?;
                    withdrawals.push((
                        QProvingJobDataID::new_proof_job_id(
                            last_orchestrator_block_id,
                            ProvingJobCircuitType::AddL1Withdrawal,
                            add_withdrawal.signature_proof_id.group_id,
                            add_withdrawal.signature_proof_id.sub_group_id,
                            task_index,
                        ),
                        CRProcessL1WithdrawalCircuitInput {
                            withdrawal_tree_delta_merkle_proof: delta_merkle_proof,
                            allowed_circuit_hashes_root: QHashOut::from_values(1, 2, 3, 4),
                        },
                    ))
                } else if let Ok(claim_l1_deposit) =
                    serde_json::from_slice::<CityClaimDepositRequest>(&message)
                {
                    let user_tree_delta_merkle_proof = CityStore::increment_user_balance(
                        &mut store,
                        last_orchestrator_block_id,
                        claim_l1_deposit.user_id,
                        claim_l1_deposit.value,
                        Some(claim_l1_deposit.nonce),
                    )?;
                    let delta_merkle_proof = CityStore::mark_deposit_as_claimed(
                        &mut store,
                        last_orchestrator_block_id,
                        claim_l1_deposit.deposit_id.into(),
                    )?;
                    claim_l1_deposits.push((
                        QProvingJobDataID::new_proof_job_id(
                            last_orchestrator_block_id,
                            ProvingJobCircuitType::ClaimL1Deposit,
                            claim_l1_deposit.signature_proof_id.group_id,
                            claim_l1_deposit.signature_proof_id.sub_group_id,
                            task_index,
                        ),
                        CRClaimL1DepositCircuitInput {
                            deposit: todo!(),
                            user_tree_delta_merkle_proof: user_tree_delta_merkle_proof,
                            deposit_tree_delta_merkle_proof: delta_merkle_proof,
                            allowed_circuit_hashes_root: todo!(),
                            signature_proof_id: claim_l1_deposit.signature_proof_id,
                        },
                    ));
                } else if let Ok(register_user) =
                    serde_json::from_slice::<CityRegisterUserRequest<F>>(&message)
                {
                    let delta_merkle_proof = CityStore::register_user(
                        &mut store,
                        last_orchestrator_block_id,
                        register_user.user_id,
                        register_user.public_key,
                    )?;
                    register_users.push((
                        QProvingJobDataID::new_proof_job_id(
                            last_orchestrator_block_id,
                            ProvingJobCircuitType::RegisterUser,
                            1,
                            register_user.rpc_node_id as u32,
                            task_index,
                        ),
                        CRUserRegistrationCircuitInput {
                            user_tree_delta_merkle_proof: delta_merkle_proof,
                            allowed_circuit_hashes_root: todo!(),
                        },
                    ))
                } else if let Ok(token_transfer) =
                    serde_json::from_slice::<CityTokenTransferRequest>(&message)
                {
                    let sender_user_tree_delta_merkle_proof = CityStore::decrement_user_balance(
                        &mut store,
                        last_orchestrator_block_id,
                        token_transfer.user_id,
                        token_transfer.value,
                        Some(token_transfer.nonce),
                    )?;
                    let receiver_user_tree_delta_merkle_proof = CityStore::increment_user_balance(
                        &mut store,
                        last_orchestrator_block_id,
                        token_transfer.to,
                        token_transfer.value,
                        None,
                    )?;
                    token_transfers.push((
                        QProvingJobDataID::new_proof_job_id(
                            last_orchestrator_block_id,
                            ProvingJobCircuitType::TransferTokensL2,
                            token_transfer.signature_proof_id.group_id,
                            token_transfer.signature_proof_id.sub_group_id,
                            task_index,
                        ),
                        CRL2TransferCircuitInput {
                            sender_user_tree_delta_merkle_proof,
                            receiver_user_tree_delta_merkle_proof,
                            allowed_circuit_hashes_root: todo!(),
                            signature_proof_id: token_transfer.signature_proof_id,
                        },
                    ))
                }
            }
        }

        wxn.commit()?;

        for token_transfer in token_transfers {
            redis_store.dispatch::<Q_JOB>(
                QJobTopic::GenerateStandardProof as u64,
                &serde_json::to_vec(&token_transfer.1)?,
            ).await?;
        }

        for register_user in register_users {
            redis_store.dispatch::<Q_JOB>(
                QJobTopic::GenerateStandardProof as u64,
                &serde_json::to_vec(&register_user.1)?,
            ).await?;
        }

        for claim_l1_deposit in claim_l1_deposits {
            redis_store.dispatch::<Q_JOB>(
                QJobTopic::GenerateStandardProof as u64,
                &serde_json::to_vec(&claim_l1_deposit.1)?,
            ).await?;
        }

        for withdrawal in withdrawals {
            redis_store.dispatch::<Q_JOB>(
                QJobTopic::GenerateStandardProof as u64,
                &serde_json::to_vec(&withdrawal.1)?,
            ).await?;
        }

        redis_store
            .get_connection()
            .await?
            .incr(LAST_ORCHESTOR_ID, 1)
            .await?;
    });
}
