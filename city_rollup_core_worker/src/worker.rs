use std::sync::Arc;
use std::time::Duration;

use city_common::cli::args::L2WorkerArgs;
use city_common::logging::trace_timer::TraceTimer;
use city_common_circuit::circuits::traits::qstandard::QStandardCircuitProvableWithProofStoreSync;
use city_macros::async_infinite_loop;
use city_redis_store::RedisStore;
use city_rollup_circuit::worker::toolbox::circuits::CRWorkerToolboxCoreCircuits;
use city_rollup_common::introspection::rollup::constants::get_network_magic_for_str;
use city_rollup_common::qworker::job_id::ProvingJobCircuitType;
use city_rollup_common::qworker::job_id::ProvingJobDataType;
use city_rollup_common::qworker::job_id::QJobTopic;
use city_rollup_common::qworker::job_id::QProvingJobDataID;
use city_rollup_common::qworker::proof_store::QProofStoreReaderSync;
use city_rollup_common::qworker::proof_store::QProofStoreWriterSync;
use city_rollup_worker_dispatch::implementations::redis::RedisDispatcher;
use city_rollup_worker_dispatch::implementations::redis::Q_JOB;
use city_rollup_worker_dispatch::traits::proving_worker::ProvingWorkerListener;
use city_store::config::C;
use city_store::config::D;
use tokio::task::spawn_blocking;

pub const PROVING_INTERVAL: u64 = 60000;

pub async fn run(args: L2WorkerArgs) -> anyhow::Result<()> {
    let redis_dispatcher = RedisDispatcher::new(&args.redis_uri).await?;
    let proof_store = RedisStore::new(&args.redis_uri)?;
    let network_magic = get_network_magic_for_str(args.network.to_string())?;

    let mut trace_timer = TraceTimer::new("CRWorkerToolboxCoreCircuits");
    trace_timer.lap("start => build core toolbox circuits");
    let toolbox = Arc::new(CRWorkerToolboxCoreCircuits::<C, D>::new(network_magic));

    async_infinite_loop!(PROVING_INTERVAL, {
        let proof_store = proof_store.clone();
        let mut redis_dispatcher = redis_dispatcher.clone();
        while let Some((id, message)) = redis_dispatcher
            .receive_one(Q_JOB)
            .await?
        {
            // let mut proof_store = proof_store.clone();
            // // Single proof
            // if let Ok(job_id) = serde_json::from_slice::<QProvingJobDataID>(&message) {
            //     if job_id.data_type == ProvingJobDataType::InputWitness {
            //         let witness = proof_store.get_bytes_by_id(job_id)?;
            //         if job_id.circuit_type == ProvingJobCircuitType::RegisterUser {
            //             let toolboxc = toolbox.clone();
            //             spawn_blocking(move || {
            //                 let proof = toolboxc.op_register_user.prove_with_proof_store_sync(
            //                     &proof_store,
            //                     &bincode::deserialize(&witness)?,
            //                 )?;
            //                 println!("register_user proof generated");
            //                 proof_store.set_proof_by_id(job_id, &proof)?;
            //                 println!("register_user proof stored");
            //                 Ok::<_, anyhow::Error>(())
            //             })
            //             .await??;
            //             redis_dispatcher
            //                 .delete_message::<Q_JOB>(QJobTopic::GenerateStandardProof as u32, id)
            //                 .await?;
            //         } else if job_id.circuit_type == ProvingJobCircuitType::ClaimL1Deposit {
            //             let toolboxc = toolbox.clone();
            //             spawn_blocking(move || {
            //                 let proof = toolboxc.op_claim_l1_deposit.prove_with_proof_store_sync(
            //                     &proof_store,
            //                     &bincode::deserialize(&witness)?,
            //                 )?;
            //                 println!("claim l1 deposit proof generated");
            //                 proof_store.set_proof_by_id(job_id, &proof)?;
            //                 println!("claim l1 deposit proof stored");
            //                 Ok::<_, anyhow::Error>(())
            //             })
            //             .await??;
            //             redis_dispatcher
            //                 .delete_message::<Q_JOB>(QJobTopic::GenerateStandardProof as u32, id)
            //                 .await?;
            //         } else if job_id.circuit_type == ProvingJobCircuitType::TransferTokensL2 {
            //             let toolboxc = toolbox.clone();
            //             spawn_blocking(move || {
            //                 let proof = toolboxc.op_l2_transfer.prove_with_proof_store_sync(
            //                     &proof_store,
            //                     &bincode::deserialize(&witness)?,
            //                 )?;
            //                 println!("claim l1 deposit proof generated");
            //                 proof_store.set_proof_by_id(job_id, &proof)?;
            //                 println!("claim l1 deposit proof stored");
            //                 Ok::<_, anyhow::Error>(())
            //             })
            //             .await??;
            //             redis_dispatcher
            //                 .delete_message::<Q_JOB>(QJobTopic::GenerateStandardProof as u32, id)
            //                 .await?;
            //         } else if job_id.circuit_type == ProvingJobCircuitType::AddL1Withdrawal {
            //             let toolboxc = toolbox.clone();
            //             spawn_blocking(move || {
            //                 let proof = toolboxc.op_add_l1_withdrawal.prove_with_proof_store_sync(
            //                     &proof_store,
            //                     &bincode::deserialize(&witness)?,
            //                 )?;
            //                 println!("add l1 withdrawal proof generated");
            //                 proof_store.set_proof_by_id(job_id, &proof)?;
            //                 println!("add l1 withdrawal proof stored");
            //                 Ok::<_, anyhow::Error>(())
            //             })
            //             .await??;
            //             redis_dispatcher
            //                 .delete_message::<Q_JOB>(QJobTopic::GenerateStandardProof as u32, id)
            //                 .await?;
            //         } else if job_id.circuit_type == ProvingJobCircuitType::ProcessL1Withdrawal {
            //             let toolboxc = toolbox.clone();
            //             spawn_blocking(move || {
            //                 let proof = toolboxc
            //                     .op_process_l1_withdrawal
            //                     .prove_with_proof_store_sync(
            //                         &proof_store,
            //                         &bincode::deserialize(&witness)?,
            //                     )?;
            //                 println!("process l1 withdrawal proof generated");
            //                 proof_store.set_proof_by_id(job_id, &proof)?;
            //                 println!("process l1 withdrawal proof stored");
            //                 Ok::<_, anyhow::Error>(())
            //             })
            //             .await??;
            //             redis_dispatcher
            //                 .delete_message::<Q_JOB>(QJobTopic::GenerateStandardProof as u32, id)
            //                 .await?;
            //         } else if job_id.circuit_type == ProvingJobCircuitType::AddL1Deposit {
            //             let toolboxc = toolbox.clone();
            //             spawn_blocking(move || {
            //                 let proof = toolboxc.op_add_l1_deposit.prove_with_proof_store_sync(
            //                     &proof_store,
            //                     &bincode::deserialize(&witness)?,
            //                 )?;
            //                 println!("process l1 withdrawal proof generated");
            //                 proof_store.set_proof_by_id(job_id, &proof)?;
            //                 println!("process l1 withdrawal proof stored");
            //                 Ok::<_, anyhow::Error>(())
            //             })
            //             .await??;
            //             redis_dispatcher
            //                 .delete_message::<Q_JOB>(QJobTopic::GenerateStandardProof as u32, id)
            //                 .await?;
            //         }
            //     }
            // }

        }
    });
}
