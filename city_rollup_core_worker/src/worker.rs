use std::time::Duration;

use city_common::cli::args::L2WorkerArgs;
use city_common::logging::trace_timer::TraceTimer;
use city_common_circuit::circuits::traits::qstandard::QStandardCircuitProvableWithProofStoreSync;
use city_common_circuit::circuits::traits::qstandard::QStandardCircuitWithDefaultMinified;
use city_macros::async_infinite_loop;
use city_rollup_circuit::block_circuits::ops::register_user::WCRUserRegistrationCircuit;
use city_rollup_common::introspection::rollup::constants::get_network_magic_for_str;
use city_rollup_common::qworker::job_id::QJobTopic;
use city_rollup_common::qworker::job_id::QProvingJobDataID;
use city_rollup_common::qworker::job_witnesses::op::CRUserRegistrationCircuitInput;
use city_rollup_common::qworker::proof_store::QProofStoreWriterSync;
use city_rollup_common::qworker::redis_proof_store::SyncRedisProofStore;
use city_rollup_worker_dispatch::implementations::redis::RedisDispatcher;
use city_rollup_worker_dispatch::implementations::redis::Q_JOB;
use city_rollup_worker_dispatch::traits::proving_worker::ProvingWorkerListener;
use city_store::config::C;
use city_store::config::D;
use city_store::config::F;
use tokio::task::spawn_blocking;

// CRL2TransferCircuitInput
// CRUserRegistrationCircuitInput
// CRClaimL1DepositCircuitInput
// CRProcessL1WithdrawalCircuitInput
pub async fn run(args: L2WorkerArgs) -> anyhow::Result<()> {
    let redis_dispatcher = RedisDispatcher::new(&args.redis_uri).await?;
    let proof_store = SyncRedisProofStore::new(&args.redis_uri)?;
    let network_magic = get_network_magic_for_str(args.network.to_string())?;

    let mut trace_timer = TraceTimer::new("CRWorkerToolboxCoreCircuits");
    trace_timer.lap("start => build core toolbox circuits");
    let op_register_user =
        WCRUserRegistrationCircuit::<C, D>::new_default_with_minifiers(network_magic, 1);

    trace_timer.lap("built op_register_user");
    async_infinite_loop!(1000, {
        let proof_store = proof_store.clone();
        let mut redis_dispatcher = redis_dispatcher.clone();
        while let Some((id, message)) = redis_dispatcher
            .receive_one::<Q_JOB>(QJobTopic::GenerateStandardProof as u32)
            .await?
        {
            let mut proof_store = proof_store.clone();
            if let Ok((job_id, register_user)) = serde_json::from_slice::<(
                QProvingJobDataID,
                CRUserRegistrationCircuitInput<F>,
            )>(&message)
            {
                let op_register_user = op_register_user.clone();
                spawn_blocking(move || {
                    let proof = op_register_user
                        .prove_with_proof_store_sync(&proof_store, &register_user)?;
                    println!("register_user proof generated");
                    proof_store.set_proof_by_id(job_id, &proof)?;
                    println!("register_user proof stored");
                    Ok::<_, anyhow::Error>(())
                })
                .await??;
            }
        }
    });
}
