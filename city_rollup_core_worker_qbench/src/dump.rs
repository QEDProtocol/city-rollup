use city_common::cli::args::L2DumpProofStoreArgs;
use city_redis_store::RedisStore;
use city_rollup_common::qworker::{
    dump::dump_job_dependencies_from_store,
    job_id::{ProvingJobCircuitType, QProvingJobDataID},
    memory_proof_store::SimpleProofStoreMemory,
    proof_store::{QProofStore, QProofStoreReaderSync},
};
use city_rollup_core_orchestrator::debug::scenario::{
    actors::job_planner::plan_jobs,
    block_planner::transition::{CityOpJobConfig, CityOpJobIds},
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct DumpProofStoreConfig {
    pub checkpoint_id: u64,
    pub rpc_node_id: u32,
    pub job_config: CityOpJobConfig,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct BlockProofStoreDump {
  pub config: DumpProofStoreConfig,
  pub store: SimpleProofStoreMemory,
}
fn mirror_proof_store<PSource: QProofStoreReaderSync, PDestination: QProofStore>(keys: &[QProvingJobDataID], source: &PSource, destination: &mut PDestination) -> anyhow::Result<()> {
    for key in keys {
        let data = source.get_bytes_by_id(*key)?;
        destination.set_bytes_by_id(*key, &data)?;
    }
    Ok(())
}
// this only works when running a single rpc node with a the node id "rpc_node_id", which is ok because this is for debugging only
fn get_rpc_proof_dependencies(
    config: &DumpProofStoreConfig,
) -> anyhow::Result<Vec<QProvingJobDataID>> {
    let token_transfer_signature_proof_ids = (0..config.job_config.token_transfer_count).map(|i| {
        QProvingJobDataID::transfer_signature_proof(config.rpc_node_id, config.checkpoint_id, i as u32)
    });

    let claim_deposit_signature_proof_ids = (0..config.job_config.token_transfer_count).map(|i| {
        QProvingJobDataID::claim_deposit_l1_signature_proof(
            config.rpc_node_id,
            config.checkpoint_id,
            i as u32,
        )
    });

    let withdrawal_signature_proof_ids = (0..config.job_config.token_transfer_count).map(|i| {
        QProvingJobDataID::withdrawal_signature_proof(config.rpc_node_id, config.checkpoint_id, i as u32)
    });

    Ok(token_transfer_signature_proof_ids
        .chain(claim_deposit_signature_proof_ids)
        .chain(withdrawal_signature_proof_ids)
        .collect())
}
fn dump_proof_store<PS: QProofStoreReaderSync>(
    config: &DumpProofStoreConfig,
    real_store: &PS,
) -> anyhow::Result<BlockProofStoreDump> {
    let mut mirror_store = SimpleProofStoreMemory::new();
    let block_op_job_ids =
        CityOpJobIds::dummy_from_config(config.checkpoint_id, &config.job_config);
    let num_input_witnesses = config.job_config.add_deposit_count + 1;
    let leaves = plan_jobs(
        &mut mirror_store,
        &block_op_job_ids,
        num_input_witnesses,
        config.checkpoint_id,
    )?;

    /*
    println!(
        "leaf_jobs: {}",
        serde_json::to_string(
            &leaves
                .iter()
                .map(|x| QProvingJobDataIDSerializedWrapped(x.to_fixed_bytes()))
                .collect::<Vec<_>>()
        )?
    );
    */


    let dependency_map = dump_job_dependencies_from_store(real_store, &leaves)?;

    let dep_tree = dependency_map.get_dependency_tree_for_block(config.checkpoint_id);
    let rpc_signature_proof_dependencies = get_rpc_proof_dependencies(config)?;
    mirror_proof_store(&rpc_signature_proof_dependencies, real_store, &mut mirror_store)?;


    let proof_witnesses = dep_tree.get_all_dependencies();
    mirror_proof_store(&proof_witnesses, real_store, &mut mirror_store)?;


    Ok(BlockProofStoreDump{
      store: mirror_store,
      config: config.clone(),
    })
}

pub fn get_leaf_count_or_dummy<PS: QProofStoreReaderSync>(store: &PS, circuit_type: ProvingJobCircuitType, dummy_type: ProvingJobCircuitType, checkpoint_id: u64) -> anyhow::Result<usize> {
    let counter_job_id = QProvingJobDataID::core_op_witness(circuit_type, checkpoint_id, 0).get_sub_group_counter_goal_id();

    let dummy_job_id = QProvingJobDataID::new_proof_job_id(
        checkpoint_id,
        dummy_type,
        0xDD,
        0,
        0,
    );

    let counter_bytes_result = store.get_bytes_by_id(counter_job_id).unwrap_or(vec![]);
    if counter_bytes_result.len() == 4 {
        let counter = u32::from_le_bytes(counter_bytes_result.try_into().unwrap());
        Ok(counter as usize)
    }else{
        let dummy_bytes_result = store.get_bytes_by_id(dummy_job_id);
        if dummy_bytes_result.is_ok() && dummy_bytes_result.unwrap().len() != 0 {
            Ok(0)
        }else{
          anyhow::bail!("no counter or dummy job found for circuit type {:?} and checkpoint_id {}", circuit_type, checkpoint_id)
        }
    }
}
pub fn get_proof_store_config<PS: QProofStoreReaderSync>(store: &PS, checkpoint_id: u64, rpc_node_id: u32) -> anyhow::Result<DumpProofStoreConfig> {
    let register_user_count = get_leaf_count_or_dummy(store, ProvingJobCircuitType::RegisterUser, ProvingJobCircuitType::DummyRegisterUserAggregate, checkpoint_id)?;
    let add_deposit_count = get_leaf_count_or_dummy(store, ProvingJobCircuitType::AddL1Deposit, ProvingJobCircuitType::DummyAddL1DepositAggregate, checkpoint_id)?;
    let token_transfer_count = get_leaf_count_or_dummy(store, ProvingJobCircuitType::TransferTokensL2, ProvingJobCircuitType::DummyTransferTokensL2Aggregate, checkpoint_id)?;
    let add_withdrawal_count = get_leaf_count_or_dummy(store, ProvingJobCircuitType::AddL1Withdrawal, ProvingJobCircuitType::DummyAddL1WithdrawalAggregate, checkpoint_id)?;
    let process_withdrawal_count = get_leaf_count_or_dummy(store, ProvingJobCircuitType::ProcessL1Withdrawal, ProvingJobCircuitType::DummyProcessL1WithdrawalAggregate, checkpoint_id)?;
    let claim_deposit_count = get_leaf_count_or_dummy(store, ProvingJobCircuitType::ClaimL1Deposit, ProvingJobCircuitType::DummyClaimL1DepositAggregate, checkpoint_id)?;
    let job_config = CityOpJobConfig {
        register_user_count,
        claim_deposit_count,
        token_transfer_count,
        add_withdrawal_count,
        process_withdrawal_count,
        add_deposit_count,
    };
    


    Ok(DumpProofStoreConfig {
        checkpoint_id,
        rpc_node_id,
        job_config,
    })
}
pub fn run_dump_block_proof_store(args: &L2DumpProofStoreArgs) -> anyhow::Result<()>{
  let root = std::env::current_dir()?;
  let output_path = root.join(args.output.clone()).display().to_string();
  let real_store = RedisStore::new(&args.redis_uri)?;
  let config = get_proof_store_config(&real_store, args.checkpoint_id, 0)?;
  //println!("got config: {}", serde_json::to_string_pretty(&config)?);
  let result = dump_proof_store(&config, &real_store)?;
  std::fs::write(output_path, &bincode::serialize(&result)?)?;
  Ok(())
}
