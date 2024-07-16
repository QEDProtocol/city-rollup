use std::path::PathBuf;

use city_redis_store::RedisStore;
use city_rollup_common::qworker::{
    dump::dump_job_dependencies_from_store,
    job_id::{QProvingJobDataID, QProvingJobDataIDSerializedWrapped},
    memory_proof_store::SimpleProofStoreMemory,
    proof_store::{QProofStore, QProofStoreReaderSync},
};
use city_rollup_core_orchestrator::debug::scenario::{
    actors::job_planner::plan_jobs,
    block_planner::transition::{CityOpJobConfig, CityOpJobIds},
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
struct DumpProofStoreConfig {
    pub checkpoint_id: u64,
    pub rpc_node_id: u32,
    pub job_config: CityOpJobConfig,
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
) -> anyhow::Result<SimpleProofStoreMemory> {
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
    println!(
        "leaf_jobs: {}",
        serde_json::to_string(
            &leaves
                .iter()
                .map(|x| QProvingJobDataIDSerializedWrapped(x.to_fixed_bytes()))
                .collect::<Vec<_>>()
        )?
    );


    let dependency_map = dump_job_dependencies_from_store(real_store, &leaves)?;

    let dep_tree = dependency_map.get_dependency_tree_for_block(config.checkpoint_id);
    let rpc_signature_proof_dependencies = get_rpc_proof_dependencies(config)?;
    println!("mirroring signature proofs");
    mirror_proof_store(&rpc_signature_proof_dependencies, real_store, &mut mirror_store)?;


    let proof_witnesses = dep_tree.get_all_dependencies();
    println!("mirroring proof witnesses");
    mirror_proof_store(&proof_witnesses, real_store, &mut mirror_store)?;


    Ok(mirror_store)
}
fn main() {
  let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
  let path = format!("{}/examples/dump_proof_store_block_config.json", root.display());
  let output_path = format!("{}/examples/dump_proof_init.bin", root.display());
  let file_data = std::fs::read(path).unwrap();
  let config: DumpProofStoreConfig = serde_json::from_slice(&file_data).unwrap();
  let redis_uri = "redis://localhost:6379/0";

  let real_store = RedisStore::new(redis_uri).unwrap();
  let result = dump_proof_store(&config, &real_store).unwrap();

  std::fs::write(output_path, &result.to_serialized_bytes().unwrap()).unwrap();
}
