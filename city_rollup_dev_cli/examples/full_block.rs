use std::{fs, path::PathBuf};

use city_common::logging::debug_timer::DebugTimer;
use city_crypto::hash::{
    base_types::{felt252::felt252_hashout_to_hash256_le, hash256::Hash256},
    qhashout::QHashOut,
};
use city_rollup_circuit::worker::{
    prover::QWorkerStandardProver, toolbox::root::CRWorkerToolboxRootCircuits,
};
use city_rollup_common::{
    actors::{requested_actions::CityScenarioRequestedActions, rpc_processor::QRPCProcessor},
    api::data::{block::rpc_request::CityRegisterUserRPCRequest, store::CityL2BlockState},
    config::sighash_wrapper_config::SIGHASH_WHITELIST_TREE_ROOT,
    introspection::rollup::{
        constants::NETWORK_MAGIC_DOGE_REGTEST, introspection::BlockSpendIntrospectionHint,
    },
    qworker::{memory_proof_store::SimpleProofStoreMemory, proof_store::QProofStoreReaderSync},
};
use city_rollup_core_orchestrator::debug::scenario::{
    block_planner::planner::CityOrchestratorBlockPlanner, sighash::finalizer::SigHashFinalizer,
    wallet::DebugScenarioWallet,
};
use city_store::store::{city::base::CityStore, sighash::SigHashMerkleTree};
use kvq::memory::simple::KVQSimpleMemoryBackingStore;
use plonky2::{
    field::goldilocks_field::GoldilocksField, hash::poseidon::PoseidonHash,
    plonk::config::PoseidonGoldilocksConfig,
};

fn prove_block_demo(hints: &[BlockSpendIntrospectionHint]) -> anyhow::Result<()> {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = GoldilocksField;
    type S = KVQSimpleMemoryBackingStore;
    type PS = SimpleProofStoreMemory;

    let finalized = hints[0]
        .get_introspection_result::<PoseidonHash, F>()
        .get_finalized_result::<PoseidonHash>();
    println!("finalized: {:?}", finalized);
    println!(
        "finalized.current_block_state_hash: {} ({:?})",
        finalized.current_block_state_hash.to_string(),
        finalized.current_block_state_hash.0
    );
    println!(
        "finalized.next_block_state_hash: {} ({:?})",
        finalized.next_block_state_hash.to_string(),
        finalized.next_block_state_hash.0
    );

    let network_magic = NETWORK_MAGIC_DOGE_REGTEST;

    let sighash_whitelist_tree = SigHashMerkleTree::new();
    println!(
        "sighash_whitelist_tree.root: {:?}",
        sighash_whitelist_tree.root.0
    );
    let toolbox_circuits =
        CRWorkerToolboxRootCircuits::<C, D>::new(network_magic, SIGHASH_WHITELIST_TREE_ROOT);
    //toolbox_circuits.print_op_common_data();

    let mut proof_store = PS::new();
    let mut store = S::new();
    let mut timer = DebugTimer::new("prove_block_demo");

    timer.lap("start creating wallets");

    let mut wallet = DebugScenarioWallet::<C, D>::new();

    let _deposit_0_public_key = wallet.add_secp256k1_private_key(Hash256(hex_literal::hex!(
        "07e5cae38a63f487667075c54cb7791b86179e3becd9198e5ee0557eeffcda31"
    )))?;

    let _deposit_1_public_key = wallet.add_secp256k1_private_key(Hash256(hex_literal::hex!(
        "df5bf5d53e56b17602f49c56246b9e1196b2335f8571147fe2df70f3016c78a7"
    )))?;

    let user_0_public_key = wallet.add_zk_private_key(QHashOut::from_values(100, 100, 100, 100));
    let user_1_public_key = wallet.add_zk_private_key(QHashOut::from_values(101, 101, 101, 101));
    let user_2_public_key = wallet.add_zk_private_key(QHashOut::from_values(102, 102, 102, 102));

    timer.lap("end creating wallets");

    timer.lap("start setup initial state");
    let register_user_rpc_events = CityRegisterUserRPCRequest::new_batch(&[
        user_0_public_key,
        user_1_public_key,
        user_2_public_key,
    ]);
    let block_0_state = CityL2BlockState {
        checkpoint_id: 0,
        next_add_withdrawal_id: 0,
        next_process_withdrawal_id: 0,
        next_deposit_id: 0,
        total_deposits_claimed_epoch: 0,
        next_user_id: 0,
        end_balance: 0,
    };

    CityStore::set_block_state(&mut store, &block_0_state)?;

    timer.lap("end setup initial state");
    timer.lap("start process state block 1 RPC");
    let mut block_1_builder = QRPCProcessor::<F>::new(1);
    block_1_builder.process_register_users(0, &register_user_rpc_events)?;

    let block_1_requested = CityScenarioRequestedActions::new_from_requested_rpc(
        block_1_builder.output,
        hints[0].funding_transactions.iter().skip(1),
        &block_0_state,
        2,
    );

    let mut block_1_planner = CityOrchestratorBlockPlanner::<S, PS>::new(
        toolbox_circuits.core.fingerprints.clone(),
        block_0_state,
    );
    timer.lap("end process state block 1 RPC");
    timer.lap("start process requests block 1");

    let (_, block_1_job_ids, _block_1_state_transition, block_1_end_jobs, _) =
        block_1_planner.process_requests(&mut store, &mut proof_store, &block_1_requested)?;
    let final_state_root =
        felt252_hashout_to_hash256_le(CityStore::<S>::get_city_root(&store, 1)?.0);
    let modified_hints = hints
        .iter()
        .map(|x| x.perform_sighash_hash_surgery(final_state_root))
        .collect::<Vec<_>>();

    let sighash_jobs = SigHashFinalizer::finalize_sighashes::<PS>(
        &mut proof_store,
        &sighash_whitelist_tree,
        1,
        *block_1_end_jobs.last().unwrap(),
        &modified_hints,
    )?;
    timer.lap("end process requests block 1");
    /*println!(
            "block_1_job_ids: {}",
            serde_json::to_string(&block_1_job_ids).unwrap()
        );
        println!("block_1_job_ids: {:?}", block_1_job_ids);
        println!(
            "block_1_state_transition: {}",
            serde_json::to_string(&block_1_state_transition).unwrap()
        );
    */
    let mut worker = QWorkerStandardProver::new();
    timer.lap("start proving op jobs");

    let all_job_ids = block_1_job_ids.plan_jobs();
    for job in all_job_ids {
        worker.prove::<PS, _, C, D>(&mut proof_store, &toolbox_circuits, job)?;
    }
    timer.lap("start proving end jobs");

    for job in block_1_end_jobs.iter() {
        worker.prove::<PS, _, C, D>(&mut proof_store, &toolbox_circuits, *job)?;
    }

    timer.lap("start proving sighash jobs");

    for job in sighash_jobs.sighash_introspection_job_ids.iter() {
        worker.prove::<PS, _, C, D>(&mut proof_store, &toolbox_circuits, *job)?;
    }

    timer.lap("start proving final_gl jobs");
    for job in sighash_jobs.sighash_final_gl_job_ids.iter() {
        worker.prove::<PS, _, C, D>(&mut proof_store, &toolbox_circuits, *job)?;
    }
    for job in sighash_jobs.wrap_sighash_final_bls12381_job_ids.iter() {
        worker.prove::<PS, _, C, D>(&mut proof_store, &toolbox_circuits, *job)?;
    }
    let sighash_proof = proof_store
        .get_proof_by_id::<C, D>(sighash_jobs.sighash_introspection_job_ids[0].get_output_id())?;
    println!(
        "sighash_proof.public_inputs: {:?}",
        sighash_proof.public_inputs
    );
    let state_root_proof =
        proof_store.get_proof_by_id::<C, D>(block_1_end_jobs.last().unwrap().get_output_id())?;
    println!(
        "state_root_proof.public_inputs: {:?}",
        state_root_proof.public_inputs
    );
    let first_sighash_proof = proof_store
        .get_proof_by_id::<C, D>(sighash_jobs.sighash_final_gl_job_ids[0].get_output_id())?;
    println!(
        "first_sighash_proof.public_inputs: {:?}",
        first_sighash_proof.public_inputs
    );

    let first_wrap_sighash_final_gl_proof = proof_store
        .get_bytes_by_id(sighash_jobs.wrap_sighash_final_bls12381_job_ids[0].get_output_id())?;
    println!(
        "first_wrap_sighash_final_gl_proof {:?}",
        std::str::from_utf8(&first_wrap_sighash_final_gl_proof)?
    );

    timer.lap("end proving jobs");
    /*
    let root_proof_ids = block_1_job_ids.get_root_proof_outputs();

    let register_users_proof =
        proof_store.get_proof_by_id::<C, D>(root_proof_ids.register_user_job_root_id)?;

    let add_deposit_proof =
        proof_store.get_proof_by_id::<C, D>(root_proof_ids.add_deposit_job_root_id)?;
    println!("got register_users_proof: {:?}", register_users_proof);*/
    Ok(())
}
fn main() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let path = format!("{}/examples/full_block_hints_3.json", root.display());
    let file_data = fs::read(path).unwrap();
    let introspection_hints: Vec<BlockSpendIntrospectionHint> =
        serde_json::from_slice(&file_data).unwrap();
    let configs = introspection_hints
        .iter()
        .map(|x| x.get_config())
        .collect::<Vec<_>>();
    println!("configs: {}", serde_json::to_string(&configs).unwrap());
    prove_block_demo(&introspection_hints).unwrap();

    //println!("Proof: {:?}", proof);
}
