use std::{thread::sleep, time::Duration};

use city_common::{
    cli::message::CITY_ROLLUP_BANNER, logging::debug_timer::DebugTimer, units::UNIT_BTC,
};
use city_crypto::hash::{base_types::hash256::Hash256, qhashout::QHashOut};
use city_redis_store::RedisStore;
use city_rollup_circuit::{wallet::memory::CityMemoryWallet, worker::toolbox::root::CRWorkerToolboxRootCircuits};
use city_rollup_common::{
    actors::{
        rpc_processor::QRPCProcessor,
        traits::{OrchestratorRPCEventSenderSync, WorkerEventTransmitterSync},
    },
    api::data::{block::rpc_request::CityRegisterUserRPCRequest, store::CityL2BlockState},
    introspection::rollup::constants::NETWORK_MAGIC_DOGE_REGTEST,
    link::{
        data::BTCAddress160, link_api::BTCLinkAPI, traits::QBitcoinAPIFunderSync,
        tx::setup_genesis_block,
    },
};
use city_rollup_core_orchestrator::{
    debug::scenario::actors::simple::SimpleActorOrchestrator,
    event_receiver::CityEventReceiver,
};
use city_rollup_core_worker::event_processor::CityEventProcessor;
use city_rollup_worker_dispatch::implementations::redis::RedisQueue;
use city_store::store::{city::base::CityStore, sighash::SigHashMerkleTree};
use kvq::memory::simple::KVQSimpleMemoryBackingStore;
use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig};
fn run_full_block() -> anyhow::Result<()> {
    tracing::info!("{}", CITY_ROLLUP_BANNER);
    let mut api = BTCLinkAPI::new_str(
        "http://devnet:devnet@localhost:1337/bitcoin-rpc/?network=dogeRegtest",
        "http://localhost:1337/api",
    );

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = GoldilocksField;
    type S = KVQSimpleMemoryBackingStore;
    type CityOrchestrator = SimpleActorOrchestrator;

    let network_magic = NETWORK_MAGIC_DOGE_REGTEST;

    let sighash_whitelist_tree = SigHashMerkleTree::new();

    let mut proof_store = RedisStore::new("redis://localhost:6379/0")?;
    let redis_queue = RedisQueue::new("redis://localhost:6379/0")?;
    let mut store = S::new();
    let mut timer = DebugTimer::new("prove_block_demo");
    let mut worker_event_processor = CityEventProcessor::new(redis_queue.clone());
    let mut rpc_queue =
        CityEventReceiver::<F>::new(redis_queue, QRPCProcessor::new(0), proof_store.clone());

    /*
    let start_state_root = CityStore::get_city_root(&store, 1)?;
    tracing::info!(
        "start_state_root: {} ({:?})",
        start_state_root.to_string(),
        start_state_root.0
    );*/

    timer.lap("start creating wallets");

    let mut wallet = CityMemoryWallet::<C, D>::new_fast_setup();

    let genesis_funder_public_key = wallet.add_secp256k1_private_key(Hash256(
        hex_literal::hex!("133700f4676a0d0e16aaced646ed693626fcf1329db55be8eee13ad8df001337"),
    ))?;
    let genesis_funder_address = BTCAddress160::from_p2pkh_key(genesis_funder_public_key);

    let deposit_0_public_key = wallet.add_secp256k1_private_key(Hash256(hex_literal::hex!(
        "e6baf19a8b0b9b8537b9354e178a0a42d0887371341d4b2303537c5d18d7bb87"
    )))?;
    let deposit_0_address = BTCAddress160::from_p2pkh_key(deposit_0_public_key);

    let deposit_1_public_key = wallet.add_secp256k1_private_key(Hash256(hex_literal::hex!(
        "51dfec6b389f5f033bbe815d5df995a20851227fd845a3be389ca9ad2b6924f0"
    )))?;
    let deposit_1_address = BTCAddress160::from_p2pkh_key(deposit_1_public_key);

    timer.lap("end creating wallets");

    timer.lap("start setup initial state");
    let block_0_state = CityL2BlockState {
        checkpoint_id: 0,
        next_add_withdrawal_id: 0,
        next_process_withdrawal_id: 0,
        next_deposit_id: 0,
        total_deposits_claimed_epoch: 0,
        next_user_id: 0,
        end_balance: 0,
    };
    let block_1_state = CityL2BlockState {
        checkpoint_id: 1,
        next_add_withdrawal_id: 0,
        next_process_withdrawal_id: 0,
        next_deposit_id: 0,
        total_deposits_claimed_epoch: 0,
        next_user_id: 0,
        end_balance: 0,
    };

    CityStore::set_block_state(&mut store, &block_0_state)?;
    CityStore::set_block_state(&mut store, &block_1_state)?;
    let genesis_state_hash = CityStore::get_city_root(&store, 0)?;
    let setup_fee = 100000 * 500;
    let fund_genesis_txid = api.fund_address_from_random_p2pkh_address(
        genesis_funder_address,
        101 * UNIT_BTC + setup_fee * 4,
    )?;

    api.mine_blocks(1)?;
    let txid_fund_genesis = setup_genesis_block(
        &api,
        &wallet.secp256k1_wallet,
        genesis_funder_address.address,
        fund_genesis_txid,
        setup_fee,
        genesis_state_hash.to_felt252_hash256(),
    )?;
    tracing::info!(
        "funded genesis block with txid: {}",
        txid_fund_genesis.to_hex_string()
    );
    //tracing::info!("txid_fund_genesis: {}", txid_fund_genesis.to_hex_string());
    let block_2_address =
        BTCAddress160::new_p2sh(CityStore::get_city_block_deposit_address(&store, 2)?);

    api.mine_blocks(1)?;
    tracing::info!("block_2_address: {}", block_2_address.to_string());

    timer.lap("start creating wallets");
    let user_0_public_key = wallet.add_zk_private_key(QHashOut::from_values(100, 100, 100, 100));
    let user_1_public_key = wallet.add_zk_private_key(QHashOut::from_values(101, 101, 101, 101));
    let user_2_public_key = wallet.add_zk_private_key(QHashOut::from_values(102, 102, 102, 102));
    wallet.setup_circuits();
    timer.lap("end creating wallets");

    timer.lap("start creating worker");
    let root_toolbox =
        CRWorkerToolboxRootCircuits::<C, D>::new(network_magic, sighash_whitelist_tree.root);
    let fingerprints = root_toolbox.core.fingerprints.clone();
    timer.lap("end creating worker");

    let mut checkpoint_id = 2;
    timer.lap("start fund block 2");
    api.fund_address_from_known_p2pkh_address(
        &wallet.secp256k1_wallet,
        deposit_0_address,
        block_2_address,
        10 * UNIT_BTC,
    )?;
    api.fund_address_from_known_p2pkh_address(
        &wallet.secp256k1_wallet,
        deposit_1_address,
        block_2_address,
        15 * UNIT_BTC,
    )?;
    api.mine_blocks(10)?;
    timer.lap("waiting for deposits for 10 seconds...");
    sleep(Duration::from_millis(1000 * 10));
    timer.lap("end fund block 2");

    timer.lap("start prepare block 2 events");
    let register_user_rpc_events =
        CityRegisterUserRPCRequest::new_batch(&[user_0_public_key, user_1_public_key]);
    let _ = register_user_rpc_events
        .into_iter()
        .map(|x| rpc_queue.notify_rpc_register_user(&x))
        .collect::<anyhow::Result<Vec<()>>>()?;
    timer.lap("end prepare block 2 events");
    let mut requested_actions =
        rpc_queue.get_requested_actions_from_rpc(&mut proof_store, checkpoint_id)?;

    let orchestrator_result_step_1 = CityOrchestrator::step_1_produce_block_enqueue_jobs(
        &mut proof_store,
        &mut store,
        &mut requested_actions,
        &mut worker_event_processor,
        &mut api,
        &fingerprints,
        &sighash_whitelist_tree,
    )?;
    let end_state_root = CityStore::get_city_root(&store, 2)?;
    tracing::info!(
        "end_state_root: {} ({:?})",
        end_state_root.to_string(),
        end_state_root.0
    );
    worker_event_processor.wait_for_block_proving_jobs(checkpoint_id)?;
    api.mine_blocks(1)?;
    let orchestrator_result_step_2 = CityOrchestrator::step_2_produce_block_finalize_and_transact(
        &mut proof_store,
        &mut api,
        &orchestrator_result_step_1,
    )?;
    tracing::info!(
        "produced block, sent to : {}",
        orchestrator_result_step_2.to_hex_string()
    );
    api.mine_blocks(1)?;
    checkpoint_id = 3;
    tracing::info!("starting block {}", checkpoint_id);

    timer.lap("start prepare block 3 events");
    let register_user_rpc_events = CityRegisterUserRPCRequest::new_batch(&[user_2_public_key]);
    let _ = register_user_rpc_events
        .into_iter()
        .map(|x| rpc_queue.notify_rpc_register_user(&x))
        .collect::<anyhow::Result<Vec<()>>>()?;

    rpc_queue.notify_rpc_claim_deposit(&wallet.sign_claim_deposit(
        network_magic,
        0,
        &CityStore::<S>::get_deposit_by_id(&store, checkpoint_id, 0)?,
    )?)?;
    rpc_queue.notify_rpc_claim_deposit(&wallet.sign_claim_deposit(
        network_magic,
        1,
        &CityStore::<S>::get_deposit_by_id(&store, checkpoint_id, 1)?,
    )?)?;

    rpc_queue.notify_rpc_token_transfer(&wallet.sign_l2_transfer(
        user_0_public_key,
        network_magic,
        0,
        1,
        2 * UNIT_BTC,
        1,
    )?)?;
    rpc_queue.notify_rpc_token_transfer(&wallet.sign_l2_transfer(
        user_1_public_key,
        network_magic,
        1,
        2,
        5 * UNIT_BTC,
        1,
    )?)?;

    timer.lap("end prepare block 3 events");

    let mut requested_actions =
        rpc_queue.get_requested_actions_from_rpc(&mut proof_store, checkpoint_id)?;

    let orchestrator_result_step_1 = CityOrchestrator::step_1_produce_block_enqueue_jobs(
        &mut proof_store,
        &mut store,
        &mut requested_actions,
        &mut worker_event_processor,
        &mut api,
        &fingerprints,
        &sighash_whitelist_tree,
    )?;
    /*let end_state_root = CityStore::get_city_root(&store, 2)?;
    tracing::info!(
        "end_state_root: {} ({:?})",
        end_state_root.to_string(),
        end_state_root.0
    );*/
    worker_event_processor.wait_for_block_proving_jobs(checkpoint_id)?;
    api.mine_blocks(1)?;
    let orchestrator_result_step_2 = CityOrchestrator::step_2_produce_block_finalize_and_transact(
        &mut proof_store,
        &mut api,
        &orchestrator_result_step_1,
    )?;
    tracing::info!(
        "produced block, sent to : {}",
        orchestrator_result_step_2.to_hex_string()
    );
    api.mine_blocks(1)?;
    checkpoint_id = 4;
    tracing::info!("starting block {}", checkpoint_id);
    Ok(())
}

fn main() {
    run_full_block().unwrap();
}
