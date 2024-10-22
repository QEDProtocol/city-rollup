use std::{thread::sleep, time::Duration};

use city_common::{
    cli::message::CITY_ROLLUP_BANNER, logging::debug_timer::DebugTimer, units::UNIT_BTC,
};
use city_crypto::hash::{base_types::hash256::Hash256, qhashout::QHashOut};
use city_redis_store::RedisStore;
use city_rollup_circuit::wallet::memory::CityMemoryWallet;
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
    qworker::fingerprints::CRWorkerToolboxCoreCircuitFingerprints,
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

    let mut timer = DebugTimer::new("prove_block_demo");
    let mut proof_store = RedisStore::new("redis://localhost:6379/0")?;
    let redis_queue = RedisQueue::new("redis://localhost:6379/0")?;
    let mut store = S::new();
    let mut worker_event_processor = CityEventProcessor::new(redis_queue.clone());

    let mut rpc_queue =
        CityEventReceiver::<F>::new(redis_queue, QRPCProcessor::new(0), proof_store.clone());
    //let mut rpc_queue = DevMemoryCoordinatatorRPCQueue::<F>::new();

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
        genesis_state_hash.to_felt248_hash256(),
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
    let _user_3_public_key = wallet.add_zk_private_key(QHashOut::from_values(103, 103, 103, 103));
    wallet.setup_circuits();
    timer.lap("end creating wallets");

    timer.lap("start creating worker");
    /*
    let fingerprints =
        CRWorkerToolboxRootCircuits::<C, D>::new(network_magic, sighash_whitelist_tree.root).core.fingerprints;

        */
    let fingerprints: CRWorkerToolboxCoreCircuitFingerprints<GoldilocksField> =
        serde_json::from_str(
        r#"
{"network_magic":1384803358401167209,"zk_signature_wrapper":"2efad90d446638deb0af8cdc8efec541a82ee5ab2b6d221bd7d57af5885fe480","l1_secp256k1_signature":"0e06b3318325a6e4b2611b75767a366f79d50c039967f13760fe106d8560735b","op_register_user":{"leaf_fingerprint":"3b3c690b289d78d2e2acd9678d919f34534cbb1946a4edab39687951b2d8df3b","aggregator_fingerprint":"6d1911dc4660dc9b2e61a581a5c1608b7ef97c2971e7117e8e121be2dc362dce","dummy_fingerprint":"1a408fbe18d03c1c7886cc7f1906a07989535d2a995d4b16eacaa4c739df628b","allowed_circuit_hashes_root":"1860a3680b473aaea4f1a26f855890bb325fee1f1019b5a160483fd4f30294f8","leaf_circuit_type":0,"aggregator_circuit_type":1},"op_claim_l1_deposit":{"leaf_fingerprint":"a97c868fcd025a2763b6c03581729d0108a709eddfdadf209c3eef99a160a50f","aggregator_fingerprint":"6d1911dc4660dc9b2e61a581a5c1608b7ef97c2971e7117e8e121be2dc362dce","dummy_fingerprint":"1a408fbe18d03c1c7886cc7f1906a07989535d2a995d4b16eacaa4c739df628b","allowed_circuit_hashes_root":"b397fee16231a678ef08fb1bd7fd4cbca63a12d6ef0d2586a2b5f1dc3cc5b74b","leaf_circuit_type":4,"aggregator_circuit_type":5},"op_l2_transfer":{"leaf_fingerprint":"6e7817a58684785bb726c1c04ed544870b1d86c4b907815ed07694a65a76ad93","aggregator_fingerprint":"6d1911dc4660dc9b2e61a581a5c1608b7ef97c2971e7117e8e121be2dc362dce","dummy_fingerprint":"1a408fbe18d03c1c7886cc7f1906a07989535d2a995d4b16eacaa4c739df628b","allowed_circuit_hashes_root":"1c88193a6cde038e1120a42260a015c5247f3710e232aba8306f960cc55e33f2","leaf_circuit_type":6,"aggregator_circuit_type":7},"op_add_l1_withdrawal":{"leaf_fingerprint":"794761e0ceaf2a20be43877eced9db4c938b426c89785cf9d3f4773556086c84","aggregator_fingerprint":"6d1911dc4660dc9b2e61a581a5c1608b7ef97c2971e7117e8e121be2dc362dce","dummy_fingerprint":"1a408fbe18d03c1c7886cc7f1906a07989535d2a995d4b16eacaa4c739df628b","allowed_circuit_hashes_root":"cf222a8fa3c1f30f7266ebad8b0bd54c92029a0884ff151c26f8b08af790ff8f","leaf_circuit_type":8,"aggregator_circuit_type":9},"op_add_l1_deposit":{"leaf_fingerprint":"9cbbe2dd4a47b04a15441ccbfe95264130c22d6387cc9cab15c50c2fbeb6b3a8","aggregator_fingerprint":"6133fd6b95240863dc4458e6a6721a2bb37ea8f81080086ed775a32589a85f34","dummy_fingerprint":"081162f1ae48232a6d4a1e9c35adc0b4f2349fcaa740fa6034a7542e0ed1e5ca","allowed_circuit_hashes_root":"f4f90b1affb54b9bc0c110eab2276b943b4e352551c2c31e888d3e93be0a1858","leaf_circuit_type":2,"aggregator_circuit_type":3},"op_process_l1_withdrawal":{"leaf_fingerprint":"9aca81a13566a4529ef78c4385e9e6dddd157f54aef7b23d9501f1ea98541e03","aggregator_fingerprint":"6133fd6b95240863dc4458e6a6721a2bb37ea8f81080086ed775a32589a85f34","dummy_fingerprint":"081162f1ae48232a6d4a1e9c35adc0b4f2349fcaa740fa6034a7542e0ed1e5ca","allowed_circuit_hashes_root":"8c43a100d8e93a1dfdb0c5bb4830b31c4cb948f4e7d84fcc0419798ac331a90f","leaf_circuit_type":10,"aggregator_circuit_type":11},"agg_state_transition":"6d1911dc4660dc9b2e61a581a5c1608b7ef97c2971e7117e8e121be2dc362dce","agg_state_transition_with_events":"6133fd6b95240863dc4458e6a6721a2bb37ea8f81080086ed775a32589a85f34","agg_state_transition_dummy":"1a408fbe18d03c1c7886cc7f1906a07989535d2a995d4b16eacaa4c739df628b","agg_state_transition_with_events_dummy":"081162f1ae48232a6d4a1e9c35adc0b4f2349fcaa740fa6034a7542e0ed1e5ca"}        "#,
        )?;
    tracing::info!(
        "fingerprints: {}",
        serde_json::to_string(&fingerprints).unwrap()
    );
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

    let orchestrator_result_step_1 = SimpleActorOrchestrator::step_1_produce_block_enqueue_jobs(
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
