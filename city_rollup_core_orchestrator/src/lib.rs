use std::time::Duration;

use city_common::{cli::args::OrchestratorArgs, units::UNIT_BTC};
use city_crypto::hash::{base_types::hash256::Hash256, qhashout::QHashOut};
use city_macros::sync_infinite_loop;
use city_redis_store::RedisStore;
use city_rollup_common::{
    actors::{
        rpc_processor::QRPCProcessor,
        traits::{
            OrchestratorEventReceiverSync, OrchestratorRPCEventSenderSync,
            WorkerEventTransmitterSync,
        },
    },
    api::data::{block::rpc_request::CityRegisterUserRPCRequest, store::CityL2BlockState},
    link::{
        data::BTCAddress160, link_api::BTCLinkAPI, traits::QBitcoinAPIFunderSync,
        tx::setup_genesis_block,
    },
    qworker::fingerprints::CRWorkerToolboxCoreCircuitFingerprints,
};
use city_rollup_core_worker::event_processor::CityEventProcessor;
use city_rollup_worker_dispatch::implementations::redis::RedisQueue;
use city_store::store::{city::base::CityStore, sighash::SigHashMerkleTree};
use kvq_store_rocksdb::KVQRocksDBStore;
use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig};

use crate::{
    debug::scenario::{actors::simple::SimpleActorOrchestrator, wallet::DebugScenarioWallet},
    event_receiver::CityEventReceiver,
};

pub mod debug;
pub mod event_receiver;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = GoldilocksField;

pub fn run(args: OrchestratorArgs) -> anyhow::Result<()> {
    let mut proof_store = RedisStore::new(&args.redis_uri)?;
    let queue = RedisQueue::new(&args.redis_uri)?;
    let mut event_processor = CityEventProcessor::new(queue.clone());
    let fingerprints: CRWorkerToolboxCoreCircuitFingerprints<F> = serde_json::from_str(
        r#"
    {"network_magic":1384803358401167209,"zk_signature_wrapper":"2efad90d446638deb0af8cdc8efec541a82ee5ab2b6d221bd7d57af5885fe480","l1_secp256k1_signature":"0e06b3318325a6e4b2611b75767a366f79d50c039967f13760fe106d8560735b","op_register_user":{"leaf_fingerprint":"3b3c690b289d78d2e2acd9678d919f34534cbb1946a4edab39687951b2d8df3b","aggregator_fingerprint":"6d1911dc4660dc9b2e61a581a5c1608b7ef97c2971e7117e8e121be2dc362dce","dummy_fingerprint":"1a408fbe18d03c1c7886cc7f1906a07989535d2a995d4b16eacaa4c739df628b","allowed_circuit_hashes_root":"1860a3680b473aaea4f1a26f855890bb325fee1f1019b5a160483fd4f30294f8","leaf_circuit_type":0,"aggregator_circuit_type":1},"op_claim_l1_deposit":{"leaf_fingerprint":"e21b3c53d7f942bfca301943124794dd8ccefd6093ea490669ffd19ca26c0226","aggregator_fingerprint":"6d1911dc4660dc9b2e61a581a5c1608b7ef97c2971e7117e8e121be2dc362dce","dummy_fingerprint":"1a408fbe18d03c1c7886cc7f1906a07989535d2a995d4b16eacaa4c739df628b","allowed_circuit_hashes_root":"7fa5739771d7275eb11230444803a58f62918509b42db403b9670f3adc9fc9cc","leaf_circuit_type":4,"aggregator_circuit_type":5},"op_l2_transfer":{"leaf_fingerprint":"4e48381c9e08a9b592a088fa03dfd9e7935af7a0636ea420901b0a28cb9c55df","aggregator_fingerprint":"6d1911dc4660dc9b2e61a581a5c1608b7ef97c2971e7117e8e121be2dc362dce","dummy_fingerprint":"1a408fbe18d03c1c7886cc7f1906a07989535d2a995d4b16eacaa4c739df628b","allowed_circuit_hashes_root":"f47cf0cc794240b402d3356facfcdc20dafc5b0769de4cd24ec7ac464c12f34a","leaf_circuit_type":6,"aggregator_circuit_type":7},"op_add_l1_withdrawal":{"leaf_fingerprint":"622f9e753ab45fc5b7164f67f9729cb7c04feccd6575fe876165d01fc77a99ae","aggregator_fingerprint":"6d1911dc4660dc9b2e61a581a5c1608b7ef97c2971e7117e8e121be2dc362dce","dummy_fingerprint":"1a408fbe18d03c1c7886cc7f1906a07989535d2a995d4b16eacaa4c739df628b","allowed_circuit_hashes_root":"2c973bb888a4c25b8e309465f548272b6e3c0b8f994930d295f655a368f40b78","leaf_circuit_type":8,"aggregator_circuit_type":9},"op_add_l1_deposit":{"leaf_fingerprint":"9cbbe2dd4a47b04a15441ccbfe95264130c22d6387cc9cab15c50c2fbeb6b3a8","aggregator_fingerprint":"a97d6231eaba54ccd65185134b7e830562540d933598d9decc6ec36bf4f632d5","dummy_fingerprint":"081162f1ae48232a6d4a1e9c35adc0b4f2349fcaa740fa6034a7542e0ed1e5ca","allowed_circuit_hashes_root":"b4a4c9b5f8c9af6e9c76946bb3aff7d6f1471061d67411b07cd4bd3da392fcff","leaf_circuit_type":2,"aggregator_circuit_type":3},"op_process_l1_withdrawal":{"leaf_fingerprint":"9aca81a13566a4529ef78c4385e9e6dddd157f54aef7b23d9501f1ea98541e03","aggregator_fingerprint":"a97d6231eaba54ccd65185134b7e830562540d933598d9decc6ec36bf4f632d5","dummy_fingerprint":"081162f1ae48232a6d4a1e9c35adc0b4f2349fcaa740fa6034a7542e0ed1e5ca","allowed_circuit_hashes_root":"1ef92f20ea565bbfe49d75997e82b965c0887714bb98065a2463b72f555b060b","leaf_circuit_type":10,"aggregator_circuit_type":11},"agg_state_transition":"6d1911dc4660dc9b2e61a581a5c1608b7ef97c2971e7117e8e121be2dc362dce","agg_state_transition_with_events":"a97d6231eaba54ccd65185134b7e830562540d933598d9decc6ec36bf4f632d5","agg_state_transition_dummy":"1a408fbe18d03c1c7886cc7f1906a07989535d2a995d4b16eacaa4c739df628b","agg_state_transition_with_events_dummy":"081162f1ae48232a6d4a1e9c35adc0b4f2349fcaa740fa6034a7542e0ed1e5ca"}

    "#,
    )?;
    let mut api = BTCLinkAPI::new_str(&args.bitcoin_rpc, &args.electrs_api);
    let mut rpc_queue =
        CityEventReceiver::<F>::new(queue.clone(), QRPCProcessor::new(0), proof_store.clone());

    let mut wallet = DebugScenarioWallet::<C, D>::new_fast_setup();
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

    let sighash_whitelist_tree = SigHashMerkleTree::new();
    let block0 = CityL2BlockState {
        checkpoint_id: 0,
        next_add_withdrawal_id: 0,
        next_process_withdrawal_id: 0,
        next_deposit_id: 0,
        total_deposits_claimed_epoch: 0,
        next_user_id: 0,
        end_balance: 0,
    };
    let block1 = CityL2BlockState {
        checkpoint_id: 1,
        next_add_withdrawal_id: 0,
        next_process_withdrawal_id: 0,
        next_deposit_id: 0,
        total_deposits_claimed_epoch: 0,
        next_user_id: 0,
        end_balance: 0,
    };
    let mut store = KVQRocksDBStore::open_default(args.db_path)?;
    CityStore::set_block_state(&mut store, &block0)?;
    CityStore::set_block_state(&mut store, &block1)?;

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
    println!(
        "funded genesis block with txid: {}",
        txid_fund_genesis.to_hex_string()
    );
    let block_2_address =
        BTCAddress160::new_p2sh(CityStore::get_city_block_deposit_address(&store, 2)?);
    api.mine_blocks(1)?;
    let user_0_public_key = wallet.add_zk_private_key(QHashOut::from_values(100, 100, 100, 100));
    let user_1_public_key = wallet.add_zk_private_key(QHashOut::from_values(101, 101, 101, 101));
    let _ = wallet.add_zk_private_key(QHashOut::from_values(102, 102, 102, 102));
    let _ = wallet.add_zk_private_key(QHashOut::from_values(103, 103, 103, 103));
    let register_user_rpc_events =
        CityRegisterUserRPCRequest::new_batch(&[user_0_public_key, user_1_public_key]);
    let _ = register_user_rpc_events
        .into_iter()
        .map(|x| rpc_queue.notify_rpc_register_user(&x))
        .collect::<anyhow::Result<Vec<()>>>()?;
    /* 

    let user_0_public_key = wallet.add_zk_private_key(QHashOut::from_values(100, 100, 100, 100));
    let user_1_public_key = wallet.add_zk_private_key(QHashOut::from_values(101, 101, 101, 101));
    let _ = wallet.add_zk_private_key(QHashOut::from_values(102, 102, 102, 102));
    let _ = wallet.add_zk_private_key(QHashOut::from_values(103, 103, 103, 103));
    wallet.setup_circuits();
    println!("block_2_address: {}", block_2_address.to_string());
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
    std::thread::sleep(Duration::from_millis(1000 * 10));

    let register_user_rpc_events =
        CityRegisterUserRPCRequest::new_batch(&[user_0_public_key, user_1_public_key]);
    let _ = register_user_rpc_events
        .into_iter()
        .map(|x| rpc_queue.notify_rpc_register_user(&x))
        .collect::<anyhow::Result<Vec<()>>>()?;
    */

    sync_infinite_loop!(1000, {
        let block_state = CityStore::get_latest_block_state(&store)?;
        println!("block_state.checkpoint_id: {}", block_state.checkpoint_id);
        let mut event_receiver = CityEventReceiver::<F>::new(
            queue.clone(),
            QRPCProcessor::new(block_state.checkpoint_id + 1),
            proof_store.clone(),
        );
        event_receiver.wait_for_produce_block()?;
        let orchestrator_result_step_1 =
            SimpleActorOrchestrator::step_1_produce_block_enqueue_jobs(
                &mut proof_store,
                &mut store,
                &mut event_receiver,
                &mut event_processor,
                &mut api,
                &fingerprints,
                &sighash_whitelist_tree,
            )?;
        event_processor.wait_for_block_proving_jobs(block_state.checkpoint_id + 1)?;
        api.mine_blocks(1)?;
        let txid = SimpleActorOrchestrator::step_2_produce_block_finalize_and_transact(
            &mut proof_store,
            &mut api,
            &orchestrator_result_step_1,
        )?;
        println!("funded next block: {}",txid.to_hex_string());
        api.mine_blocks(1)?;
    });
}
