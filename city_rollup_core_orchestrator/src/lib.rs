use std::{sync::Arc, time::Duration};

use city_common::{cli::args::OrchestratorArgs, units::UNIT_BTC};
use city_crypto::hash::{base_types::hash256::Hash256, qhashout::QHashOut};
use city_macros::sync_infinite_loop;
use city_redis_store::RedisStore;
use city_rollup_circuit::{wallet::memory::CityMemoryWallet, worker::toolbox::circuits::CRWorkerToolboxCoreCircuits};
use city_rollup_common::{
    actors::{
        rpc_processor::QRPCProcessor,
        traits::{
            OrchestratorEventReceiverSync, OrchestratorRPCEventSenderSync,
            WorkerEventTransmitterSync,
        },
    }, api::data::{block::rpc_request::CityRegisterUserRPCRequest, store::CityL2BlockState}, introspection::rollup::constants::get_network_magic_for_str, link::{
        data::BTCAddress160, link_api::BTCLinkAPI, traits::QBitcoinAPIFunderSync,
        tx::setup_genesis_block,
    }, qworker::proof_store::QDummyProofStore
};
use city_rollup_core_api::KV;
use city_rollup_core_worker::event_processor::CityEventProcessor;
use city_rollup_worker_dispatch::implementations::redis::RedisQueue;
use city_store::store::{city::base::CityStore, sighash::SigHashMerkleTree};
use kvq_store_redb::KVQReDBStore;
use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig};
use redb::Database;

use crate::{
    debug::scenario::actors::simple::SimpleActorOrchestrator, event_receiver::CityEventReceiver,
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
    let mut api = BTCLinkAPI::new_str(&args.bitcoin_rpc, &args.electrs_api);
    let network_magic = get_network_magic_for_str(args.network.to_string())?;
    let toolbox =
        CRWorkerToolboxCoreCircuits::<C, D>::new(network_magic);
    let mut rpc_queue =
        CityEventReceiver::<F>::new(queue.clone(), QRPCProcessor::new(0), proof_store.clone());

    let mut wallet = CityMemoryWallet::<C, D>::new_fast_setup();
    let genesis_funder_public_key = wallet.add_secp256k1_private_key(Hash256(
        hex_literal::hex!("133700f4676a0d0e16aaced646ed693626fcf1329db55be8eee13ad8df001337"),
    ))?;
    let genesis_funder_address = BTCAddress160::from_p2pkh_key(genesis_funder_public_key);
    let deposit_0_public_key = wallet.add_secp256k1_private_key(Hash256(hex_literal::hex!(
        "e6baf19a8b0b9b8537b9354e178a0a42d0887371341d4b2303537c5d18d7bb87"
    )))?;
    let _deposit_0_address = BTCAddress160::from_p2pkh_key(deposit_0_public_key);
    let deposit_1_public_key = wallet.add_secp256k1_private_key(Hash256(hex_literal::hex!(
        "51dfec6b389f5f033bbe815d5df995a20851227fd845a3be389ca9ad2b6924f0"
    )))?;
    let _deposit_1_address = BTCAddress160::from_p2pkh_key(deposit_1_public_key);

    let sighash_whitelist_tree = SigHashMerkleTree::new();
    let block0 = CityL2BlockState::default();
    let block1 = CityL2BlockState {
        checkpoint_id: 1,
        ..Default::default()
    };
    let db = Arc::new(Database::create(&args.db_path)?);
    let wxn = db.begin_write()?;
    {
        let table = wxn.open_table(KV)?;
        let mut store = KVQReDBStore::new(table);
        let expose_proof_store_api = args.expose_proof_store_api;
        let api_proof_store = proof_store.clone();

        let dbc = db.clone();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap();

            let _ = rt.block_on(async move {
                tracing::info!("api server listening on http://{}", args.server_addr);
                if expose_proof_store_api {
                    city_rollup_core_api::run_server(args.server_addr, dbc, api_proof_store).await?;
                } else {
                    city_rollup_core_api::run_server(args.server_addr, dbc, QDummyProofStore::new()).await?;
                }
                Ok::<_, anyhow::Error>(())
            });
        });
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
            genesis_state_hash.to_felt248_hash256(),
        )?;
        tracing::info!(
            "funded genesis block with txid: {}",
            txid_fund_genesis.to_hex_string()
        );
        let _block_2_address =
            BTCAddress160::new_p2sh(CityStore::get_city_block_deposit_address(&store, 2)?);
        api.mine_blocks(1)?;
        let user_0_public_key =
            wallet.add_zk_private_key(QHashOut::from_values(100, 100, 100, 100));
        let user_1_public_key =
            wallet.add_zk_private_key(QHashOut::from_values(101, 101, 101, 101));
        let _ = wallet.add_zk_private_key(QHashOut::from_values(102, 102, 102, 102));
        let _ = wallet.add_zk_private_key(QHashOut::from_values(103, 103, 103, 103));
        let register_user_rpc_events =
            CityRegisterUserRPCRequest::new_batch(&[user_0_public_key, user_1_public_key]);
        let _ = register_user_rpc_events
            .into_iter()
            .map(|x| rpc_queue.notify_rpc_register_user(&x))
            .collect::<anyhow::Result<Vec<()>>>()?;
    }
    wxn.commit()?;

    /*
    let user_0_public_key = wallet.add_zk_private_key(QHashOut::from_values(100, 100, 100, 100));
    let user_1_public_key = wallet.add_zk_private_key(QHashOut::from_values(101, 101, 101, 101));
    let _ = wallet.add_zk_private_key(QHashOut::from_values(102, 102, 102, 102));
    let _ = wallet.add_zk_private_key(QHashOut::from_values(103, 103, 103, 103));
    wallet.setup_circuits();
    tracing::info!("block_2_address: {}", block_2_address.to_string());
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
        let wxn = db.begin_write()?;
        {
            let table = wxn.open_table(KV)?;
            let mut store = KVQReDBStore::new(table);
            let block_state = CityStore::get_latest_block_state(&store)?;
            tracing::info!(
                "last_block_state.checkpoint_id: {}",
                block_state.checkpoint_id
            );
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
                    &toolbox.fingerprints,
                    &sighash_whitelist_tree,
                )?;
            event_processor.wait_for_block_proving_jobs(block_state.checkpoint_id + 1)?;
            api.mine_blocks(1)?;
            let txid = SimpleActorOrchestrator::step_2_produce_block_finalize_and_transact(
                &mut proof_store,
                &mut api,
                &orchestrator_result_step_1,
            )?;
            tracing::info!("funded next block: {}", txid.to_hex_string());
            api.mine_blocks(1)?;
        }
        wxn.commit()?;
    });
}
