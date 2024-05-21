use city_common::{cli::args::OrchestratorArgs, logging::debug_timer::DebugTimer, units::UNIT_BTC};
use city_crypto::hash::base_types::hash256::Hash256;
use city_macros::define_table;
use city_redis_store::RedisStore;
use city_rollup_circuit::worker::toolbox::circuits::CRWorkerToolboxCoreCircuits;
use city_rollup_common::{
    actors::rpc_processor::QRPCProcessor,
    api::data::store::CityL2BlockState,
    introspection::rollup::constants::get_network_magic_for_str,
    link::{
        data::BTCAddress160, link_api::BTCLinkAPI, traits::QBitcoinAPIFunderSync,
        tx::setup_genesis_block,
    },
};
use city_rollup_core_worker::event_processor::CityEventProcessor;
use city_rollup_worker_dispatch::implementations::redis::RedisQueue;
use city_store::store::{city::base::CityStore, sighash::SigHashMerkleTree};
use kvq_store_redb::KVQReDBStore;
use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig};
use redb::{Database, TableDefinition};

use crate::{
    debug::scenario::{actors::simple::SimpleActorOrchestrator, wallet::DebugScenarioWallet},
    event_receiver::CityEventReceiver,
};

pub mod debug;
pub mod event_receiver;

define_table! { KV, &[u8], &[u8] }

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = GoldilocksField;

pub fn run(args: OrchestratorArgs) -> anyhow::Result<()> {
    let mut proof_store = RedisStore::new(&args.redis_uri)?;
    let database = Database::create(&args.db_path)?;
    let queue = RedisQueue::new(&args.redis_uri)?;
    let mut event_processor = CityEventProcessor::new(queue.clone());
    let toolbox = CRWorkerToolboxCoreCircuits::<C, D>::new(get_network_magic_for_str(
        args.network.to_string(),
    )?);
    let mut api = BTCLinkAPI::new_str(&args.bitcoin_rpc, &args.electrs_api);
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
    let mut timer = DebugTimer::new("run_orchestrator");
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
    let wxn = database.begin_write()?;
    {
        let mut store = KVQReDBStore::new(wxn.open_table(KV)?);
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
    }
    wxn.commit()?;

    loop {
        let wxn = database.begin_write()?;
        {
            let mut store = KVQReDBStore::new(wxn.open_table(KV)?);
            let block_state = CityStore::get_latest_block_state(&store)?;
            let mut event_receiver = CityEventReceiver::<F>::new(
                queue.clone(),
                QRPCProcessor::new(block_state.checkpoint_id + 1),
                proof_store.clone(),
            );
            SimpleActorOrchestrator::run_orchestrator(
                &mut proof_store,
                &mut store,
                &mut event_receiver,
                &mut event_processor,
                &mut api,
                &toolbox.get_fingerprint_config(),
                &sighash_whitelist_tree,
                &mut timer,
            )?;
        }
        wxn.commit()?;
    }
}
