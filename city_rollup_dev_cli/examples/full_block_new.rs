use std::{thread::sleep, time::Duration};

use city_common::{logging::debug_timer::DebugTimer, units::UNIT_BTC};
use city_crypto::{
    hash::base_types::hash256::Hash256, signature::secp256k1::wallet::MemorySecp256K1Wallet,
};
use city_rollup_common::{
    api::data::store::CityL2BlockState,
    config::sighash_wrapper_config::SIGHASH_WHITELIST_TREE_ROOT,
    introspection::rollup::constants::NETWORK_MAGIC_DOGE_REGTEST,
    link::{
        data::BTCAddress160,
        link_api::BTCLinkAPI,
        traits::QBitcoinAPIFunderSync,
        tx::{send_entire_balance_simple_p2pkh, setup_genesis_block},
    },
    qworker::memory_proof_store::SimpleProofStoreMemory,
};
use city_rollup_core_orchestrator::debug::scenario::wallet::DebugScenarioWallet;
use city_store::store::{city::base::CityStore, sighash::SigHashMerkleTree};
use kvq::memory::simple::KVQSimpleMemoryBackingStore;
use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig};
fn run_full_block() -> anyhow::Result<()> {
    let api = BTCLinkAPI::new_str(
        "http://devnet:devnet@localhost:1337/bitcoin-rpc/?network=dogeRegtest",
        "http://localhost:1337/api",
    );

    let mut wallet = MemorySecp256K1Wallet::new();
    let address_0 = BTCAddress160::from_p2pkh_key(wallet.add_private_key(Hash256(
        hex_literal::hex!("4aff83bc362080634c25316fe89bf5414b97ba44437e4068ddda8ed94a47c58f"),
    ))?);
    let address_1 = BTCAddress160::from_p2pkh_key(wallet.add_private_key(Hash256(
        hex_literal::hex!("09a803d7f826a7372dc0294b7b876c86bc83c202415c2241c23c3305abfc3051"),
    ))?);
    let address_2 = BTCAddress160::from_p2pkh_key(wallet.add_private_key(Hash256(
        hex_literal::hex!("072565005c5a2d84c1ec342c3c758450407f25129406805cd0463059289e20e9"),
    ))?);

    println!("address_0: {}", address_0.to_string());
    println!("address_1: {}", address_1.to_string());
    println!("address_2: {}", address_2.to_string());

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = GoldilocksField;
    type S = KVQSimpleMemoryBackingStore;
    type PS = SimpleProofStoreMemory;

    let network_magic = NETWORK_MAGIC_DOGE_REGTEST;

    let sighash_whitelist_tree = SigHashMerkleTree::new();

    let mut proof_store = PS::new();
    let mut store = S::new();
    let mut timer = DebugTimer::new("prove_block_demo");

    timer.lap("start creating wallets");

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

    CityStore::set_block_state(&mut store, &block_0_state)?;
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
    println!("txid_fund_genesis: {}", txid_fund_genesis.to_hex_string());
    let block_1_address =
        BTCAddress160::new_p2sh(CityStore::get_city_block_deposit_address(&store, 1)?);

    api.mine_blocks(1)?;
    println!("block_1_address: {}", block_1_address.to_string());

    Ok(())
}

fn main() {
    run_full_block().unwrap();
}
