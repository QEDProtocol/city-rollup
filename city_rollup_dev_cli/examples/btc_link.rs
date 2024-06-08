use std::{thread::sleep, time::Duration};

use city_common::units::UNIT_BTC;
use city_crypto::{
    hash::base_types::hash256::Hash256, signature::secp256k1::wallet::MemorySecp256K1Wallet,
};
use city_rollup_common::link::{
    data::BTCAddress160, link_api::BTCLinkAPI, traits::QBitcoinAPIFunderSync,
    tx::send_entire_balance_simple_p2pkh,
};

fn run_btc_link_demos() -> anyhow::Result<()> {
    let api = BTCLinkAPI::new_str(
        "http://devnet:devnet@localhost:18443",
        "http://localhost:50000",
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

    tracing::info!("address_0: {}", address_0.to_string());
    tracing::info!("address_1: {}", address_1.to_string());
    tracing::info!("address_2: {}", address_2.to_string());

    let txid_0 = api.fund_address(address_0, 2 * UNIT_BTC)?;
    tracing::info!("txid_0: {}", txid_0.to_hex_string());
    api.mine_blocks(10)?;
    sleep(Duration::from_millis(3000));
    let txid_1 =
        send_entire_balance_simple_p2pkh(&api, &wallet, address_0.address, address_1, 60000)?;
    tracing::info!("txid_1: {}", txid_1.to_hex_string());

    Ok(())
}

fn main() {
    run_btc_link_demos().unwrap();
}
