use city_common::cli::user_args::L1DepositArgs;
use city_crypto::{
    hash::base_types::hash256::Hash256, signature::secp256k1::wallet::MemorySecp256K1Wallet,
};
use city_rollup_common::link::{
    data::BTCAddress160, link_api::BTCLinkAPI, traits::QBitcoinAPIFunderSync,
};
use city_rollup_rpc_provider::{CityRpcProvider, RpcProvider};

use anyhow::Result;

pub async fn run(args: L1DepositArgs) -> Result<()> {
    let provider = RpcProvider::new(&args.rpc_address);
    let mut wallet = MemorySecp256K1Wallet::new();
    let api = BTCLinkAPI::new_str(&args.bitcoin_rpc, &args.electrs_api);
    let from = BTCAddress160::from_p2pkh_key(
        wallet.add_private_key(Hash256::from_hex_string(&args.private_key)?)?,
    );

    let deposit_address = if args.deposit_address.is_empty() {
        let block_state = provider.get_latest_block_state().await?;
        provider
        .get_city_block_deposit_address(block_state.checkpoint_id + 1)
        .await?
    }else{
        BTCAddress160::try_from_string(&args.deposit_address)?.address
    };
    let txid = api.fund_address_from_known_p2pkh_address(
        &wallet,
        from,
        BTCAddress160::new_p2sh(deposit_address),
        args.amount,
    )?;
    api.mine_blocks(100)?;

    println!("{{\"txid\": \"{}\"}}", txid.to_hex_string());
    Ok(())
}
