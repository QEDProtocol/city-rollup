use std::{collections::HashMap, str::FromStr};

use city_common::cli::user_args::RPCReplArgs;
use city_crypto::{
    hash::{base_types::hash256::Hash256, qhashout::QHashOut}, signature::secp256k1::wallet::MemorySecp256K1Wallet,
};
use city_rollup_common::{
    introspection::transaction::BTCTransactionInputWithoutScript,
    link::{
        data::BTCAddress160,
        link_api::BTCLinkAPI,
        traits::{QBitcoinAPIFunderSync, QBitcoinAPISync},
        tx::{send_entire_balance_simple_p2pkh, send_p2pkh_exact_value},
    },
};

use city_rollup_rpc_provider::{CityRpcProviderSync, RpcProviderSync};

use anyhow::Result;
use plonky2::field::goldilocks_field::GoldilocksField;
use repl_rs::{Command, Convert, Parameter, Repl, Value};
use serde::{Deserialize, Serialize};
/*
const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = GoldilocksField;
*/
const MAX_CHECKPOINT_ID: u64 = 0xffffffff;
struct ReplContext {
    pub city_rpc: RpcProviderSync,
    pub btc_link_rpc: BTCLinkAPI,
}
impl ReplContext {
    pub fn new(city_rpc_url: &str, btc_rpc_url: &str, electrs_rpc_url: &str) -> Self {
        let city_rpc = RpcProviderSync::new(city_rpc_url);
        let btc_link_rpc = BTCLinkAPI::new_str(btc_rpc_url, electrs_rpc_url);

        Self {
            city_rpc,
            btc_link_rpc,
        }
    }
}

// Get a user by id
fn get_user_by_id(
    args: HashMap<String, Value>,
    context: &mut ReplContext,
) -> Result<Option<String>> {
    let user_id: u64 = args["user_id"].convert()?;
    let checkpoint_option = args.get("checkpoint");
    let checkpoint_id: u64 = if checkpoint_option.is_some() {
        checkpoint_option.unwrap().convert()?
    } else {
        MAX_CHECKPOINT_ID
    };

    let result = context
        .city_rpc
        .get_user_by_id_sync(checkpoint_id, user_id)?;

    Ok(Some(serde_json::to_string_pretty(&result)?))
}

// Get a deposit by id
fn get_deposit_by_id(
    args: HashMap<String, Value>,
    context: &mut ReplContext,
) -> Result<Option<String>> {
    let deposit_id: u64 = args["deposit_id"].convert()?;
    let checkpoint_option = args.get("checkpoint");
    let checkpoint_id: u64 = if checkpoint_option.is_some() {
        checkpoint_option.unwrap().convert()?
    } else {
        MAX_CHECKPOINT_ID
    };

    let result = context
        .city_rpc
        .get_deposit_by_id_sync(checkpoint_id, deposit_id)?;

    Ok(Some(serde_json::to_string_pretty(&result)?))
}

// Get a block by id
fn get_block_by_id(
    args: HashMap<String, Value>,
    context: &mut ReplContext,
) -> Result<Option<String>> {
    let checkpoint_option = args.get("checkpoint");
    let checkpoint_id: u64 = if checkpoint_option.is_some() {
        checkpoint_option.unwrap().convert()?
    } else {
        MAX_CHECKPOINT_ID
    };

    let result = context.city_rpc.get_block_state_sync(checkpoint_id)?;

    Ok(Some(serde_json::to_string_pretty(&result)?))
}
// Get a withdrawal by id
fn get_withdrawal_by_id(
    args: HashMap<String, Value>,
    context: &mut ReplContext,
) -> Result<Option<String>> {
    let withdrawal_id: u64 = args["withdrawal_id"].convert()?;
    let checkpoint_option = args.get("checkpoint");
    let checkpoint_id: u64 = if checkpoint_option.is_some() {
        checkpoint_option.unwrap().convert()?
    } else {
        MAX_CHECKPOINT_ID
    };

    let result = context
        .city_rpc
        .get_withdrawal_by_id_sync(checkpoint_id, withdrawal_id)?;

    Ok(Some(serde_json::to_string_pretty(&result)?))
}

// Get block deposit addresss by id
fn get_block_deposit_address_by_id(
    args: HashMap<String, Value>,
    context: &mut ReplContext,
) -> Result<Option<String>> {
    let checkpoint_option = args.get("checkpoint");
    let checkpoint_id: u64 = if checkpoint_option.is_some() {
        checkpoint_option.unwrap().convert()?
    } else {
        MAX_CHECKPOINT_ID
    };

    let result = context
        .city_rpc
        .get_city_block_deposit_address_string_sync(checkpoint_id)?;

    Ok(Some(result))
}

fn get_utxos(args: HashMap<String, Value>, context: &mut ReplContext) -> Result<Option<String>> {
    let address: String = args["address"].convert()?;

    let result = context
        .btc_link_rpc
        .get_utxos(BTCAddress160::try_from_string(&address)?)?;

    Ok(Some(serde_json::to_string_pretty(&result)?))
}

fn faucet(args: HashMap<String, Value>, context: &mut ReplContext) -> Result<Option<String>> {
    let address: String = args["address"].convert()?;
    let amount: u64 = args["amount"].convert()?;

    let result = context
        .btc_link_rpc
        .fund_address_from_random_p2pkh_address(
            BTCAddress160::try_from_string(&address)?,
            amount,
        )?;

    Ok(Some(format!(
        "{{\"txid\": \"{}\"}}",
        result.to_hex_string()
    )))
}

fn mine_l1_blocks(
    args: HashMap<String, Value>,
    context: &mut ReplContext,
) -> Result<Option<String>> {
    let optional_count = args.get("count");
    let count = if optional_count.is_some() {
        optional_count.unwrap().convert()?
    } else {
        1u32
    };
    let results = context.btc_link_rpc.mine_blocks(count)?;

    Ok(Some(serde_json::to_string_pretty(&results)?))
}
fn get_user_ids_for_public_key(
    args: HashMap<String, Value>,
    context: &mut ReplContext,
) -> Result<Option<String>> {
    let public_key_string: String = args["public_key"].convert()?;
    let public_key = QHashOut::<GoldilocksField>::from_str(&public_key_string)?;
    let results = context.city_rpc.get_user_ids_for_public_key_sync(public_key)?;


    Ok(Some(serde_json::to_string(&results)?))
}

fn spend_all(args: HashMap<String, Value>, context: &mut ReplContext) -> Result<Option<String>> {
    let private_key: String = args["private_key"].convert()?;
    let recipient: String = args["recipient"].convert()?;
    let optional_fee = args.get("fee");
    let fee = if optional_fee.is_some() {
        optional_fee.unwrap().convert()?
    } else {
        10000000u64
    };

    let mut wallet = MemorySecp256K1Wallet::new();
    let from = BTCAddress160::from_p2pkh_key(
        wallet.add_private_key(Hash256::from_hex_string(&private_key)?)?,
    );
    let to = BTCAddress160::try_from_string(&recipient)?;

    let txid =
        send_entire_balance_simple_p2pkh(&context.btc_link_rpc, &wallet, from.address, to, fee)?;

    Ok(Some(format!("{{\"txid\": \"{}\"}}", txid.to_hex_string())))
}

fn spend_utxo(args: HashMap<String, Value>, context: &mut ReplContext) -> Result<Option<String>> {
    let private_key: String = args["private_key"].convert()?;
    let txid_string: String = args["txid"].convert()?;
    let txid = Hash256::from_hex_string(&txid_string)?;
    let recipient: String = args["recipient"].convert()?;
    let optional_fee = args.get("fee");
    let fee = if optional_fee.is_some() {
        optional_fee.unwrap().convert()?
    } else {
        10000000u64
    };
    let mut wallet = MemorySecp256K1Wallet::new();

    let from = BTCAddress160::from_p2pkh_key(
        wallet.add_private_key(Hash256::from_hex_string(&private_key)?)?,
    );
    let to = BTCAddress160::try_from_string(&recipient)?;

    let funding_tx = context.btc_link_rpc.get_transaction(txid)?;
    let vouts = funding_tx.get_vouts_for_address(&from);
    let value: u64 = vouts
        .iter()
        .map(|x| {
            let index: usize = (*x) as usize;
            funding_tx.outputs[index].value
        })
        .sum();
    let inputs = vouts
        .into_iter()
        .map(|x| BTCTransactionInputWithoutScript {
            hash: txid.reversed(),
            index: x,
            sequence: 0xffffffff,
        })
        .collect::<Vec<_>>();

    if value <= fee {
        anyhow::bail!(
            "balance ({} sats) must be greater than fee ({} sats) ",
            value,
            fee
        );
    }

    let txid = send_p2pkh_exact_value(
        &context.btc_link_rpc,
        &wallet,
        from.address,
        to,
        &inputs,
        value - fee,
    )?;

    Ok(Some(format!("{{\"txid\": \"{}\"}}", txid.to_hex_string())))
}

#[derive(Serialize, Deserialize, Clone)]
struct L1P2PKHWallet {
    pub address: String,
    pub private_key: Hash256,
    pub public_key: String,
}
impl L1P2PKHWallet {
    pub fn new_random() -> anyhow::Result<Self> {
        let mut wallet = MemorySecp256K1Wallet::new();
        let private_key = Hash256::rand();
        let public_key = wallet.add_private_key(private_key)?;
        let address = BTCAddress160::from_p2pkh_key(public_key);
        Ok(Self {
            address: address.to_address_string(),
            private_key,
            public_key: hex::encode(&public_key.0),
        })
    }
}
fn random_dogecoin_wallet(
    _args: HashMap<String, Value>,
    _context: &mut ReplContext,
) -> Result<Option<String>> {
    let rand_wallet = L1P2PKHWallet::new_random()?;
    Ok(Some(serde_json::to_string_pretty(&rand_wallet)?))
}
fn exit_repl(_args: HashMap<String, Value>, _context: &mut ReplContext) -> Result<Option<String>> {
    std::process::exit(0);
}

pub async fn run(args: RPCReplArgs) -> Result<()> {
    let mut repl = Repl::new(ReplContext::new(
        &args.rpc_address,
        &args.bitcoin_rpc,
        &args.electrs_api,
    ))
    .with_name("CityRollup REPL")
    .with_version("v0.1.0")
    .with_description("A REPL for City Rollup")
    .use_completion(true)
    .add_command(
        Command::new("user", get_user_by_id)
            .with_help("fetch user by id")
            .with_parameter(Parameter::new("user_id").set_required(true)?)?
            .with_parameter(Parameter::new("checkpoint").set_required(false)?)?,
    )
    .add_command(
        Command::new("deposit", get_deposit_by_id)
            .with_help("fetch deposit by id")
            .with_parameter(Parameter::new("deposit_id").set_required(true)?)?
            .with_parameter(Parameter::new("checkpoint").set_required(false)?)?,
    )
    .add_command(
        Command::new("withdrawal", get_withdrawal_by_id)
            .with_help("fetch withdrawal by id")
            .with_parameter(Parameter::new("withdrawal_id").set_required(true)?)?
            .with_parameter(Parameter::new("checkpoint").set_required(false)?)?,
    )
    .add_command(
        Command::new("block", get_block_by_id)
            .with_help("fetch block state by block id (checkpoint id)")
            .with_parameter(Parameter::new("checkpoint").set_required(false)?)?,
    )
    .add_command(
        Command::new("address", get_block_deposit_address_by_id)
            .with_help("fetch block deposit address by block id (checkpoint id)")
            .with_parameter(Parameter::new("checkpoint").set_required(false)?)?,
    )
    .add_command(
        Command::new("utxos", get_utxos)
            .with_help("fetch L1 utxos for dogecoin address")
            .with_parameter(Parameter::new("address").set_required(true)?)?,
    )
    .add_command(
        Command::new("faucet", faucet)
            .with_help("fetch L1 utxos for dogecoin address")
            .with_parameter(Parameter::new("address").set_required(true)?)?
            .with_parameter(Parameter::new("amount").set_required(true)?)?,
    )
    .add_command(
        Command::new("spend_all", spend_all)
            .with_help("spend all utxos for a P2PKH dogecoin address")
            .with_parameter(Parameter::new("private_key").set_required(true)?)?
            .with_parameter(Parameter::new("recipient").set_required(true)?)?
            .with_parameter(Parameter::new("fee").set_required(false)?)?,
    )
    .add_command(
        Command::new("spend_utxo", spend_utxo)
            .with_help("spend a utxo for a P2PKH dogecoin address")
            .with_parameter(Parameter::new("private_key").set_required(true)?)?
            .with_parameter(Parameter::new("txid").set_required(true)?)?
            .with_parameter(Parameter::new("recipient").set_required(true)?)?
            .with_parameter(Parameter::new("fee").set_required(false)?)?,
    )
    .add_command(
        Command::new("mine_l1_blocks", mine_l1_blocks)
            .with_help("mine n blocks on dogecoin layer 1 (regtest/local testnet ONLY)")
            .with_parameter(Parameter::new("count").set_required(false)?)?,
    )
    .add_command(
        Command::new("user_ids", get_user_ids_for_public_key)
            .with_help("get the user ids that have a given public key hash")
            .with_parameter(Parameter::new("public_key").set_required(true)?)?,
    )
    .add_command(
        Command::new("random_l1_wallet", random_dogecoin_wallet)
            .with_help("generate a random dogecoin P2PKH wallet"),
    )
    .add_command(Command::new("exit", exit_repl).with_help("exits the repl"));
    repl.run().map_err(|err| err.into())
}
