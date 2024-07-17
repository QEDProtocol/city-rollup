use std::str::FromStr;

use city_common::cli::user_args::GetPublicKeyArgs;
use city_crypto::hash::base_types::hash256::Hash256;
use city_crypto::hash::qhashout::QHashOut;
use city_crypto::signature::secp256k1::wallet::{CompressedPublicKeyToP2PKH, MemorySecp256K1Wallet};
use city_rollup_common::introspection::rollup::signature::SimpleL2PrivateKey;
use city_rollup_common::link::data::BTCAddress160;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::hash::poseidon::PoseidonHash;

pub async fn run(args: GetPublicKeyArgs) -> anyhow::Result<()> {
    let private_key_base = QHashOut::<GoldilocksField>::from_str(&args.private_key)
        .map_err(|e| anyhow::format_err!("{}", e.to_string()))?;
    let l1_public_key = MemorySecp256K1Wallet::new().add_private_key(Hash256::from_hex_string(&args.private_key)?)?;
    let l2_public_key = SimpleL2PrivateKey::new(private_key_base).get_public_key::<PoseidonHash>();

    println!("l1 public_key = {}", hex::encode(&l1_public_key.0));
    println!("l1 p2pkh = {}", BTCAddress160::new_p2pkh(l1_public_key.to_p2pkh_address()).to_address_string());
    println!("l2 public_key = {}", l2_public_key.to_string());
    Ok(())
}
