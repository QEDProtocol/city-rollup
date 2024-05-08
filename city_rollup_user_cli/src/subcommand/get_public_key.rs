use std::str::FromStr;

use city_common::cli::user_args::GetPublicKeyArgs;
use city_crypto::hash::qhashout::QHashOut;
use city_rollup_common::introspection::rollup::signature::SimpleL2PrivateKey;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::hash::poseidon::PoseidonHash;

use crate::error::Result;

pub async fn run(args: GetPublicKeyArgs) -> Result<()> {
    let private_key_base = QHashOut::<GoldilocksField>::from_str(&args.private_key)
        .map_err(|e| anyhow::format_err!("{}", e.to_string()))?;
    let private_key = SimpleL2PrivateKey::new(private_key_base);
    let public_key = private_key.get_public_key::<PoseidonHash>();

    println!("public_key = {}", public_key.to_string());
    Ok(())
}
