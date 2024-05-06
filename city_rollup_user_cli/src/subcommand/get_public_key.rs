use std::str::FromStr;

use city_common::cli::user_args::GetPublicKeyArgs;
use city_common_circuit::circuits::zk_signature::ZKSignatureCircuit;
use city_crypto::hash::qhashout::QHashOut;
use city_rollup_common::introspection::rollup::signature::SimpleL2PrivateKey;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::PoseidonGoldilocksConfig;

use crate::error::Result;

pub async fn run(args: GetPublicKeyArgs) -> Result<()> {
    let private_key_base = QHashOut::<GoldilocksField>::from_str(&args.private_key)
        .map_err(|e| anyhow::format_err!("{}", e.to_string()))?;
    let private_key = SimpleL2PrivateKey::new(private_key_base);

    let circuit = ZKSignatureCircuit::<PoseidonGoldilocksConfig, 2>::new(
        private_key.get_public_key::<PoseidonHash>(),
    );
    let public_key = circuit.public_key;
    println!("public_key = {}", public_key.to_string());
    Ok(())
}
