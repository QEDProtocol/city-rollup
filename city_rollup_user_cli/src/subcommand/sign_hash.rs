use std::{fs, str::FromStr};

use city_common::cli::user_args::SignHashArgs;
use city_common_circuit::circuits::zk_signature::gen_standard_wrapped_zk_signature_proof;
use city_crypto::hash::qhashout::QHashOut;

use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig};

use crate::error::Result;

pub async fn run(args: SignHashArgs) -> Result<()> {
    let private_key_base = QHashOut::<GoldilocksField>::from_str(&args.private_key)
        .map_err(|e| anyhow::format_err!("{}", e.to_string()))?;
    let action_hash = QHashOut::<GoldilocksField>::from_str(&args.action_hash)
        .map_err(|e| anyhow::format_err!("{}", e.to_string()))?;

    let proof = gen_standard_wrapped_zk_signature_proof::<PoseidonGoldilocksConfig, 2>(
        private_key_base,
        action_hash,
    )?;

    fs::write(args.output, proof.to_bytes())
        .map_err(|e| anyhow::format_err!("{}", e.to_string()))?;
    Ok(())
}
