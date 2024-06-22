use city_common::cli::user_args::ProverRPCArgs;
use city_crypto::hash::base_types::hash256::Hash256;

pub async fn run(args: ProverRPCArgs) -> anyhow::Result<()> {
    let api_key = if args.api_key.is_empty() {
        Hash256::rand()
    } else {
        Hash256::from_hex_string(&args.api_key).map_err(|_| anyhow::anyhow!("invalid api key (must be 32 bytes, hex encoded)"))?
    };
    city_rollup_user_prover_api::run::run_server(args.prover_rpc_address, api_key).await?;
    Ok(())
}
