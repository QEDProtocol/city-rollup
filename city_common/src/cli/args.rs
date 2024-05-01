use clap::Args;

#[derive(Clone, Args)]
pub struct RPCServerArgs {
    #[clap(long, default_value = "0.0.0.0:3000", env)]
    pub rollup_rpc_address: String,
    #[clap(
        env,
        long,
        default_value = "http://devnet:devnet@localhost:1337/bitcoin-rpc/?network=dogeRegtest",
        env
    )]
    pub bitcoin_rpc: String,
    #[clap(env, long, default_value = "http://localhost:1337/api", env)]
    pub electrs_api: String,
    #[clap(env, long, default_value = "redis://localhost:6379", env)]
    pub redis_uri: String,
    #[clap(short, env, long, default_value = "db", env)]
    pub db_path: String,
}

#[derive(Clone, Args)]
#[cfg(debug_assertions)]
pub struct RollupProvingWorkerArgs {
    #[clap(short, env, long, default_value = "http://localhost:3000", env)]
    pub rollup_rpc_url: String,
    #[clap(env, long, default_value = "redis://localhost:6379", env)]
    pub redis_uri: String,
}

#[derive(Clone, Args)]
#[cfg(debug_assertions)]
pub struct L2TransferArgs {
    #[clap(short, env, long, default_value = "http://localhost:3000", env)]
    pub rollup_rpc_url: String,
    #[arg(env, long, default_value = "", env)]
    pub private_key: String,
    #[arg(short, long)]
    pub from: u64,
    #[arg(short, long)]
    pub to: u64,
    #[arg(short, long)]
    pub amount: u64,
    #[arg(short, long)]
    pub nonce: u64,
}
