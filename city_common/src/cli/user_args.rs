use clap::Args;

#[derive(Clone, Args)]
pub struct RandomWalletArgs {}

#[derive(Clone, Args)]
pub struct GetPublicKeyArgs {
    /// user private key
    #[clap(long, short)]
    pub private_key: String,
}

#[derive(Clone, Args)]
pub struct SignHashArgs {
    /// user private key
    #[clap(long, short)]
    pub private_key: String,

    /// action hash to sign
    #[clap(long, short)]
    pub action_hash: String,

    /// output file path for the proof
    #[clap(long, short)]
    pub output: String,
}

/*
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
    #[clap(env, long, default_value = "", env)]
    pub private_key: String,
    #[clap(short, long)]
    pub from: u64,
    #[clap(short, long)]
    pub to: u64,
    #[clap(short, long)]
    pub amount: u64,
    #[clap(short, long)]
    pub nonce: u64,
}
*/
