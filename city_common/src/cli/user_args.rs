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

#[derive(Clone, Args)]
pub struct AddWithdrawalArgs {
    #[clap(long, short, default_value = "0.0.0.0:3000", env)]
    pub rpc_address: String,

    #[clap(long, default_value = "dogeregtest", env)]
    pub network: String,

    #[clap(long, short)]
    pub public_key: String,

    #[clap(long, short)]
    pub user_id: u64,

    #[clap(long, short)]
    pub value: u64,

    #[clap(long, short)]
    pub nonce: u64,

    // #[clap(long, short)]
    // pub destination_type: u8,

    #[clap(long, short)]
    pub destination: String,
}

#[derive(Clone, Args)]
pub struct ClaimDepositArgs {
    #[clap(long, short, default_value = "0.0.0.0:3000", env)]
    pub rpc_address: String,

    #[clap(long, short)]
    pub private_key: String,

    #[clap(long, default_value = "dogeregtest", env)]
    pub network: String,

    /// l1deposit
    #[clap(long, short)]
    pub txid: String,

    #[clap(long, short)]
    pub user_id: u64,
}

#[derive(Clone, Args)]
pub struct RegisterUserArgs {
    #[clap(long, short, default_value = "0.0.0.0:3000", env)]
    pub rpc_address: String,
    /// user private key
    #[clap(long, short)]
    pub private_key: String,
}

#[derive(Clone, Args)]
pub struct TokenTransferArgs {
    #[clap(long, short, default_value = "0.0.0.0:3000", env)]
    pub rpc_address: String,

    #[clap(long, default_value = "dogeregtest", env)]
    pub network: String,

    #[clap(long, short)]
    pub public_key: String,

    #[clap(long, short)]
    pub value: u64,

    #[clap(long, short)]
    pub from: u64,

    #[clap(long, short)]
    pub to: u64,

    #[clap(long, short)]
    pub nonce: u64,
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
