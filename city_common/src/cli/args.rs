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
    #[clap(env, long, default_value = "redis://localhost:6379/0", env)]
    pub redis_uri: String,
    #[clap(short, env, long, default_value = "db", env)]
    pub db_path: String,
    #[clap(short, env, long, default_value = "0", env)]
    pub rpc_node_id: u32,
}

#[derive(Clone, Args)]
pub struct OrchestratorArgs {
    #[clap(long, default_value = "https://localhost:3000", env)]
    pub rollup_rpc_url: String,
    #[clap(
        env,
        long,
        default_value = "http://devnet:devnet@localhost:1337/bitcoin-rpc/?network=dogeRegtest",
        env
    )]
    pub bitcoin_rpc: String,
    #[clap(env, long, default_value = "http://localhost:1337/api", env)]
    pub electrs_api: String,
    #[clap(env, long, default_value = "redis://localhost:6379/0", env)]
    pub redis_uri: String,
    #[clap(short, env, long, default_value = "db", env)]
    pub db_path: String,
    #[clap(short, long, default_value = "dogeregtest", env)]
    pub network: String,
    #[clap(short, long, default_value = "204274aebd35178f5e623e3ca6d2c76e727f91d138ca73bbdf3ba5265f1eb046017c76a82086a678dd3c502984b1dcd3113bd0a109fd4ca99bf06dae158b9459cc825e4ac3884c50f71007206f1177e3a21cc9cc7d71e1962a54c3e996a019f2ab03522832fcbc4653c63ae833ed10a29c46cb0b53ac0b11fdcbb74abb7397fce69b1b02a20524597d5ef967f7a4bb61e361435e68093ba04c50f4d21e0dfd30268c995d87c4e9b4f6b66ab0b112f29fce17528af62af6c8c2a07f97fbf2f63368777e1b5ae416e74ce96461592a4f32c137e20a9d084d5e7a35db133f92f24b6a9e26f955f11c107eac4c50315da2d0baaafabda118d5d270cc2b83194387a45be51697d702d98c36bbdf6f7bd734907da6fb50732699d32811ac6b706914c709669a944c3a515a599ef212dceda5b4cfa611a0373051ed84dbf0f24c50aea325ee3b32a4b3b4b42535cb935b025f1b182c88a90055c8747ad06ceb40421f2f6135f12685799a021dbfd0a28cb940e842342cf5c11bea9947d8180c8981aea561f364b9e7979e8065a24cef64b44c5026602c18df26a22fb829ce63f0ee4c75ab615a4fa2f29916f9a436a46263bdc3f1baac49ff3891a83612a5ad3fa80010d5d9f9ff71a24936e8021af4eaf9683f977ff4a6d12894fcbc1455a0d14f9fcc51926d6d6d6d6d6d51", env)]
    pub next_block_redeem_script: String,
}

#[derive(Clone, Args)]
pub struct L2WorkerArgs {
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
    #[clap(env, long, default_value = "redis://localhost:6379/0", env)]
    pub redis_uri: String,
    #[clap(short, env, long, default_value = "db", env)]
    pub db_path: String,
    #[clap(short, long, default_value = "dogeregtest", env)]
    pub network: String,
}
#[derive(Clone, Args)]
pub struct L2TransferArgs {
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
    #[clap(env, long, default_value = "redis://localhost:6379/0", env)]
    pub redis_uri: String,
    #[clap(short, env, long, default_value = "db", env)]
    pub db_path: String,
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
