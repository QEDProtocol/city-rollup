use clap::Args;
/*
pub const NETWORK_MAGIC_DOGE_MAINNET: u64 = 0x1337CF514544F069u64;
pub const NETWORK_MAGIC_DOGE_TESTNET: u64 = 0x1337CF514544F169u64;
pub const NETWORK_MAGIC_DOGE_REGTEST: u64 = 0x1337CF514544FF69u64;
*/
#[derive(Clone, Args)]
pub struct PrintCircuitInfoArgs {
    #[clap(short, long, default_value = "dogeregtest", env)]
    pub network: String,
}
#[derive(Clone, Args)]
pub struct TreeProveTestArgs {
    #[clap(short, long, default_value = "dogeregtest", env)]
    pub network: String,
}
