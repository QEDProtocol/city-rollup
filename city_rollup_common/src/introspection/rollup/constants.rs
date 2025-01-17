// Network Magic
pub const NETWORK_MAGIC_DOGE_MAINNET: u64 = 0x1337CF514544F069u64;
pub const NETWORK_MAGIC_DOGE_TESTNET: u64 = 0x1337CF514544F169u64;
pub const NETWORK_MAGIC_DOGE_REGTEST: u64 = 0x1337CF514544FF69u64;

// Sig Actions
// CDEPOSIT (little-endian)
pub const SIG_ACTION_CLAIM_DEPOSIT_MAGIC: u64 = 0x5449534F50454443u64;

// WITHDRAW (little-endian)
pub const SIG_ACTION_WITHDRAW_MAGIC: u64 = 0x5741524448544957u64;

// SENDDOGE (little-endian)
pub const SIG_ACTION_TRANSFER_MAGIC: u64 = 0x45474F44444E4553u64;

pub fn get_network_magic_for_str(network: String) -> anyhow::Result<u64> {
    match network.as_str() {
        "dogeregtest" => Ok(NETWORK_MAGIC_DOGE_REGTEST),
        "dogetestnet" => Ok(NETWORK_MAGIC_DOGE_TESTNET),
        "dogemainnet" => Ok(NETWORK_MAGIC_DOGE_MAINNET),
        _ => Err(anyhow::anyhow!("Invalid network {}", network)),
    }
}
