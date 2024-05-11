use city_crypto::hash::base_types::hash256::Hash256;

use crate::link::data::BTCUTXO;

#[derive(Debug, Clone)]
pub struct BTCDataResolverError {
    pub message: String,
}
impl BTCDataResolverError {
    pub fn new(message: String) -> Self {
        Self { message }
    }
    pub fn new_str(message: &str) -> Self {
        Self {
            message: message.to_string(),
        }
    }
}
impl core::fmt::Display for BTCDataResolverError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "error in BTCDataResolver: {}", self.message)
    }
}

impl std::error::Error for BTCDataResolverError {}

pub trait BTCDataResolver {
    fn get_raw_transaction_sync(&self, txid: Hash256) -> Result<Vec<u8>, BTCDataResolverError>;
    fn get_utxos_sync(&self, address: String) -> Result<Vec<BTCUTXO>, BTCDataResolverError>;
    fn send_raw_transaction_sync(
        &self,
        transaction_data: Vec<u8>,
    ) -> Result<Hash256, BTCDataResolverError>;
}
