use city_crypto::hash::base_types::{hash160::Hash160, hash256::Hash256};

use crate::introspection::transaction::BTCTransaction;

use super::data::{BTCAddress160, BTCTransactionWithVout, PartialBTCUTXO, BTCUTXO};

pub trait QBitcoinAPISync {
    fn get_funding_transactions(
        &self,
        address: BTCAddress160,
    ) -> anyhow::Result<Vec<BTCTransaction>>;
    fn get_utxos(&self, address: BTCAddress160) -> anyhow::Result<Vec<BTCUTXO>>;
    fn get_partial_utxos(&self, address: BTCAddress160) -> anyhow::Result<Vec<PartialBTCUTXO>> {
        Ok(self
            .get_utxos(address)?
            .into_iter()
            .map(|utxo| PartialBTCUTXO {
                txid: utxo.txid,
                vout: utxo.vout,
                value: utxo.value,
            })
            .collect())
    }
    fn get_funding_transactions_with_vout(
        &self,
        address: BTCAddress160,
    ) -> anyhow::Result<Vec<BTCTransactionWithVout>>;
    fn get_transaction(&self, txid: Hash256) -> anyhow::Result<BTCTransaction>;
    fn send_transaction(&self, tx: &BTCTransaction) -> anyhow::Result<Hash256>;
}
pub trait QBitcoinAPIFunderSync {
    fn fund_address(&self, address: BTCAddress160, amount: u64) -> anyhow::Result<Hash256>;
    fn mine_blocks(&self, count: u32) -> anyhow::Result<()>;
    fn mine_blocks_to_address(&self, count: u32, address: BTCAddress160) -> anyhow::Result<()>;
}
