use city_crypto::{
    hash::base_types::{hash160::Hash160, hash256::Hash256},
    signature::secp256k1::wallet::Secp256K1WalletProvider,
};

use crate::introspection::transaction::{
    BTCTransaction, BTCTransactionInputWithoutScript, BTCTransactionOutput,
};

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

pub fn create_base_tx<W: Secp256K1WalletProvider, A: QBitcoinAPISync>(
    wallet: &W,
    script: &[u8],
    inputs: &[BTCTransactionInputWithoutScript],
    outputs: &[BTCTransactionOutput],
) -> anyhow::Result<BTCTransaction> {
    todo!()
}
pub trait QBitcoinScriptBuilderSync {
    fn create_p2pkh<W: Secp256K1WalletProvider, A: QBitcoinAPISync>(
        &self,
        api: &A,
        wallet: &W,
        from: Hash160,
        inputs: &[BTCTransactionInputWithoutScript],
        outputs: &[BTCTransactionOutput],
        amount: u64,
    ) -> anyhow::Result<BTCTransaction>;
    fn send_p2sh<W: Secp256K1WalletProvider, A: QBitcoinAPISync>(
        &self,
        api: &A,
        from: Hash160,
        inputs: &[BTCTransactionInputWithoutScript],
        outputs: &[BTCTransactionOutput],
        amount: u64,
    ) -> anyhow::Result<Hash256>;
}

pub trait QBitcoinAPIFunderSync {
    fn fund_address(&self, address: Hash160, amount: u64) -> anyhow::Result<Hash256>;
}
