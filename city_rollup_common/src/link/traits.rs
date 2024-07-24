use city_common::units::UNIT_BTC;
use city_crypto::{
    hash::base_types::hash256::Hash256,
    signature::secp256k1::wallet::{MemorySecp256K1Wallet, Secp256K1WalletProvider},
};

use crate::introspection::transaction::{
    BTCTransaction, BTCTransactionInputWithoutScript, BTCTransactionOutput,
};

use super::{
    data::{AddressToBTCScript, BTCAddress160, BTCTransactionWithVout, PartialBTCUTXO, BTCUTXO},
    tx::create_p2pkh_tx,
};

pub trait QBitcoinAPISync {
    fn get_funding_transactions(
        &self,
        address: BTCAddress160,
    ) -> anyhow::Result<Vec<BTCTransaction>>;
    fn get_confirmed_funding_transactions_with_vout(
        &self,
        address: BTCAddress160,
    ) -> anyhow::Result<Vec<BTCTransactionWithVout>>;
    fn get_utxos(&self, address: BTCAddress160) -> anyhow::Result<Vec<BTCUTXO>>;
    fn estimate_fee_rate(&self, n_blocks: u32) -> anyhow::Result<u64>;
    fn reset_cached_fee_rate(&mut self, n_blocks: u32) -> anyhow::Result<u64>;
    fn get_cached_fee_rate(&self) -> anyhow::Result<u64>;
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
        filter_fn: impl Fn(&BTCUTXO) -> bool
    ) -> anyhow::Result<Vec<BTCTransactionWithVout>>;
    fn get_transaction(&self, txid: Hash256) -> anyhow::Result<BTCTransaction>;
    fn send_transaction(&self, tx: &BTCTransaction) -> anyhow::Result<Hash256>;
}
pub trait QBitcoinAPIFunderSync: QBitcoinAPISync {
    fn fund_address(&self, address: BTCAddress160, amount: u64) -> anyhow::Result<Hash256>;
    fn fund_address_from_random_p2pkh_address(
        &self,
        address: BTCAddress160,
        amount: u64,
    ) -> anyhow::Result<Hash256> {
        let mut wallet = MemorySecp256K1Wallet::new();
        let from = BTCAddress160::from_p2pkh_key(wallet.add_private_key(Hash256::rand())?);
        self.fund_address_from_known_p2pkh_address(&wallet, from, address, amount)
    }
    fn fund_address_from_known_p2pkh_address<W: Secp256K1WalletProvider>(
        &self,
        wallet: &W,
        from: BTCAddress160,
        address: BTCAddress160,
        amount: u64,
    ) -> anyhow::Result<Hash256> {
        let fund_txid_0 = self.fund_address(from, amount + UNIT_BTC * 2)?;
        let full_tx = self.get_transaction(fund_txid_0)?;
        let vout = full_tx
            .get_vouts_for_address(&from)
            .first()
            .unwrap()
            .to_owned();

        let tx = create_p2pkh_tx(
            wallet,
            from.address,
            &[BTCTransactionInputWithoutScript {
                hash: fund_txid_0.reversed(),
                sequence: 0xffff_ffff,
                index: vout,
            }],
            vec![BTCTransactionOutput {
                value: amount,
                script: address.to_btc_script(),
            }],
        )?;
        self.send_transaction(&tx)
    }
    fn ask_for_refund<W: Secp256K1WalletProvider>(
        &self,
        wallet: &W,
        from: BTCAddress160,
        utxo: &BTCUTXO,
    ) -> anyhow::Result<Hash256> {
        let tx = create_p2pkh_tx(
            wallet,
            from.address,
            &[BTCTransactionInputWithoutScript {
                hash: utxo.txid,
                sequence: 0xffff_ffff,
                index: utxo.vout
            }],
            vec![BTCTransactionOutput {
                value: utxo.value,
                script: from.to_btc_script(),
            }],
        )?;
        self.send_transaction(&tx)
    }
    fn mine_blocks(&self, count: u32) -> anyhow::Result<Vec<Hash256>>;
    fn mine_blocks_to_address(&self, count: u32, address: BTCAddress160) -> anyhow::Result<()>;
}
