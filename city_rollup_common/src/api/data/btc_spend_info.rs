use city_crypto::hash::base_types::hash256::Hash256;
use serde::{Deserialize, Serialize};

use serde_with::serde_as;

use crate::introspection::{
    rollup::introspection::BlockSpendIntrospectionHint, sighash::SigHashPreimage,
    transaction::BTCTransaction,
};

#[serde_as]
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct SimpleRollupBlockSpendSigHashHint {
    pub sighash: Hash256,

    #[serde_as(as = "serde_with::hex::Hex")]
    pub sighash_preimage: Vec<u8>,

    pub index: usize,
    pub txid: Hash256,

    #[serde_as(as = "serde_with::hex::Hex")]
    pub funding_tx: Vec<u8>,
}

#[serde_as]
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct SimpleRollupBTCSpendInfo {
    pub sighash_hints_for_spend_inputs: Vec<SimpleRollupBlockSpendSigHashHint>,

    #[serde_as(as = "serde_with::hex::Hex")]
    pub next_block_redeem_script: Vec<u8>,
}

impl SimpleRollupBTCSpendInfo {
    pub fn to_block_spend_hints(&self) -> anyhow::Result<Vec<BlockSpendIntrospectionHint>> {
        let mut sorted_sighash_hints = self.sighash_hints_for_spend_inputs.clone();
        sorted_sighash_hints.sort_by(|a, b| a.index.cmp(&b.index));

        let mut funding_transactions = Vec::with_capacity(sorted_sighash_hints.len());

        for h in sorted_sighash_hints.iter() {
            let funding_transaction = BTCTransaction::from_bytes(&h.funding_tx)?;
            funding_transactions.push(funding_transaction);
        }

        let mut block_spend_hints: Vec<BlockSpendIntrospectionHint> = Vec::new();

        for h in sorted_sighash_hints.iter() {
            block_spend_hints.push(BlockSpendIntrospectionHint {
                sighash_preimage: SigHashPreimage::from_bytes(&h.sighash_preimage)?,
                current_spend_index: h.index,
                last_block_spend_index: 0,
                block_spend_index: 0,
                funding_transactions: funding_transactions.clone(),
                next_block_redeem_script: self.next_block_redeem_script.clone(),
            });
        }
        Ok(block_spend_hints)
    }
}
