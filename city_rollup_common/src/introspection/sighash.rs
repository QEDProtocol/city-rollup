use city_crypto::hash::{
    base_types::{felt252::hash256_le_to_felt252_hashout, hash256::Hash256},
    core::btc::btc_hash256,
};
use plonky2::hash::hash_types::{HashOut, RichField};
use serde::{Deserialize, Serialize};

use super::transaction::{BTCTransaction, BTCTransactionConfig, BTCTransactionOutput};
/*


#[derive(PartialEq, Eq, Debug, Copy, Clone, Hash)]
pub enum EcdsaSighashType {
    /// 0x1: Sign all outputs.
    All = 0x01,
    /// 0x2: Sign no outputs --- anyone can choose the destination.
    None = 0x02,
    /// 0x3: Sign the output whose index matches this input's index. If none exists,
    /// sign the hash `0000000000000000000000000000000000000000000000000000000000000001`.
    /// (This rule is probably an unintentional C++ism, but it's consensus so we have
    /// to follow it.)
    Single = 0x03,
    /// 0x81: Sign all outputs but only this input.
    AllPlusAnyoneCanPay = 0x81,
    /// 0x82: Sign no outputs and only this input.
    NonePlusAnyoneCanPay = 0x82,
    /// 0x83: Sign one output and only this input (see `Single` for what "one output" means).
    SinglePlusAnyoneCanPay = 0x83,
}
*/
pub const SIGHASH_ALL: u32 = 0x01;
pub const SIGHASH_NONE: u32 = 0x02;
pub const SIGHASH_SINGLE: u32 = 0x03;
pub const SIGHASH_ANYONECANPAY: u32 = 0x80;
pub const SIGHASH_ALL_ANYONECANPAY: u32 = SIGHASH_ALL | SIGHASH_ANYONECANPAY;
pub const SIGHASH_NONE_ANYONECANPAY: u32 = SIGHASH_NONE | SIGHASH_ANYONECANPAY;
pub const SIGHASH_SINGLE_ANYONECANPAY: u32 = SIGHASH_SINGLE | SIGHASH_ANYONECANPAY;

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct SigHashPreimage {
    pub transaction: BTCTransaction,
    pub sighash_type: u32,
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct SigHashPreimageConfig {
    pub transaction_config: BTCTransactionConfig,
    pub sighash_type: u32,
}

fn prepare_sighash_preimage_pre_segwit(
    transaction: &BTCTransaction,
    input_index: usize,
    prev_out_script: &[u8],
    sighash_type: u32,
) -> SigHashPreimage {
    // TODO: remove code separator from prev_out_script like bitcoinlib-js?
    let our_script = prev_out_script.to_vec();

    let mut tx = transaction.clone();
    if (sighash_type & 0x1f) == SIGHASH_NONE {
        // ignore all outputs
        tx.outputs = vec![];
        tx.inputs[input_index].sequence = 0;
    } else if (sighash_type & 0x1f) == SIGHASH_SINGLE {
        // ignore all outputs except the one at the same index
        tx.outputs.truncate(input_index + 1);
        for i in 0..input_index {
            tx.outputs[i] = BTCTransactionOutput::blank();
            tx.inputs[i].sequence = 0;
        }
    }
    if (sighash_type & SIGHASH_ANYONECANPAY) != 0 {
        tx.inputs = vec![tx.inputs[input_index].clone()];
        tx.inputs[0].script = our_script;
    } else {
        // SIGHASH_ALL
        for input in tx.inputs.iter_mut() {
            input.script = vec![];
        }
        tx.inputs[input_index].script = our_script;
    }

    SigHashPreimage {
        transaction: tx,
        sighash_type,
    }
}

impl SigHashPreimage {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.extend(self.transaction.to_bytes());
        bytes.extend(self.sighash_type.to_le_bytes());
        bytes
    }
    pub fn from_bytes(data: &[u8]) -> anyhow::Result<Self> {
        let (transaction, index) = BTCTransaction::from_bytes_offset(data, 0)?;
        if index + 4 > data.len() {
            return Err(anyhow::anyhow!("Not enough data to parse SigHashPreimage"));
        }
        let sighash_type = u32::from_le_bytes(data[index..(index + 4)].try_into().unwrap());
        Ok(Self {
            transaction,
            sighash_type,
        })
    }
    pub fn for_transaction_pre_segwit(
        transaction: &BTCTransaction,
        input_index: usize,
        prev_out_script: &[u8],
        sighash_type: u32,
    ) -> Self {
        prepare_sighash_preimage_pre_segwit(transaction, input_index, prev_out_script, sighash_type)
    }

    pub fn get_hash(&self) -> Hash256 {
        btc_hash256(&self.to_bytes())
    }
    pub fn get_hash_felt252<F: RichField>(&self) -> HashOut<F> {
        hash256_le_to_felt252_hashout::<F>(&self.get_hash().0)
    }
    pub fn get_sighash_config(&self) -> SigHashPreimageConfig {
        SigHashPreimageConfig {
            transaction_config: self.transaction.get_tx_config(),
            sighash_type: self.sighash_type,
        }
    }
}
