use city_crypto::field::conversions::bytes33_to_public_key;
use city_crypto::hash::base_types::felt252::hash256_le_to_felt252_hashout;
use city_crypto::hash::qhashout::QHashOut;
use city_crypto::signature::secp256k1::core::hash256_to_hashout_u224;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::config::AlgebraicHasher;
use serde::Deserialize;
use serde::Serialize;
use serde_with::serde_as;

use super::introspection_result::BTCRollupIntrospectionResult;
use super::introspection_result::BTCRollupIntrospectionResultDeposit;
use super::introspection_result::BTCRollupIntrospectionResultWithdrawal;
use crate::introspection::sighash::SigHashPreimage;
use crate::introspection::sighash::SigHashPreimageConfig;
use crate::introspection::transaction::BTCTransaction;
use crate::introspection::transaction::BTCTransactionConfig;

#[serde_as]
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct BlockSpendIntrospectionHint {
    pub sighash_preimage: SigHashPreimage,

    pub last_block_spend_index: i32,
    pub block_spend_index: usize,

    pub current_spend_index: usize,

    pub funding_transactions: Vec<BTCTransaction>,

    #[serde_as(as = "serde_with::hex::Hex")]
    pub next_block_redeem_script: Vec<u8>,
}
impl BlockSpendIntrospectionHint {
    pub fn get_config(&self) -> BlockSpendIntrospectionGadgetConfig {
        BlockSpendIntrospectionGadgetConfig {
            sighash_preimage_config: self.sighash_preimage.get_sighash_config(),
            funding_transaction_configs: self
                .funding_transactions
                .iter()
                .map(|tx| tx.get_tx_config())
                .collect(),
            block_spend_index: self.block_spend_index,
            current_spend_index: self.current_spend_index,
            last_block_spend_index: self.last_block_spend_index,

            block_script_length: self.next_block_redeem_script.len(),
        }
    }
    pub fn get_introspection_result<H: AlgebraicHasher<F>, F: RichField>(
        &self,
    ) -> BTCRollupIntrospectionResult<F> {
        let sighash_felt252 = QHashOut(self.sighash_preimage.get_hash_felt252::<F>());
        let spend_index = self.current_spend_index;
        let mut deposits: Vec<BTCRollupIntrospectionResultDeposit<F>> = Vec::new();
        let mut withdrawals: Vec<BTCRollupIntrospectionResultWithdrawal<F>> = Vec::new();

        for (i, d) in self.funding_transactions.iter().enumerate() {
            if i as i32 != self.last_block_spend_index {
                deposits.push(BTCRollupIntrospectionResultDeposit {
                    txid_224: QHashOut(hash256_to_hashout_u224(
                        d.get_hash(), /* self.sighash_preimage.transaction.inputs[self.
                                       * current_spend_index].hash, */
                    )),
                    public_key: bytes33_to_public_key::<F>(&d.inputs[0].script[73..106]),
                    value: F::from_noncanonical_u64(d.outputs[0].value),
                })
            }
        }

        for (i, output) in self.sighash_preimage.transaction.outputs.iter().enumerate() {
            if i != self.block_spend_index {
                withdrawals.push(BTCRollupIntrospectionResultWithdrawal {
                    script: output
                        .script
                        .iter()
                        .map(|b| F::from_canonical_u8(*b))
                        .collect::<Vec<_>>(),
                    value: F::from_noncanonical_u64(output.value),
                })
            }
        }

        let current_block_rollup_balance = if self.last_block_spend_index != -1 {
            F::from_noncanonical_u64(
                self.funding_transactions[self.last_block_spend_index as usize].outputs[0].value,
            )
        } else {
            F::ZERO
        };
        let next_block_rollup_balance = F::from_noncanonical_u64(
            self.sighash_preimage.transaction.outputs[self.block_spend_index].value,
        );
        let current_block_state_hash: [u8; 32] =
            self.sighash_preimage.transaction.inputs[self.current_spend_index].script[1..33]
                .try_into()
                .unwrap();

        BTCRollupIntrospectionResult {
            sighash: self.sighash_preimage.get_hash(),
            sighash_felt252,
            spend_index,
            deposits,
            withdrawals,
            current_block_rollup_balance,
            next_block_rollup_balance,
            current_block_state_hash: QHashOut(hash256_le_to_felt252_hashout(
                &current_block_state_hash,
            )),
            next_block_state_hash: QHashOut(hash256_le_to_felt252_hashout(
                &self.next_block_redeem_script[1..33],
            )),
        }
    }
}

#[serde_as]
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct BlockSpendIntrospectionGadgetConfig {
    pub sighash_preimage_config: SigHashPreimageConfig,
    pub funding_transaction_configs: Vec<BTCTransactionConfig>,

    pub last_block_spend_index: i32,
    pub block_spend_index: usize,

    pub current_spend_index: usize,

    pub block_script_length: usize,
}
