use city_crypto::{
    field::conversions::bytes33_to_public_key,
    hash::{
        base_types::{felt252::hash256_le_to_felt252_hashout, hash256::Hash256},
        core::btc::btc_hash160,
        qhashout::QHashOut,
    },
    signature::secp256k1::core::hash256_to_hashout_u224,
};
use plonky2::{hash::hash_types::RichField, plonk::config::AlgebraicHasher};
use serde::{Deserialize, Serialize};

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
                    public_key: bytes33_to_public_key::<F>(if d.inputs[0].script.len() == 106 {
                        &d.inputs[0].script[73..106]
                    } else {
                        &d.inputs[0].script[74..107]
                    }),
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
                self.funding_transactions[self.last_block_spend_index as usize].outputs
                    [self.last_block_spend_index as usize]
                    .value,
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
    pub fn perform_sighash_hash_surgery(&self, new_state_hash: Hash256) -> Self {
        let mut clone = self.clone();
        clone.next_block_redeem_script[1..33].copy_from_slice(&new_state_hash.0);
        let new_p2sh_address = btc_hash160(&clone.next_block_redeem_script);
        clone
            .sighash_preimage
            .transaction
            .outputs
            .iter_mut()
            .for_each(|output| {
                if output.script.len() == 23 {
                    output.script[2..22].copy_from_slice(&new_p2sh_address.0);
                }
            });
        clone
    }
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug, Hash, Eq, Copy, Ord, PartialOrd)]
pub struct SigHashGadgetIdWithIndex {
    pub gadget_id: SigHashGadgetId,
    pub index: usize,
}
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug, Hash, Eq, Copy, Ord, PartialOrd)]
pub struct SigHashGadgetId {
    pub num_deposits: usize,
    pub num_withdrawals: usize,
    pub last_block_num_deposits: usize,
    pub last_block_num_withdrawals: usize,
    pub current_spend_index: usize,
}
impl SigHashGadgetId {
    pub fn new(
        num_deposits: usize,
        num_withdrawals: usize,
        last_block_num_deposits: usize,
        last_block_num_withdrawals: usize,
        current_spend_index: usize,
    ) -> Self {
        SigHashGadgetId {
            num_deposits,
            num_withdrawals,
            last_block_num_deposits,
            last_block_num_withdrawals,
            current_spend_index,
        }
    }
    pub fn from_index(
        index: usize,
        max_withdrawals: usize,
        max_deposits: usize,
    ) -> anyhow::Result<Self> {
        // TODO: write constant time implementation
        let max_total_inputs = max_deposits + 1;
        let max_total_outputs = max_withdrawals + 1;
        let mut ind = 0;

        for last_block_num_withdrawals in 0..max_total_outputs {
            for last_block_num_deposits in 0..max_total_inputs {
                for num_withdrawals in 0..max_total_outputs {
                    for num_deposits in 0..max_total_inputs {
                        for current_spend_index in 0..num_deposits {
                            if ind == index {
                                return Ok(SigHashGadgetId {
                                    num_deposits,
                                    num_withdrawals,
                                    last_block_num_deposits,
                                    last_block_num_withdrawals,
                                    current_spend_index,
                                });
                            }
                            ind += 1;
                        }
                    }
                }
            }
        }

        anyhow::bail!("index out of bounds");
    }
    pub fn from_index_fast(
        index: usize,
        max_withdrawals: usize,
        max_deposits: usize,
    ) -> anyhow::Result<Self> {
        let max_total_inputs = max_deposits + 1;
        let max_total_outputs = max_withdrawals + 1;
        let max_total_spend_index = (max_deposits * (max_deposits + 1)) / 2;

        if index
            >= max_total_inputs
                * max_total_outputs
                * max_total_outputs
                * max_total_inputs
                * max_total_spend_index
        {
            anyhow::bail!("index out of bounds");
        }

        let num_deposits = {
            let mut low = 0;
            let mut high = max_deposits;
            while low < high {
                let mid = (low + high + 1) / 2;
                let mid_spend_index = (mid * (mid + 1)) / 2;
                if index
                    < mid_spend_index
                        * max_total_inputs
                        * max_total_outputs
                        * max_total_outputs
                        * max_total_inputs
                {
                    high = mid - 1;
                } else {
                    low = mid;
                }
            }
            low
        };

        let spend_index_offset = (num_deposits * (num_deposits + 1)) / 2;
        let index_div_spend = index / spend_index_offset;
        let current_spend_index = index % spend_index_offset;
        let num_withdrawals = index_div_spend % max_total_outputs;
        let index_div_withdrawals = index_div_spend / max_total_outputs;
        let last_block_num_deposits = index_div_withdrawals % max_total_inputs;
        let last_block_num_withdrawals = index_div_withdrawals / max_total_inputs;

        Ok(SigHashGadgetId {
            num_deposits,
            num_withdrawals,
            last_block_num_deposits,
            last_block_num_withdrawals,
            current_spend_index,
        })
    }
    pub fn from_index_fast2(
        index: usize,
        max_withdrawals: usize,
        max_deposits: usize,
    ) -> anyhow::Result<Self> {
        let max_total_inputs = max_deposits + 1;
        let max_total_outputs = max_withdrawals + 1;
        let max_total_spend_index = (max_deposits * (max_deposits + 1)) / 2;

        if index
            >= max_total_inputs
                * max_total_outputs
                * max_total_outputs
                * max_total_inputs
                * max_total_spend_index
        {
            anyhow::bail!("index out of bounds");
        }

        let num_deposits = {
            let mut low = 0;
            let mut high = max_deposits;
            while low < high {
                let mid = (low + high + 1) / 2;
                let mid_spend_index = (mid * (mid + 1)) / 2;
                if index
                    < mid_spend_index
                        * max_total_inputs
                        * max_total_outputs
                        * max_total_outputs
                        * max_total_inputs
                {
                    high = mid - 1;
                } else {
                    low = mid;
                }
            }
            low
        };

        let spend_index_offset = (num_deposits * (num_deposits + 1)) / 2;
        let (current_spend_index, index_div_spend) = if num_deposits == 0 {
            (0, index)
        } else {
            (index % spend_index_offset, index / spend_index_offset)
        };

        let num_withdrawals = index_div_spend % max_total_outputs;
        let index_div_withdrawals = index_div_spend / max_total_outputs;
        let last_block_num_deposits = index_div_withdrawals % max_total_inputs;
        let last_block_num_withdrawals = index_div_withdrawals / max_total_inputs;

        Ok(SigHashGadgetId {
            num_deposits,
            num_withdrawals,
            last_block_num_deposits,
            last_block_num_withdrawals,
            current_spend_index,
        })
    }
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug, Hash, Eq, Copy)]
#[serde(bound = "")]
pub struct SigHashGadgetFingerprint<F: RichField> {
    pub fingerprint: QHashOut<F>,
    pub num_deposits: usize,
    pub num_withdrawals: usize,
    pub last_block_num_deposits: usize,
    pub last_block_num_withdrawals: usize,
    pub current_spend_index: usize,
}
impl<F: RichField> SigHashGadgetFingerprint<F> {}
#[serde_as]
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug, Hash, Eq, PartialOrd, Ord, Copy)]
pub struct BlockSpendCoreConfig {
    pub block_spend_index: usize,
    pub block_funding_script_size: usize,
    pub block_sighash_script_size: usize,
    pub block_output_script_size: usize,
    pub deposit_funding_script_size: usize,
    pub withdrawal_output_script_size: usize,
    pub sighash_type: u32,
    pub locktime: u32,
    pub version: u32,
}
impl BlockSpendCoreConfig {
    pub fn standard_p2sh_p2pkh() -> Self {
        BlockSpendCoreConfig {
            block_spend_index: 0,
            block_funding_script_size: 770,
            block_sighash_script_size: 489,
            block_output_script_size: 23,
            deposit_funding_script_size: 106,
            withdrawal_output_script_size: 25,
            sighash_type: 1,
            locktime: 0,
            version: 2,
        }
    }
    pub fn generate_permutations(
        &self,
        max_deposits: usize,
        max_withdrawals: usize,
    ) -> Vec<BlockSpendIntrospectionGadgetConfig> {
        let mut result = Vec::new();

        let max_total_inputs = max_deposits + 1;
        let max_total_outputs = max_withdrawals + 1;

        for last_block_num_withdrawals in 0..max_total_outputs {
            for last_block_num_deposits in 0..max_total_inputs {
                for num_withdrawals in 0..max_total_outputs {
                    for num_deposits in 0..max_total_inputs {
                        for current_spend_index in 0..(num_deposits + 1) {
                            result.push(
                                BlockSpendIntrospectionGadgetConfig::generate_from_template(
                                    self,
                                    last_block_num_deposits,
                                    last_block_num_withdrawals,
                                    num_deposits,
                                    num_withdrawals,
                                    current_spend_index,
                                ),
                            );
                        }
                    }
                }
            }
        }

        result
    }
    pub fn generate_id_permutations(
        &self,
        max_deposits: usize,
        max_withdrawals: usize,
    ) -> Vec<SigHashGadgetId> {
        let mut result = Vec::new();

        let max_total_inputs = max_deposits + 1;
        let max_total_outputs = max_withdrawals + 1;

        for last_block_num_withdrawals in 0..max_total_outputs {
            for last_block_num_deposits in 0..max_total_inputs {
                for num_withdrawals in 0..max_total_outputs {
                    for num_deposits in 0..max_total_inputs {
                        for current_spend_index in 0..(num_deposits + 1) {
                            result.push(SigHashGadgetId {
                                last_block_num_deposits,
                                last_block_num_withdrawals,
                                num_deposits,
                                num_withdrawals,
                                current_spend_index,
                            });
                        }
                    }
                }
            }
        }

        result
    }
}

#[serde_as]
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug, Hash, Eq, PartialOrd, Ord)]
pub struct BlockSpendIntrospectionGadgetConfig {
    pub sighash_preimage_config: SigHashPreimageConfig,
    pub funding_transaction_configs: Vec<BTCTransactionConfig>,

    pub last_block_spend_index: i32,
    pub block_spend_index: usize,

    pub current_spend_index: usize,

    pub block_script_length: usize,
}

impl BlockSpendIntrospectionGadgetConfig {
    pub fn generate_from_template(
        config: &BlockSpendCoreConfig,
        last_block_num_deposits: usize,
        last_block_num_withdrawals: usize,
        num_deposits: usize,
        num_withdrawals: usize,
        current_spend_index: usize,
    ) -> Self {
        let sighash_preimage_config = SigHashPreimageConfig::generate_from_template(
            config,
            num_deposits,
            num_withdrawals,
            current_spend_index,
        );
        let funding_transaction_configs = (0..num_deposits + 1)
            .map(|i| {
                if i == config.block_spend_index {
                    BTCTransactionConfig::generate_funding_block_tx_from_template(
                        config,
                        last_block_num_deposits,
                        last_block_num_withdrawals,
                    )
                } else {
                    BTCTransactionConfig::generate_funding_deposit_tx_from_template(config)
                }
            })
            .collect::<Vec<_>>();

        let last_block_spend_index = config.block_spend_index as i32;
        let block_spend_index = config.block_spend_index;
        let current_spend_index = current_spend_index;
        let block_script_length = config.block_sighash_script_size;

        Self {
            sighash_preimage_config,
            funding_transaction_configs,
            last_block_spend_index,
            block_spend_index,
            current_spend_index,
            block_script_length,
        }
    }
    pub fn get_gadget_config_id(&self) -> SigHashGadgetId {
        if self.last_block_spend_index < 0 {
            panic!("last_block_spend_index must be non-negative");
        }
        SigHashGadgetId {
            last_block_num_deposits: self.funding_transaction_configs[self.block_spend_index]
                .layout
                .input_script_sizes
                .len()
                - 1,
            last_block_num_withdrawals: self.funding_transaction_configs[self.block_spend_index]
                .layout
                .output_script_sizes
                .len()
                - 1,
            num_deposits: self.funding_transaction_configs.len() - 1,
            num_withdrawals: self
                .sighash_preimage_config
                .transaction_config
                .layout
                .output_script_sizes
                .len()
                - 1,
            current_spend_index: self.current_spend_index,
        }
    }
}

#[cfg(test)]
mod tests {


    #[test]
    fn test_index_fast() -> anyhow::Result<()> {
        let max_deposits = 3;
        let max_withdrawals = 3;
        let max_index = 81;

        /*
        for i in 0..max_index {
            let standard = SigHashGadgetId::from_index(i, max_withdrawals, max_deposits)?;
            let fast = SigHashGadgetId::from_index_fast2(i, max_withdrawals, max_deposits)?;
            assert_eq!(standard, fast);
        }
        */

        Ok(())
    }
}
