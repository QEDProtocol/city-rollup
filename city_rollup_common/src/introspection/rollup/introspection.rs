use city_crypto::{
    field::conversions::bytes33_to_public_key,
    hash::{base_types::felt252::hash256_le_to_felt252_hashout, qhashout::QHashOut},
};
use plonky2::{hash::hash_types::RichField, plonk::config::AlgebraicHasher};
use serde::{Deserialize, Serialize};

use serde_with::serde_as;

use crate::introspection::{
    sighash::{SigHashPreimage, SigHashPreimageConfig},
    transaction::{BTCTransaction, BTCTransactionConfig},
};

use super::{
    introspection_result::{
        BTCRollupIntrospectionResult, BTCRollupIntrospectionResultDeposit,
        BTCRollupIntrospectionResultWithdrawal,
    },
    signature::hash256_to_hashout_u224,
};

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
                        self.sighash_preimage.transaction.inputs[self.current_spend_index].hash,
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
