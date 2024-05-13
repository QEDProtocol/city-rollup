use city_common::logging::trace_timer::TraceTimer;
use city_common_circuit::builder::connect::CircuitBuilderConnectHelpers;
use city_common_circuit::builder::core::CircuitBuilderHelpersCore;
use city_common_circuit::builder::core::WitnessHelpersCore;
use city_common_circuit::builder::signature::CircuitBuilderSignatureHelpers;
use city_common_circuit::hash::accelerator::sha256::planner::Sha256AcceleratorDomain;
use city_common_circuit::hash::accelerator::sha256::planner::Sha256AcceleratorDomainID;
use city_common_circuit::hash::accelerator::sha256::planner::Sha256AcceleratorDomainPlanner;
use city_common_circuit::hash::accelerator::sha256::planner::Sha256AcceleratorDomainResolver;
use city_common_circuit::hash::base_types::felthash252::CircuitBuilderFelt252Hash;
use city_common_circuit::hash::base_types::hash160bytes::Hash160BytesTarget;
use city_common_circuit::hash::base_types::hash256bytes::CircuitBuilderHash256Bytes;
use city_common_circuit::hash::base_types::hash256bytes::Hash256BytesTarget;
use city_rollup_common::introspection::rollup::introspection::BlockSpendIntrospectionGadgetConfig;
use city_rollup_common::introspection::rollup::introspection::BlockSpendIntrospectionHint;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::iop::witness::Witness;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use super::introspection_result::BTCRollupIntrospectionResultDepositGadget;
use super::introspection_result::BTCRollupIntrospectionResultGadget;
use super::introspection_result::BTCRollupIntrospectionResultWithdrawalGadget;
use crate::introspection::gadgets::sighash::SigHashPreimageBytesGadget;
use crate::introspection::gadgets::transaction::BTCTransactionBytesGadget;

#[derive(Debug, Clone)]
pub struct BTCRollupIntrospectionGadget {
    pub sighash_preimage: SigHashPreimageBytesGadget,
    pub funding_transactions: Vec<BTCTransactionBytesGadget>,

    pub current_script: Vec<Target>,

    pub last_block_spend_index: i32,
    pub block_spend_index: usize,

    pub current_spend_index: usize,

    pub next_block_redeem_script: Vec<Target>,
    pub next_block_redeem_script_hash: Hash160BytesTarget,
    pub current_sighash: Hash256BytesTarget,

    pub hash_domain: Sha256AcceleratorDomain,
    pub hash_domain_id: Sha256AcceleratorDomainID,
    pub current_state_hash: HashOutTarget,
}

impl BTCRollupIntrospectionGadget {
    pub fn add_virtual_to<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        config: &BlockSpendIntrospectionGadgetConfig,
    ) -> Self {
        let mut trace_timer = TraceTimer::new("BTCRollupIntrospectionGadget");

        let mut hash_domain = Sha256AcceleratorDomain::new();

        // start sig hash
        let sighash_tx = BTCTransactionBytesGadget::add_virtual_to_fixed_locktime_version(
            builder,
            config
                .sighash_preimage_config
                .transaction_config
                .layout
                .clone(),
            config.sighash_preimage_config.transaction_config.version,
            config.sighash_preimage_config.transaction_config.locktime,
            false,
        );

        let sighash_type_bytes =
            builder.constant_u32_bytes_le(config.sighash_preimage_config.sighash_type);

        let sighash_preimage = SigHashPreimageBytesGadget::add_virtual_to_from_tx(
            builder,
            sighash_tx,
            sighash_type_bytes,
        );
        let sighash_preimage_bytes = &sighash_preimage.to_byte_targets(builder);
        let current_sighash = hash_domain.btc_hash256(builder, &sighash_preimage_bytes);

        // end sig hash

        // start funding transactions

        let mut funding_transactions = Vec::with_capacity(config.funding_transaction_configs.len());
        for funding_tx_config in config.funding_transaction_configs.iter() {
            trace_timer.event(format!(
                "funding_tx_config: {:?}",
                funding_tx_config.layout.input_script_sizes
            ));

            let funding_tx = BTCTransactionBytesGadget::add_virtual_to_fixed_locktime_version(
                builder,
                funding_tx_config.layout.clone(),
                funding_tx_config.version,
                funding_tx_config.locktime,
                false,
            );
            funding_transactions.push(funding_tx);
        }
        // end funding transactions

        let current_script = sighash_preimage.transaction.inputs[config.current_spend_index]
            .script
            .clone();

        // start next redeem script
        println!("config.block_script_length: {}", config.block_script_length);
        let next_block_redeem_script = builder.add_virtual_targets(config.block_script_length);
        let next_block_redeem_script_hash =
            hash_domain.btc_hash160(builder, &next_block_redeem_script);
        assert_eq!(current_script.len(), next_block_redeem_script.len());
        // end next redeem script

        let current_state_hash_bytes: Hash256BytesTarget =
            core::array::from_fn(|i| current_script[i + 1]);

        let current_state_hash = builder.hash256_bytes_to_felt252_hashout(current_state_hash_bytes);

        assert_eq!(
            funding_transactions.len(),
            sighash_preimage.transaction.inputs.len()
        );
        let mut result = Self {
            sighash_preimage,
            current_spend_index: config.current_spend_index,
            last_block_spend_index: config.last_block_spend_index,
            block_spend_index: config.block_spend_index,
            funding_transactions,
            next_block_redeem_script,
            next_block_redeem_script_hash,
            current_script,
            hash_domain,
            current_state_hash,
            current_sighash,
            hash_domain_id: 0xffffffff,
        };
        result.ensure_funding_transactions(builder);
        result.ensure_block_script_transition(builder);

        result
    }
    pub fn ensure_script_is_block_script<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        script: &[Target],
        offset: usize,
    ) {
        assert_eq!(script.len(), self.current_script.len() + offset);

        // ensure the first byte is push 32 followed by state
        builder.connect_constant(script[offset], 32);

        // ensure the body of the current script is the same as the target script
        builder.connect_vec(&self.current_script[33..], &script[(offset + 33)..]);
    }
    pub fn ensure_block_script_transition<F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
    ) {
        // first byte of the script should push 32 bytes for the public input
        builder.connect_constant(self.current_script[0], 32);
        self.ensure_script_is_block_script(builder, &self.next_block_redeem_script, 0);

        if self.last_block_spend_index != -1 {
            self.ensure_script_is_block_script(
                builder,
                &self.funding_transactions[self.last_block_spend_index as usize].inputs[0].script,
                281,
            );
        }
        let next_block_p2sh =
            &self.sighash_preimage.transaction.outputs[self.block_spend_index].script;

        assert_eq!(
            next_block_p2sh.len(),
            23,
            "outputs[block_spend_index].script should be a 23 byte p2sh script"
        );

        // ensure next block output is OP_HASH160 <script hash> OP_EQUAL
        builder.connect_templated_array(
            &[0xa9, 0x14],
            &self.next_block_redeem_script_hash,
            &[0x87],
            next_block_p2sh,
        );
    }

    pub fn ensure_funding_transactions<F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
    ) {
        assert_eq!(
            self.funding_transactions.len(),
            self.sighash_preimage.transaction.inputs.len()
        );
        self.funding_transactions
            .iter()
            .zip(self.sighash_preimage.transaction.inputs.iter())
            .enumerate()
            .for_each(|(_, (funding_tx, spend_tx))| {
                let funding_tx_bytes = funding_tx.to_byte_targets(builder);
                let funding_tx_hash = self.hash_domain.btc_hash256(builder, &funding_tx_bytes);
                // ensure the funding transaction provided is actually the transaction that
                // funded this utxo
                builder.connect_hash256_bytes(funding_tx_hash, spend_tx.hash);
            });
    }
    pub fn get_deposits<F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Vec<BTCRollupIntrospectionResultDepositGadget> {
        self.funding_transactions
            .iter()
            .enumerate()
            .filter_map(|(i, funding_tx)| {
                if (i as i32) != self.last_block_spend_index {
                    assert_eq!(
                        funding_tx.inputs.len(),
                        1,
                        "deposits should only have one input (p2pkh)"
                    );
                    assert_eq!(
                        funding_tx.outputs.len(),
                        1,
                        "deposits should only have one output (send to layer 2)"
                    );
                    assert_eq!(
                        funding_tx.inputs[0].script.len(),
                        106,
                        "the input script for a deposit should be a p2pkh signature + public key reveal"
                    );
                    let public_key =
                        builder.bytes33_to_public_key(&funding_tx.inputs[0].script[73..106]);
                    let txid_224 = builder.hash256_bytes_to_hashout224(self.sighash_preimage.transaction.inputs[i].hash);

                    Some(BTCRollupIntrospectionResultDepositGadget {
                        txid_224,
                        public_key,
                        value: funding_tx.outputs[0].get_value_target_u64(builder),
                    })
                } else {
                    None
                }
            })
            .collect()
    }
    pub fn get_withdrawals<F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Vec<BTCRollupIntrospectionResultWithdrawalGadget> {
        self.sighash_preimage
            .transaction
            .outputs
            .iter()
            .enumerate()
            .filter_map(|(i, output)| {
                if i != self.block_spend_index {
                    assert_eq!(
                        output.script.len(),
                        25,
                        "withdrawals should be to a p2pkh address",
                    );
                    Some(BTCRollupIntrospectionResultWithdrawalGadget {
                        script: output.script.clone(),
                        value: output.get_value_target_u64(builder),
                    })
                } else {
                    None
                }
            })
            .collect()
    }
    pub fn generate_result<F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> BTCRollupIntrospectionResultGadget {
        let deposits = self.get_deposits(builder);
        let withdrawals = self.get_withdrawals(builder);
        let current_block_rollup_balance = if self.last_block_spend_index != -1 {
            self.funding_transactions[self.last_block_spend_index as usize].outputs[0]
                .get_value_target_u64(builder)
        } else {
            builder.zero()
        };
        let next_block_rollup_balance = self.sighash_preimage.transaction.outputs
            [self.block_spend_index]
            .get_value_target_u64(builder);
        let sighash_felt252 = builder.hash256_bytes_to_felt252_hashout(self.current_sighash);

        let next_block_state_hash = builder.hash256_bytes_to_felt252_hashout(
            self.next_block_redeem_script[1..33].try_into().unwrap(),
        );
        BTCRollupIntrospectionResultGadget {
            deposits,
            withdrawals,
            current_block_state_hash: self.current_state_hash,
            next_block_state_hash,
            current_block_rollup_balance,
            next_block_rollup_balance: next_block_rollup_balance,
            spend_index: self.current_spend_index,
            sighash: self.current_sighash,
            sighash_felt252,
        }
    }

    pub fn finalize<F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        _builder: &mut CircuitBuilder<F, D>,
        dp: &mut Sha256AcceleratorDomainPlanner,
    ) {
        self.hash_domain_id = dp.register_domain(&self.hash_domain);
    }

    pub fn set_witness<
        W: Witness<F>,
        F: RichField + Extendable<D>,
        const D: usize,
        DR: Sha256AcceleratorDomainResolver,
    >(
        &self,
        witness: &mut W,
        dr: &mut DR,
        hint: &BlockSpendIntrospectionHint,
    ) {
        self.sighash_preimage
            .transaction
            .set_witness(witness, &hint.sighash_preimage.transaction);
        witness.set_byte_targets(
            &self.next_block_redeem_script,
            &hint.next_block_redeem_script,
        );
        self.funding_transactions
            .iter()
            .zip(hint.funding_transactions.iter())
            .for_each(|(funding_tx, hint_tx)| {
                funding_tx.set_witness(witness, hint_tx);
            });
        if self.hash_domain_id == 0xffffffff {
            panic!("cannot set witness for a BTCRollupIntrospectionGadget that has not been finalized!");
        }
        dr.set_witness_for_domain(self.hash_domain_id, &[]);
    }
}
