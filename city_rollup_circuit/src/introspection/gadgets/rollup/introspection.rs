use city_common::logging::trace_timer::TraceTimer;
use city_common_circuit::{builder::{connect::CircuitBuilderConnectHelpers, core::{CircuitBuilderHelpersCore, WitnessHelpersCore}, select::CircuitBuilderSelectHelpers, signature::CircuitBuilderSignatureHelpers}, hash::{accelerator::sha256::planner::{Sha256AcceleratorDomain, Sha256AcceleratorDomainID, Sha256AcceleratorDomainPlanner, Sha256AcceleratorDomainResolver}, base_types::{felthash248::CircuitBuilderFelt248Hash, felthash252::CircuitBuilderFelt252Hash, hash160bytes::Hash160BytesTarget, hash256bytes::{CircuitBuilderHash256Bytes, Hash256BytesTarget}}}};
use city_rollup_common::{block_template::config::{GENESIS_STATE_HASH, OP_CHECKGROTH16VERIFY, OP_CHECKGROTH16VERIFY_NOP}, introspection::rollup::introspection::{BlockSpendIntrospectionGadgetConfig, BlockSpendIntrospectionHint}};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::{target::Target, witness::Witness},
    plonk::circuit_builder::CircuitBuilder,
};


use crate::introspection::gadgets::{sighash::SigHashPreimageBytesGadget, transaction::BTCTransactionBytesGadget};

use super::introspection_result::{
    BTCRollupIntrospectionResultDepositGadget, BTCRollupIntrospectionResultGadget,
    BTCRollupIntrospectionResultWithdrawalGadget,
};

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
        for (i, funding_tx_config) in config.funding_transaction_configs.iter().enumerate() {
            trace_timer.event(format!(
                "funding_tx_config: {:?}",
                funding_tx_config.layout.input_script_sizes
            ));

            let funding_tx = if i != config.block_spend_index {
                BTCTransactionBytesGadget::add_virtual_to_fixed_locktime_version_with_der(
                builder,
                funding_tx_config.layout.clone(),
                funding_tx_config.version,
                funding_tx_config.locktime,
                false,
                true,
            )
        }else{
            BTCTransactionBytesGadget::add_virtual_to_fixed_locktime_version(
                builder,
                funding_tx_config.layout.clone(),
                funding_tx_config.version,
                funding_tx_config.locktime,
                false,
            )
        };
            funding_transactions.push(funding_tx);
        }
        // end funding transactions

        let current_script = sighash_preimage.transaction.inputs[config.current_spend_index]
            .script
            .clone();

        // start next redeem script
        tracing::info!("config.block_script_length: {}", config.block_script_length);
        let next_block_redeem_script = builder.add_virtual_targets(config.block_script_length);
        let next_block_redeem_script_hash =
            hash_domain.btc_hash160(builder, &next_block_redeem_script);
        assert_eq!(current_script.len(), next_block_redeem_script.len());
        // end next redeem script

        let current_state_hash_bytes: Hash256BytesTarget =
            core::array::from_fn(|i| current_script[i + 1]);

        let current_state_hash = builder.hash256_bytes_to_felt248_hashout(current_state_hash_bytes);

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
/*


        OP_CHECKGROTH16VERIFY, // len-8
        OP_2DROP, // len-7
        OP_2DROP, // len-6
        OP_2DROP, // len-5
        OP_2DROP, // len-4
        OP_2DROP, // len-3
        OP_2DROP, // len-2
        OP_1 // len-1

*/

        // ensure the first byte is push 32 followed by state
        builder.connect_constant(script[offset], 32);


        // ensure the body of the current script is the same as the target script except for the groth16 verify
        builder.connect_vec(&self.current_script[33..], &script[(offset + 33)..]);
    }
    pub fn ensure_script_is_funding_block_script<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        script: &[Target],
        offset: usize,
    ) {

        if self.funding_transactions.len() == 1 {
            assert_eq!(script.len(), self.current_script.len() + offset);
    /*


            OP_CHECKGROTH16VERIFY, // len-8
            OP_2DROP, // len-7
            OP_2DROP, // len-6
            OP_2DROP, // len-5
            OP_2DROP, // len-4
            OP_2DROP, // len-3
            OP_2DROP, // len-2
            OP_1 // len-1

    */
            let current_script_check_proof_op_code_index = self.current_script.len()-8;
            let script_check_proof_op_code_index = script.len()-8;
            // const_concat_arrays!([OP_PUSHBYTES_32], <STATE_HASH>, STANDARD_BLOCK_SCRIPT_BODY);

            // ensure the first byte is push 32 followed by state
            builder.connect_constant(script[offset], 32);
            let current_script_state_hash_index = 1;
            let script_state_hash_index = offset + 1;


            // ensure the body of the current script is the same as the target script except for the groth16 verify
            builder.connect_vec(&self.current_script[33..current_script_check_proof_op_code_index], &script[(offset + 33)..script_check_proof_op_code_index]);
            builder.connect_vec(&self.current_script[(current_script_check_proof_op_code_index+1)..], &script[(script_check_proof_op_code_index+1)..]);

            // if the prev tx input is a single genesis spend, then allow for a NOP proof verify for the previous proof
            let genesis_state_hash_256: Hash256BytesTarget = builder.constant_hash256_bytes(&GENESIS_STATE_HASH);
            let _current_script_state_hash : Hash256BytesTarget = core::array::from_fn(|i| self.current_script[i + current_script_state_hash_index]);
            let script_state_hash : Hash256BytesTarget = core::array::from_fn(|i| script[i + script_state_hash_index]);
            let is_prev_script_genesis = builder.is_equal_hash_256_bytes(script_state_hash, genesis_state_hash_256);
            let op_check_groth16_verify_op = builder.constant_u8(OP_CHECKGROTH16VERIFY);
            let op_check_groth16_verify_nop_op = builder.constant_u8(OP_CHECKGROTH16VERIFY_NOP);

            let is_prev_script_op_groth16_verify = builder.is_equal(script[script_check_proof_op_code_index], op_check_groth16_verify_op);
            let is_prev_script_op_groth16_verify_nop = builder.is_equal(script[script_check_proof_op_code_index], op_check_groth16_verify_nop_op);
            let is_prev_script_op_groth16_verify_or_nop = builder.or(is_prev_script_op_groth16_verify, is_prev_script_op_groth16_verify_nop);
            let is_prev_script_genesis_and_op_groth16_verify_or_nop = builder.and(is_prev_script_genesis, is_prev_script_op_groth16_verify_or_nop);
            // (is_prev_script_op_groth16_verify || (is_prev_script_genesis && op_groth16_verify_or_nop))
            let is_prev_script_valid_op = builder.or(is_prev_script_op_groth16_verify, is_prev_script_genesis_and_op_groth16_verify_or_nop);
            let one = builder.one();
            builder.connect(is_prev_script_valid_op.target, one);


            builder.connect(self.current_script[current_script_check_proof_op_code_index], op_check_groth16_verify_op);
        }else{
            self.ensure_script_is_block_script(builder, script, offset)
        }
    }
    pub fn ensure_block_script_transition<F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
    ) {
        // first byte of the script should push 32 bytes for the public input
        builder.connect_constant(self.current_script[0], 32);
        self.ensure_script_is_block_script(builder, &self.next_block_redeem_script, 0);

        if self.last_block_spend_index != -1 {
            self.ensure_script_is_funding_block_script(
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
            .for_each(|(i, (funding_tx, spend_tx))| {
                if i != self.block_spend_index {
                    // deposit, use der pad
                    funding_tx.connect_to_hash_deposit(builder, &mut self.hash_domain, spend_tx.hash, true)
                }else{

                    let funding_tx_bytes = funding_tx.to_byte_targets(builder);
                    let funding_tx_hash = self.hash_domain.btc_hash256(builder, &funding_tx_bytes);
                    // ensure the funding transaction provided is actually the transaction that funded this utxo
                    builder.connect_hash256_bytes(funding_tx_hash, spend_tx.hash);
                }
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

                    // todo: support length 107 signatures
                    assert_eq!(
                        funding_tx.inputs[0].script.len(),
                        106,
                        "the input script for a deposit should be a p2pkh signature + public key reveal"
                    );
                    let public_key = if funding_tx.inputs[0].script.len() == 106 {
                        builder.bytes33_to_public_key(&funding_tx.inputs[0].script[73..106])
                    }else{
                        builder.bytes33_to_public_key(&funding_tx.inputs[0].script[74..107])
                    };
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
            self.funding_transactions[self.block_spend_index].outputs
                [self.last_block_spend_index as usize]
                .get_value_target_u64(builder)
        } else {
            builder.zero()
        };
        let next_block_rollup_balance = self.sighash_preimage.transaction.outputs
            [self.block_spend_index]
            .get_value_target_u64(builder);
        let sighash_felt252 = builder.hash256_bytes_to_felt252_hashout_packed(self.current_sighash);

        let next_block_state_hash = builder.hash256_bytes_to_felt248_hashout(self.next_block_redeem_script[1..33].try_into().unwrap());
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
