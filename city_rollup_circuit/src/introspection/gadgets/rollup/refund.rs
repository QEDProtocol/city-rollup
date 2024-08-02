use city_common_circuit::{
    builder::{core::CircuitBuilderHelpersCore, signature::CircuitBuilderSignatureHelpers},
    hash::{
        accelerator::sha256::planner::{
            Sha256AcceleratorDomain, Sha256AcceleratorDomainID, Sha256AcceleratorDomainPlanner,
            Sha256AcceleratorDomainResolver,
        },
        base_types::{
            felthash248::CircuitBuilderFelt248Hash, felthash252::CircuitBuilderFelt252Hash, hash160bytes::Hash160BytesTarget, hash256bytes::{CircuitBuilderHash256Bytes, Hash256BytesTarget}
        },
    },
};
use city_rollup_common::introspection::rollup::{
    introspection::{RefundIntrospectionGadgetConfig, RefundSpendIntrospectionHint},
    introspection_result::BTCRollupRefundIntrospectionResult,
};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::{target::Target, witness::Witness},
    plonk::circuit_builder::CircuitBuilder,
};

use crate::introspection::gadgets::{
    rollup::{
        introspection::ensure_output_script_is_p2pkh,
        introspection_result::{
            BTCRollupIntrospectionResultDepositGadget, BTCRollupIntrospectionResultWithdrawalGadget,
        },
        refund_result::BTCRollupRefundIntrospectionResultGadget,
    },
    sighash::SigHashPreimageBytesGadget,
    transaction::BTCTransactionBytesGadget,
};

#[derive(Debug, Clone)]
pub struct BTCRollupRefundIntrospectionGadget {
    pub sighash_preimage: SigHashPreimageBytesGadget,
    pub funding_transaction: BTCTransactionBytesGadget,

    pub current_state_hash: HashOutTarget,

    pub current_script: Vec<Target>,
    pub current_sighash: Hash256BytesTarget,

    pub public_key: [Target; 9],
    pub public_key_hash160_bytes: Hash160BytesTarget,

    pub hash_domain: Sha256AcceleratorDomain,
    pub hash_domain_id: Sha256AcceleratorDomainID,
}

impl BTCRollupRefundIntrospectionGadget {
    pub fn add_virtual_to<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        config: &RefundIntrospectionGadgetConfig,
    ) -> Self {
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
        eprintln!(
            "DEBUGPRINT[1]: refund.rs:74: sighash_preimage_bytes={:#?}",
            sighash_preimage_bytes
        );

        // end sig hash

        // start funding transactions

        let funding_transaction =
            BTCTransactionBytesGadget::add_virtual_to_fixed_locktime_version_with_der(
                builder,
                config.funding_transaction_config.layout.clone(),
                config.funding_transaction_config.version,
                config.funding_transaction_config.locktime,
                false,
                true,
            );

        // end funding transactions

        assert_eq!(
            sighash_preimage.transaction.inputs.len(),
            1,
            "you can only refund your own deposit"
        );
        assert_eq!(
            sighash_preimage.transaction.outputs.len(),
            1,
            "you can only send your refund back to yourself"
        );

        let current_script = sighash_preimage.transaction.inputs[0].script.clone();

        funding_transaction.connect_to_hash_deposit(
            builder,
            &mut hash_domain,
            sighash_preimage.transaction.inputs[0].hash,
            true,
        );

        let public_key: [Target; 9] = if funding_transaction.inputs[0].script.len() == 106 {
            builder.bytes33_to_public_key(&funding_transaction.inputs[0].script[73..106])
        } else {
            builder.bytes33_to_public_key(&funding_transaction.inputs[0].script[74..107])
        };
        eprintln!("DEBUGPRINT[1]: refund.rs:113: public_key={:#?}", public_key);

        // ensure the refund is sent to the sender
        let output_public_key_hash =
            ensure_output_script_is_p2pkh(builder, &sighash_preimage.transaction.outputs[0].script);
        // let input_public_key_hash = hash_domain.btc_hash160(builder, &public_key);
        // builder.connect_hash160_bytes(output_public_key_hash, input_public_key_hash);
        //
        let current_state_hash_bytes: Hash256BytesTarget =
            core::array::from_fn(|i| current_script[i + 1]);
        let current_state_hash = builder.hash256_bytes_to_felt248_hashout(current_state_hash_bytes);

        let result = Self {
            sighash_preimage,
            funding_transaction,
            current_script,
            hash_domain,
            current_sighash,
            public_key,
            public_key_hash160_bytes: output_public_key_hash,
            hash_domain_id: 0xffffffff,
            current_state_hash
        };

        result
    }

    pub fn get_deposits<F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Vec<BTCRollupIntrospectionResultDepositGadget> {
        let funding_tx = &self.funding_transaction;
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
        let public_key = if funding_tx.inputs[0].script.len() == 106 {
            builder.bytes33_to_public_key(&funding_tx.inputs[0].script[73..106])
        } else {
            builder.bytes33_to_public_key(&funding_tx.inputs[0].script[74..107])
        };
        let txid_224 =
            builder.hash256_bytes_to_hashout224(self.sighash_preimage.transaction.inputs[0].hash);

        vec![BTCRollupIntrospectionResultDepositGadget {
            txid_224,
            public_key,
            value: funding_tx.outputs[0].get_value_target_u64(builder),
        }]
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
            .filter_map(|(_, output)| {
                assert_eq!(
                    output.script.len(),
                    25,
                    "withdrawals should be to a p2pkh address",
                );
                ensure_output_script_is_p2pkh(builder, &output.script);
                Some(BTCRollupIntrospectionResultWithdrawalGadget {
                    script: output.script.clone(),
                    value: output.get_value_target_u64(builder),
                })
            })
            .collect()
    }

    pub fn generate_result<F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> BTCRollupRefundIntrospectionResultGadget {
        let deposits = self.get_deposits(builder);
        let withdrawals = self.get_withdrawals(builder);
        let sighash_felt252 = builder.hash256_bytes_to_felt252_hashout_packed(self.current_sighash);

        BTCRollupRefundIntrospectionResultGadget {
            deposits,
            withdrawals,
            sighash: self.current_sighash,
            sighash_felt252,
            current_block_state_hash: self.current_state_hash,
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
        hint: &RefundSpendIntrospectionHint,
        result: &BTCRollupRefundIntrospectionResult<F>,
    ) {
        witness.set_target_arr(&self.public_key, &result.deposits[0].public_key);
        eprintln!(
            "DEBUGPRINT[2]: refund.rs:159: result.deposits[0].public_key={:#?}",
            result.deposits[0].public_key
        );

        self.sighash_preimage
            .transaction
            .set_witness(witness, &hint.sighash_preimage.transaction);

        self.funding_transaction
            .set_witness(witness, &hint.funding_transaction);
        eprintln!(
            "DEBUGPRINT[1]: refund.rs:168: &hint.funding_transaction={:#?}",
            &hint.funding_transaction
        );
        if self.hash_domain_id == 0xffffffff {
            panic!("cannot set witness for a BTCRollupIntrospectionGadget that has not been finalized!");
        }
        dr.set_witness_for_domain(self.hash_domain_id, &[]);
    }

    pub fn get_sighash_felt252<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> HashOutTarget {
        builder.hash256_bytes_to_felt252_hashout_packed(self.current_sighash)
    }
}
