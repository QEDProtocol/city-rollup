use city_common_circuit::{builder::hash::core::CircuitBuilderHashCore, hash::base_types::hash256bytes::Hash256BytesTarget};
use city_rollup_common::introspection::rollup::introspection_result::BTCRollupRefundIntrospectionFinalizedResult;
use plonky2::{field::extension::Extendable, hash::hash_types::{HashOutTarget, RichField}, iop::witness::Witness, plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher}};

use crate::introspection::gadgets::rollup::introspection_result::{get_introspection_events_hash_circuit, BTCRollupIntrospectionResultDepositGadget, BTCRollupIntrospectionResultWithdrawalGadget};

#[derive(Debug, Clone)]
pub struct BTCRollupRefundIntrospectionResultGadget {
    pub deposits: Vec<BTCRollupIntrospectionResultDepositGadget>,
    pub withdrawals: Vec<BTCRollupIntrospectionResultWithdrawalGadget>,

    pub current_block_state_hash: HashOutTarget,

    pub sighash: Hash256BytesTarget,
    pub sighash_felt252: HashOutTarget,
}
impl BTCRollupRefundIntrospectionResultGadget {
    pub fn get_finalized_result<
        H: AlgebraicHasher<F>,
        F: RichField + Extendable<D>,
        const D: usize,
    >(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> BTCRollupRefundIntrospectionFinalizedResultGadget {
        let d_events = self
            .deposits
            .iter()
            .map(|deposit| deposit.get_hash::<H, F, D>(builder))
            .collect::<Vec<_>>();
        let deposits_hash = get_introspection_events_hash_circuit::<H, F, D>(builder, &d_events);
        let w_events = self
            .withdrawals
            .iter()
            .map(|withdrawal| withdrawal.get_hash::<H, F, D>(builder))
            .collect::<Vec<_>>();
        let withdrawals_hash = get_introspection_events_hash_circuit::<H, F, D>(builder, &w_events);

        BTCRollupRefundIntrospectionFinalizedResultGadget {
            deposits_hash,
            withdrawals_hash,
            current_block_state_hash: self.current_block_state_hash
        }
    }
}

#[derive(Debug, Clone)]
pub struct BTCRollupRefundIntrospectionFinalizedResultGadget {
    pub deposits_hash: HashOutTarget,
    pub withdrawals_hash: HashOutTarget,
    pub current_block_state_hash: HashOutTarget,
}

impl BTCRollupRefundIntrospectionFinalizedResultGadget {
    pub fn add_virtual_to<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let deposits_hash = builder.add_virtual_hash();
        let withdrawals_hash = builder.add_virtual_hash();
        let current_block_state_hash = builder.add_virtual_hash();
        Self {
            deposits_hash,
            withdrawals_hash,
            current_block_state_hash
        }
    }
    pub fn get_combined_hash<
        H: AlgebraicHasher<F>,
        F: RichField + Extendable<D>,
        const D: usize,
    >(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> HashOutTarget {
        let deposits_withdrawals_hash =
            builder.hash_two_to_one::<H>(self.deposits_hash, self.withdrawals_hash);

        let combined_hash = builder.hash_n_to_hash_no_pad::<H>(vec![
            self.current_block_state_hash.elements[0],
            self.current_block_state_hash.elements[1],
            self.current_block_state_hash.elements[2],
            self.current_block_state_hash.elements[3],
            deposits_withdrawals_hash.elements[0],
            deposits_withdrawals_hash.elements[1],
            deposits_withdrawals_hash.elements[2],
            deposits_withdrawals_hash.elements[3],
        ]);
        combined_hash
    }
    pub fn set_witness<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        result: &BTCRollupRefundIntrospectionFinalizedResult<F>,
    ) {
        witness.set_hash_target(self.deposits_hash, result.deposits_hash.0);
        witness.set_hash_target(self.withdrawals_hash, result.withdrawals_hash.0);
        witness.set_hash_target(self.current_block_state_hash, result.current_block_state_hash.0);
    }
}
