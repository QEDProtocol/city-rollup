use city_common_circuit::{
    builder::{core::CircuitBuilderHelpersCore, hash::core::CircuitBuilderHashCore},
    debug::circuit_tracer::DebugCircuitTracer,
    hash::{
        base_types::hash256bytes::Hash256BytesTarget,
        merkle::partial::compute_partial_merkle_root_from_leaves_algebraic_circuit,
    },
};
use city_rollup_common::introspection::rollup::introspection_result::{
    BTCRollupIntrospectionFinalizedResult, BTCRollupIntrospectionResultDeposit,
    WITHDRAWAL_TYPE_P2PKH, WITHDRAWAL_TYPE_P2SH,
};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::{target::Target, witness::Witness},
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};

#[derive(Debug, Clone)]
pub struct BTCRollupIntrospectionResultDepositGadget {
    pub public_key: [Target; 9],
    pub txid_224: HashOutTarget,
    pub value: Target,
}
impl BTCRollupIntrospectionResultDepositGadget {
    pub fn add_virtual_to<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let public_key = builder.add_virtual_target_arr();
        let txid_224 = builder.add_virtual_hash();
        let value = builder.add_virtual_target();
        Self {
            public_key,
            txid_224,
            value,
        }
    }
    pub fn get_hash<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> HashOutTarget {
        builder.hash_n_to_hash_no_pad::<H>(
            [
                self.txid_224.elements.to_vec(),
                vec![self.value],
                self.public_key.to_vec(),
            ]
            .concat(),
        )
    }
    pub fn get_hash_trace<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        deposit_index: usize,
        tracer: &mut DebugCircuitTracer,
    ) -> HashOutTarget {
        let preimage = vec![
            self.txid_224.elements.to_vec(),
            vec![self.value],
            self.public_key.to_vec(),
        ]
        .concat();
        tracer.trace_vec_s(format!("deposit_{}_preimage", deposit_index), &preimage);
        let hash = builder.hash_n_to_hash_no_pad::<H>(preimage);
        tracer.trace_hash_s(format!("deposit_{}_hash", deposit_index), hash);
        hash
    }
    pub fn set_witness<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        deposit: &BTCRollupIntrospectionResultDeposit<F>,
    ) {
        witness.set_target_arr(&self.public_key, &deposit.public_key);
        witness.set_target(self.value, deposit.value);
        witness.set_hash_target(self.txid_224, deposit.txid_224.0);
    }
}

#[derive(Debug, Clone)]
pub struct BTCRollupIntrospectionResultWithdrawalGadget {
    // p2pkh => 23 bytes
    pub script: Vec<Target>,
    pub value: Target,
}

impl BTCRollupIntrospectionResultWithdrawalGadget {
    pub fn get_hash<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> HashOutTarget {
        //builder.hash_n_to_hash_no_pad::<H>([vec![self.value],
        // self.script.to_vec()].concat())
        let script_length = self.script.len();
        assert!(
            script_length == 23 || script_length == 25,
            "only supports p2sh (length = 23) and p2pkh withdrawals (length = 25), got length = {}",
            script_length
        );
        let withdrawal_type_flag = if script_length == 23 {
            WITHDRAWAL_TYPE_P2SH
        } else {
            WITHDRAWAL_TYPE_P2PKH
        };
        let first_56 = builder.le_bytes_to_u56_target(&self.script[2..9]);
        let mid_56 = builder.le_bytes_to_u56_target(&self.script[9..16]);
        let last_48 = builder.le_bytes_to_u48_target(&self.script[16..22]);
        let last_48_with_flag =
            builder.add_const(last_48, F::from_canonical_u64(withdrawal_type_flag));

        HashOutTarget {
            elements: [self.value, first_56, mid_56, last_48_with_flag],
        }
    }
    pub fn validate_withdrawal_hash_get_amount<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        hash: HashOutTarget,
    ) -> Target {
        let value = hash.elements[0];
        let first_56 = hash.elements[1];
        let mid_56 = hash.elements[2];
        let last_48_with_flag = hash.elements[3];
        builder.range_check(first_56, 56);
        builder.range_check(mid_56, 56);
        // disable p2sh withdrawals for now
        // in the future we can add support by changing n_log in the range check below
        // from 48 to 49
        builder.range_check(last_48_with_flag, 48);
        value
    }
}

pub fn get_introspection_events_hash_circuit<
    H: AlgebraicHasher<F>,
    F: RichField + Extendable<D>,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    events: &[HashOutTarget],
) -> HashOutTarget {
    if events.len() == 0 {
        let zero = builder.zero();
        HashOutTarget {
            elements: [zero, zero, zero, zero],
        }
    } else {
        compute_partial_merkle_root_from_leaves_algebraic_circuit::<H, F, D>(builder, events)
    }
}
#[derive(Debug, Clone)]
pub struct BTCRollupIntrospectionResultGadget {
    pub deposits: Vec<BTCRollupIntrospectionResultDepositGadget>,
    pub withdrawals: Vec<BTCRollupIntrospectionResultWithdrawalGadget>,

    pub current_block_state_hash: HashOutTarget,
    pub next_block_state_hash: HashOutTarget,

    pub current_block_rollup_balance: Target,
    pub next_block_rollup_balance: Target,

    pub spend_index: usize,

    pub sighash: Hash256BytesTarget,
    pub sighash_felt252: HashOutTarget,
}
impl BTCRollupIntrospectionResultGadget {
    pub fn get_finalized_result_trace<
        H: AlgebraicHasher<F>,
        F: RichField + Extendable<D>,
        const D: usize,
    >(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        tracer: &mut DebugCircuitTracer,
    ) -> BTCRollupIntrospectionFinalizedResultGadget {
        let total_withdrawals_count =
            builder.constant(F::from_noncanonical_u64(self.withdrawals.len() as u64));
        let total_deposits_count =
            builder.constant(F::from_noncanonical_u64(self.deposits.len() as u64));
        let d_events = self
            .deposits
            .iter()
            .enumerate()
            .map(|(i, deposit)| deposit.get_hash_trace::<H, F, D>(builder, i, tracer))
            .collect::<Vec<_>>();
        let deposits_hash = get_introspection_events_hash_circuit::<H, F, D>(builder, &d_events);
        let w_events = self
            .withdrawals
            .iter()
            .map(|withdrawal| withdrawal.get_hash::<H, F, D>(builder))
            .collect::<Vec<_>>();
        let withdrawals_hash = get_introspection_events_hash_circuit::<H, F, D>(builder, &w_events);
        let mut total_withdrawals_value: Target = builder.zero();
        for w in self.withdrawals.iter() {
            total_withdrawals_value = builder.add(total_withdrawals_value, w.value);
        }
        let mut total_deposits_value: Target = builder.zero();
        for w in self.deposits.iter() {
            total_deposits_value = builder.add(total_deposits_value, w.value);
        }

        BTCRollupIntrospectionFinalizedResultGadget {
            deposits_hash,
            withdrawals_hash,
            current_block_state_hash: self.current_block_state_hash,
            next_block_state_hash: self.next_block_state_hash,
            total_deposits_count,
            total_withdrawals_count,
            total_deposits_value,
            total_withdrawals_value,
            current_block_rollup_balance: self.current_block_rollup_balance,
            next_block_rollup_balance: self.next_block_rollup_balance,
        }
    }
    pub fn get_finalized_result<
        H: AlgebraicHasher<F>,
        F: RichField + Extendable<D>,
        const D: usize,
    >(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> BTCRollupIntrospectionFinalizedResultGadget {
        let total_withdrawals_count =
            builder.constant(F::from_noncanonical_u64(self.withdrawals.len() as u64));
        let total_deposits_count =
            builder.constant(F::from_noncanonical_u64(self.deposits.len() as u64));
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
        let mut total_withdrawals_value: Target = builder.zero();
        for w in self.withdrawals.iter() {
            total_withdrawals_value = builder.add(total_withdrawals_value, w.value);
        }
        let mut total_deposits_value: Target = builder.zero();
        for w in self.deposits.iter() {
            total_deposits_value = builder.add(total_deposits_value, w.value);
        }

        BTCRollupIntrospectionFinalizedResultGadget {
            deposits_hash,
            withdrawals_hash,
            current_block_state_hash: self.current_block_state_hash,
            next_block_state_hash: self.next_block_state_hash,
            total_deposits_count,
            total_withdrawals_count,
            total_deposits_value,
            total_withdrawals_value,
            current_block_rollup_balance: self.current_block_rollup_balance,
            next_block_rollup_balance: self.next_block_rollup_balance,
        }
    }
}
#[derive(Debug, Clone)]
pub struct BTCRollupIntrospectionFinalizedResultGadget {
    pub deposits_hash: HashOutTarget,
    pub withdrawals_hash: HashOutTarget,

    pub current_block_state_hash: HashOutTarget,
    pub next_block_state_hash: HashOutTarget,

    pub total_deposits_count: Target,
    pub total_withdrawals_count: Target,

    pub total_deposits_value: Target,
    pub total_withdrawals_value: Target,
    pub current_block_rollup_balance: Target,
    pub next_block_rollup_balance: Target,
}

impl BTCRollupIntrospectionFinalizedResultGadget {
    pub fn add_virtual_to<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let deposits_hash = builder.add_virtual_hash();
        let withdrawals_hash = builder.add_virtual_hash();

        let current_block_state_hash = builder.add_virtual_hash();
        let next_block_state_hash = builder.add_virtual_hash();

        let total_deposits_count = builder.add_virtual_target();
        let total_withdrawals_count = builder.add_virtual_target();

        let total_deposits_value = builder.add_virtual_target();
        let total_withdrawals_value = builder.add_virtual_target();
        let current_block_rollup_balance = builder.add_virtual_target();
        let next_block_rollup_balance = builder.add_virtual_target();
        Self {
            deposits_hash,
            withdrawals_hash,
            current_block_state_hash,
            next_block_state_hash,
            total_deposits_count,
            total_withdrawals_count,
            total_deposits_value,
            total_withdrawals_value,
            current_block_rollup_balance,
            next_block_rollup_balance,
        }
    }
    pub fn trace_combined_hash<
        H: AlgebraicHasher<F>,
        F: RichField + Extendable<D>,
        const D: usize,
    >(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        tracer: &mut DebugCircuitTracer,
    ) -> HashOutTarget {
        let state_transition_hash =
            builder.hash_two_to_one::<H>(self.current_block_state_hash, self.next_block_state_hash);
        let deposits_withdrawals_hash =
            builder.hash_two_to_one::<H>(self.deposits_hash, self.withdrawals_hash);

        let combined_hash = builder.hash_n_to_hash_no_pad::<H>(vec![
            state_transition_hash.elements[0],
            state_transition_hash.elements[1],
            state_transition_hash.elements[2],
            state_transition_hash.elements[3],
            deposits_withdrawals_hash.elements[0],
            deposits_withdrawals_hash.elements[1],
            deposits_withdrawals_hash.elements[2],
            deposits_withdrawals_hash.elements[3],
            self.total_deposits_value,
            self.total_deposits_count,
            self.total_withdrawals_value,
            self.total_withdrawals_count,
            self.current_block_rollup_balance,
            self.next_block_rollup_balance,
        ]);

        tracer.trace_hash("current_block_state_hash", self.current_block_state_hash);
        tracer.trace_hash("next_block_state_hash", self.next_block_state_hash);
        tracer.trace_hash("state_transition_hash", state_transition_hash);
        tracer.trace_hash("deposits_hash", self.deposits_hash);
        tracer.trace_hash("withdrawals_hash", self.withdrawals_hash);
        tracer.trace_hash("deposits_withdrawals_hash", deposits_withdrawals_hash);

        tracer.trace("total_deposits_value", self.total_deposits_value);
        tracer.trace("total_deposits_count", self.total_deposits_count);
        tracer.trace("total_withdrawals_value", self.total_withdrawals_value);
        tracer.trace("total_withdrawals_count", self.total_withdrawals_count);
        tracer.trace(
            "current_block_rollup_balance",
            self.current_block_rollup_balance,
        );
        tracer.trace("next_block_rollup_balance", self.next_block_rollup_balance);
        combined_hash
    }
    pub fn get_combined_hash<
        H: AlgebraicHasher<F>,
        F: RichField + Extendable<D>,
        const D: usize,
    >(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> HashOutTarget {
        let state_transition_hash =
            builder.hash_two_to_one::<H>(self.current_block_state_hash, self.next_block_state_hash);
        let deposits_withdrawals_hash =
            builder.hash_two_to_one::<H>(self.deposits_hash, self.withdrawals_hash);

        let combined_hash = builder.hash_n_to_hash_no_pad::<H>(vec![
            state_transition_hash.elements[0],
            state_transition_hash.elements[1],
            state_transition_hash.elements[2],
            state_transition_hash.elements[3],
            deposits_withdrawals_hash.elements[0],
            deposits_withdrawals_hash.elements[1],
            deposits_withdrawals_hash.elements[2],
            deposits_withdrawals_hash.elements[3],
            self.total_deposits_value,
            self.total_deposits_count,
            self.total_withdrawals_value,
            self.total_withdrawals_count,
            self.current_block_rollup_balance,
            self.next_block_rollup_balance,
        ]);
        combined_hash
    }
    pub fn set_witness<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        result: &BTCRollupIntrospectionFinalizedResult<F>,
    ) {
        witness.set_hash_target(self.deposits_hash, result.deposits_hash.0);
        witness.set_hash_target(self.withdrawals_hash, result.withdrawals_hash.0);
        witness.set_hash_target(
            self.current_block_state_hash,
            result.current_block_state_hash.0,
        );
        witness.set_hash_target(self.next_block_state_hash, result.next_block_state_hash.0);

        witness.set_target(self.total_deposits_count, result.total_deposits_count);
        witness.set_target(self.total_deposits_value, result.total_deposits_value);

        witness.set_target(self.total_withdrawals_count, result.total_withdrawals_count);
        witness.set_target(self.total_withdrawals_value, result.total_withdrawals_value);
        witness.set_target(
            self.current_block_rollup_balance,
            result.current_block_rollup_balance,
        );
        witness.set_target(
            self.next_block_rollup_balance,
            result.next_block_rollup_balance,
        );
        /*
        total_deposits_count,
        total_withdrawals_count,
        total_deposits_value,
        total_withdrawals_value,
        current_block_rollup_balance,
        next_block_rollup_balance,
         */
    }
}
