use city_common::binaryhelpers::bytes::{read_u48_from_bytes_le, read_u56_from_bytes_le};
use city_crypto::{
    field::conversions::bytes33_to_public_key,
    hash::{
        base_types::{hash160::Hash160, hash256::Hash256},
        merkle::core::compute_partial_merkle_root_from_leaves_algebraic,
        qhashout::QHashOut,
    },
    signature::secp256k1::core::hash256_to_hashout_u224,
};
use plonky2::{
    hash::hash_types::{HashOut, RichField},
    plonk::config::AlgebraicHasher,
};
use serde::{Deserialize, Serialize};

pub const WITHDRAWAL_TYPE_BYTE_P2PKH: u8 = 0u8;
pub const WITHDRAWAL_TYPE_BYTE_P2SH: u8 = 1u8;
pub const WITHDRAWAL_TYPE_P2PKH: u64 = 0;
pub const WITHDRAWAL_TYPE_P2SH: u64 = 1u64 << 48u64;

#[derive(Serialize, Deserialize, PartialEq, Clone, Copy, Debug)]
#[serde(bound = "")]
pub struct BTCRollupIntrospectionResultDeposit<F: RichField> {
    pub public_key: [F; 9],
    pub txid_224: QHashOut<F>,
    pub value: F,
}
impl<F: RichField> BTCRollupIntrospectionResultDeposit<F> {
    pub fn get_hash<H: AlgebraicHasher<F>>(&self) -> QHashOut<F> {
        QHashOut(H::hash_no_pad(
            &[
                self.txid_224.0.elements.to_vec(),
                vec![self.value],
                self.public_key.to_vec(),
            ]
            .concat(),
        ))
    }
    pub fn from_byte_representation(public_key: &[u8], txid: Hash256, value: u64) -> Self {
        let public_key = bytes33_to_public_key(public_key);
        let txid_224 = QHashOut(hash256_to_hashout_u224::<F>(txid));
        let value = F::from_canonical_u64(value);
        BTCRollupIntrospectionResultDeposit {
            public_key,
            txid_224,
            value,
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
#[serde(bound = "")]
pub struct BTCRollupIntrospectionResultWithdrawal<F: RichField> {
    pub script: Vec<F>,
    pub value: F,
}

impl<F: RichField> BTCRollupIntrospectionResultWithdrawal<F> {
    pub fn from_bytes(script_bytes: &[u8], value: F) -> Self {
        let script = script_bytes
            .iter()
            .map(|f| F::from_canonical_u8(*f))
            .collect::<Vec<F>>();
        BTCRollupIntrospectionResultWithdrawal { script, value }
    }
    pub fn hash_from_public_key_hash(
        value: u64,
        public_key_hash: Hash160,
        script_type_flag: u8,
    ) -> QHashOut<F> {
        let last_48_bits_with_flag =
            read_u48_from_bytes_le(&public_key_hash.0, 14) | ((script_type_flag as u64) << 48u64);

        QHashOut(HashOut {
            elements: [
                F::from_noncanonical_u64(value),
                F::from_noncanonical_u64(read_u56_from_bytes_le(&public_key_hash.0, 0)),
                F::from_noncanonical_u64(read_u56_from_bytes_le(&public_key_hash.0, 7)),
                F::from_noncanonical_u64(last_48_bits_with_flag),
            ],
        })
    }
    pub fn get_hash<H: AlgebraicHasher<F>>(&self) -> QHashOut<F> {
        /*
        QHashOut(H::hash_no_pad(
            &[vec![self.value], self.script.to_vec()].concat(),
        ))
        */
        let script_length = self.script.len();
        assert!(
            script_length == 23 || script_length == 25,
            "only supports p2sh (length = 23) and p2pkh withdrawals (length = 25), got length = {}",
            script_length
        );
        let public_key_hash_bytes = if script_length == 23 {
            // p2sh
            self.script[2..22]
            .iter()
            .map(|f| f.to_canonical_u64() as u8)
            .collect::<Vec<u8>>()
        }else{
            // p2pkh
            self.script[3..23]
            .iter()
            .map(|f| f.to_canonical_u64() as u8)
            .collect::<Vec<u8>>()
        };
        let withdrawal_type_flag = if script_length == 23 {
            WITHDRAWAL_TYPE_P2SH
        } else {
            WITHDRAWAL_TYPE_P2PKH
        };
        let last_48_bits_with_flag =
            read_u48_from_bytes_le(&public_key_hash_bytes, 14) | withdrawal_type_flag;

        QHashOut(HashOut {
            elements: [
                self.value,
                F::from_noncanonical_u64(read_u56_from_bytes_le(&public_key_hash_bytes, 0)),
                F::from_noncanonical_u64(read_u56_from_bytes_le(&public_key_hash_bytes, 7)),
                F::from_noncanonical_u64(last_48_bits_with_flag),
            ],
        })
    }
}

pub fn get_introspection_events_hash<H: AlgebraicHasher<F>, F: RichField>(
    events: &[QHashOut<F>],
) -> QHashOut<F> {
    if events.len() == 0 {
        QHashOut::ZERO
    } else {
        let leaves = events.iter().map(|e| e.0).collect::<Vec<HashOut<F>>>();
        QHashOut(compute_partial_merkle_root_from_leaves_algebraic::<F, H>(
            &leaves,
        ))
    }
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
#[serde(bound = "")]
pub struct BTCRollupRefundIntrospectionResult<F: RichField> {
    pub deposits: Vec<BTCRollupIntrospectionResultDeposit<F>>,
    pub withdrawals: Vec<BTCRollupIntrospectionResultWithdrawal<F>>,

    pub current_block_state_hash: QHashOut<F>,

    pub sighash: Hash256,
    pub sighash_felt252: QHashOut<F>,
}

impl<F: RichField> BTCRollupRefundIntrospectionResult<F> {
    pub fn get_finalized_result<H: AlgebraicHasher<F>>(
        &self,
    ) -> BTCRollupRefundIntrospectionFinalizedResult<F> {
        let d_events = self
            .deposits
            .iter()
            .map(|d| d.get_hash::<H>())
            .collect::<Vec<_>>();
        let deposits_hash = get_introspection_events_hash::<H, F>(&d_events);
        let w_events = self
            .withdrawals
            .iter()
            .map(|w| w.get_hash::<H>())
            .collect::<Vec<_>>();

        let withdrawals_hash = get_introspection_events_hash::<H, F>(&w_events);

        BTCRollupRefundIntrospectionFinalizedResult {
            deposits_hash,
            withdrawals_hash,
            current_block_state_hash: self.current_block_state_hash
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
#[serde(bound = "")]
pub struct BTCRollupIntrospectionResult<F: RichField> {
    pub deposits: Vec<BTCRollupIntrospectionResultDeposit<F>>,
    pub withdrawals: Vec<BTCRollupIntrospectionResultWithdrawal<F>>,

    pub current_block_state_hash: QHashOut<F>,
    pub next_block_state_hash: QHashOut<F>,

    pub current_block_rollup_balance: F,
    pub next_block_rollup_balance: F,

    pub spend_index: usize,

    pub sighash: Hash256,
    pub sighash_felt252: QHashOut<F>,
}
impl<F: RichField> BTCRollupIntrospectionResult<F> {
    pub fn get_finalized_result<H: AlgebraicHasher<F>>(
        &self,
    ) -> BTCRollupIntrospectionFinalizedResult<F> {
        let total_withdrawals_count = F::from_noncanonical_u64(self.withdrawals.len() as u64);
        let total_deposits_count = F::from_noncanonical_u64(self.deposits.len() as u64);

        let d_events = self
            .deposits
            .iter()
            .map(|d| d.get_hash::<H>())
            .collect::<Vec<_>>();
        let deposits_hash = get_introspection_events_hash::<H, F>(&d_events);
        let w_events = self
            .withdrawals
            .iter()
            .map(|w| w.get_hash::<H>())
            .collect::<Vec<_>>();

        let withdrawals_hash = get_introspection_events_hash::<H, F>(&w_events);
        let total_withdrawals_value = self.withdrawals.iter().map(|w| w.value).sum();
        let total_deposits_value = self.deposits.iter().map(|d| d.value).sum();

        BTCRollupIntrospectionFinalizedResult {
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
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
#[serde(bound = "")]
pub struct BTCRollupIntrospectionFinalizedResult<F: RichField> {
    pub deposits_hash: QHashOut<F>,
    pub withdrawals_hash: QHashOut<F>,

    pub current_block_state_hash: QHashOut<F>,
    pub next_block_state_hash: QHashOut<F>,

    pub total_deposits_count: F,
    pub total_withdrawals_count: F,

    pub total_deposits_value: F,
    pub total_withdrawals_value: F,
    pub current_block_rollup_balance: F,
    pub next_block_rollup_balance: F,
}
impl<F: RichField> BTCRollupIntrospectionFinalizedResult<F> {
    pub fn get_combined_hash<H: AlgebraicHasher<F>>(&self) -> QHashOut<F> {
        let state_transition_hash = H::two_to_one(
            self.current_block_state_hash.0,
            self.next_block_state_hash.0,
        );
        let deposits_withdrawals_hash =
            H::two_to_one(self.deposits_hash.0, self.withdrawals_hash.0);
        let combined_hash = H::hash_no_pad(&[
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
        QHashOut(combined_hash)
    }
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
#[serde(bound = "")]
pub struct BTCRollupRefundIntrospectionFinalizedResult<F: RichField> {
    pub deposits_hash: QHashOut<F>,
    pub withdrawals_hash: QHashOut<F>,
    pub current_block_state_hash: QHashOut<F>,
}
impl<F: RichField> BTCRollupRefundIntrospectionFinalizedResult<F> {
    pub fn get_combined_hash<H: AlgebraicHasher<F>>(&self) -> QHashOut<F> {
        let deposits_withdrawals_hash =
            H::two_to_one(self.deposits_hash.0, self.withdrawals_hash.0);
        let combined_hash = H::hash_no_pad(&[
            self.current_block_state_hash.0.elements[0],
            self.current_block_state_hash.0.elements[1],
            self.current_block_state_hash.0.elements[2],
            self.current_block_state_hash.0.elements[3],
            deposits_withdrawals_hash.elements[0],
            deposits_withdrawals_hash.elements[1],
            deposits_withdrawals_hash.elements[2],
            deposits_withdrawals_hash.elements[3],
        ]);
        QHashOut(combined_hash)
    }
}
