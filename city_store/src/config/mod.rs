use city_common::config::rollup_constants::{
    GLOBAL_USER_TREE_HEIGHT, L1_DEPOSIT_TREE_HEIGHT, L1_WITHDRAWAL_TREE_HEIGHT,
};
use city_crypto::hash::{
    merkle::core::{DeltaMerkleProofCore, MerkleProofCore},
    qhashout::QHashOut,
};
use city_rollup_common::api::data::store::{CityL1Deposit, CityL2BlockState};
use kvq::adapters::standard::KVQStandardAdapter;
use plonky2::{
    field::goldilocks_field::GoldilocksField, hash::poseidon::PoseidonHash,
    plonk::config::PoseidonGoldilocksConfig,
};

use crate::models::{
    kvq_merkle::{key::KVQMerkleNodeKey, model::KVQFixedConfigMerkleTreeModel},
    l1_deposits::{
        data::{L1DepositKeyByDepositIdCore, L1DepositKeyByTransactionIdCore},
        model::L1DepositsModel,
    },
    l2_block_state::{data::L2BlockStateKeyCore, model::L2BlockStatesModel},
    user::{data::L2UserIdKeyByPubicKeyIdCore, model::L2UserIdsModel},
};

pub type F = GoldilocksField;
pub type C = PoseidonGoldilocksConfig;
pub type CityHasher = PoseidonHash;
pub type CityHash = QHashOut<F>;
pub type CityMerkleProof = MerkleProofCore<CityHash>;
pub type CityDeltaMerkleProof = DeltaMerkleProofCore<CityHash>;

pub const D: usize = 2;

pub const TREE_TABLE_TYPE: u16 = 1;
pub const L1_DEPOSITS_BY_ID_TABLE_TYPE: u16 = 2;
pub const L1_DEPOSITS_BY_TXID_TABLE_TYPE: u16 = 3;
pub const L2_BLOCK_STATE_TABLE_TYPE: u16 = 4;
pub const L2_USER_IDS_BY_PUBLIC_KEY_TABLE_TYPE: u16 = 5;

pub const GLOBAL_USER_TREE_ID: u8 = 1;
pub const L1_DEPOSIT_TREE_ID: u8 = 2;
pub const L1_WITHDRAWAL_TREE_ID: u8 = 3;

pub type CityTreeStore<S, const TREE_ID: u8, const HEIGHT: u8> = KVQFixedConfigMerkleTreeModel<
    TREE_ID,
    HEIGHT,
    0,
    0,
    TREE_TABLE_TYPE,
    false,
    S,
    KVQStandardAdapter<S, KVQMerkleNodeKey<TREE_TABLE_TYPE>, CityHash>,
    CityHash,
    CityHasher,
>;

pub type GlobalUserTreeStore<S> = CityTreeStore<S, GLOBAL_USER_TREE_ID, GLOBAL_USER_TREE_HEIGHT>;
pub type L1DepositTreeStore<S> = CityTreeStore<S, L1_DEPOSIT_TREE_ID, L1_DEPOSIT_TREE_HEIGHT>;
pub type L1WithdrawalTreeStore<S> =
    CityTreeStore<S, L1_WITHDRAWAL_TREE_ID, L1_WITHDRAWAL_TREE_HEIGHT>;

pub type L1DepositsStore<S> = L1DepositsModel<
    L1_DEPOSITS_BY_ID_TABLE_TYPE,
    L1_DEPOSITS_BY_TXID_TABLE_TYPE,
    S,
    KVQStandardAdapter<S, L1DepositKeyByDepositIdCore<L1_DEPOSITS_BY_ID_TABLE_TYPE>, CityL1Deposit>,
    KVQStandardAdapter<
        S,
        L1DepositKeyByTransactionIdCore<L1_DEPOSITS_BY_TXID_TABLE_TYPE>,
        CityL1Deposit,
    >,
>;

pub type L2BlockStateStore<S> = L2BlockStatesModel<
    L2_BLOCK_STATE_TABLE_TYPE,
    S,
    KVQStandardAdapter<S, L2BlockStateKeyCore<L2_BLOCK_STATE_TABLE_TYPE>, CityL2BlockState>,
>;

pub type L2UserIdsStore<S> = L2UserIdsModel<
    L2_USER_IDS_BY_PUBLIC_KEY_TABLE_TYPE,
    S,
    KVQStandardAdapter<S, L2UserIdKeyByPubicKeyIdCore<L2_USER_IDS_BY_PUBLIC_KEY_TABLE_TYPE>, u64>,
>;
