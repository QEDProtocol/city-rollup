use city_common::config::rollup_constants::GLOBAL_USER_TREE_HEIGHT;
use city_common::config::rollup_constants::L1_DEPOSIT_TREE_HEIGHT;
use city_common::config::rollup_constants::L1_WITHDRAWAL_TREE_HEIGHT;
use city_crypto::hash::merkle::core::DeltaMerkleProofCore;
use city_crypto::hash::merkle::core::MerkleProofCore;
use city_crypto::hash::qhashout::QHashOut;
use city_rollup_common::api::data::store::CityL1Deposit;
use kvq::adapters::standard::KVQStandardAdapter;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::PoseidonGoldilocksConfig;

use crate::models::kvq_merkle::key::KVQMerkleNodeKey;
use crate::models::kvq_merkle::model::KVQFixedConfigMerkleTreeModel;
use crate::models::l1_deposits::data::L1DepositKeyByDepositIdCore;
use crate::models::l1_deposits::data::L1DepositKeyByTransactionIdCore;
use crate::models::l1_deposits::model::L1DepositsModel;

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
