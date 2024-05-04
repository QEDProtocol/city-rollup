use city_crypto::hash::base_types::hash256::Hash256;
use city_rollup_common::api::data::store::CityL1Deposit;
use kvq::traits::{KVQBinaryStore, KVQBinaryStoreReader, KVQStoreAdapter, KVQStoreAdapterReader};

use super::data::{L1DepositKeyByDepositIdCore, L1DepositKeyByTransactionIdCore};

pub trait L1DepositsModelReaderCore<
    const L1_DEPOSITS_BY_ID_TABLE_TYPE: u16,
    const L1_DEPOSITS_BY_TXID_TABLE_TYPE: u16,
    S: KVQBinaryStoreReader,
    IDKVA: KVQStoreAdapterReader<
        S,
        L1DepositKeyByDepositIdCore<L1_DEPOSITS_BY_ID_TABLE_TYPE>,
        CityL1Deposit,
    >,
    TXIDKVA: KVQStoreAdapterReader<
        S,
        L1DepositKeyByTransactionIdCore<L1_DEPOSITS_BY_TXID_TABLE_TYPE>,
        CityL1Deposit,
    >,
>
{
    fn get_deposit_by_id(store: &S, deposit_id: u64) -> anyhow::Result<CityL1Deposit> {
        IDKVA::get_exact(store, &L1DepositKeyByDepositIdCore(deposit_id))
    }
    fn get_deposit_by_txid(store: &S, transaction_id: Hash256) -> anyhow::Result<CityL1Deposit> {
        TXIDKVA::get_exact(store, &L1DepositKeyByTransactionIdCore(transaction_id.0))
    }
}

pub trait L1DepositsModelCore<
    const L1_DEPOSITS_BY_ID_TABLE_TYPE: u16,
    const L1_DEPOSITS_BY_TXID_TABLE_TYPE: u16,
    S: KVQBinaryStore,
    IDKVA: KVQStoreAdapter<S, L1DepositKeyByDepositIdCore<L1_DEPOSITS_BY_ID_TABLE_TYPE>, CityL1Deposit>,
    TXIDKVA: KVQStoreAdapter<
        S,
        L1DepositKeyByTransactionIdCore<L1_DEPOSITS_BY_TXID_TABLE_TYPE>,
        CityL1Deposit,
    >,
>:
    L1DepositsModelReaderCore<
    L1_DEPOSITS_BY_ID_TABLE_TYPE,
    L1_DEPOSITS_BY_TXID_TABLE_TYPE,
    S,
    IDKVA,
    TXIDKVA,
>
{
    fn delete_l1_deposit_by_id(
        store: &mut S,
        deposit_id: u64,
    ) -> anyhow::Result<Option<CityL1Deposit>> {
        let key_id = L1DepositKeyByDepositIdCore(deposit_id);
        let current = IDKVA::get_exact(store, &key_id);
        if current.is_ok() {
            let deposit = current.unwrap();
            let key_txid = L1DepositKeyByTransactionIdCore(deposit.txid.0);
            IDKVA::delete(store, &key_id)?;
            TXIDKVA::delete(store, &key_txid)?;
            Ok(Some(deposit))
        } else {
            Ok(None)
        }
    }
    fn set_l1_deposit(store: &mut S, deposit: CityL1Deposit) -> anyhow::Result<()> {
        let key_id = L1DepositKeyByDepositIdCore(deposit.deposit_id);
        let key_txid = L1DepositKeyByTransactionIdCore(deposit.txid.0);
        IDKVA::set(store, key_id, deposit)?;
        TXIDKVA::set(store, key_txid, deposit)?;
        Ok(())
    }
    fn set_l1_deposit_ref(store: &mut S, deposit: &CityL1Deposit) -> anyhow::Result<()> {
        let key_id = L1DepositKeyByDepositIdCore(deposit.deposit_id);
        let key_txid = L1DepositKeyByTransactionIdCore(deposit.txid.0);
        IDKVA::set_ref(store, &key_id, deposit)?;
        TXIDKVA::set_ref(store, &key_txid, deposit)?;
        Ok(())
    }
    fn set_l1_deposits(store: &mut S, deposits: &[CityL1Deposit]) -> anyhow::Result<()> {
        let key_ids = deposits
            .iter()
            .map(|d| L1DepositKeyByDepositIdCore::<L1_DEPOSITS_BY_ID_TABLE_TYPE>(d.deposit_id))
            .collect::<Vec<_>>();
        IDKVA::set_many_split_ref(store, &key_ids, deposits)?;

        let key_txids = deposits
            .iter()
            .map(|d| L1DepositKeyByTransactionIdCore::<L1_DEPOSITS_BY_TXID_TABLE_TYPE>(d.txid.0))
            .collect::<Vec<_>>();
        TXIDKVA::set_many_split_ref(store, &key_txids, deposits)?;

        Ok(())
    }
}

pub struct L1DepositsModel<
    const L1_DEPOSITS_BY_ID_TABLE_TYPE: u16,
    const L1_DEPOSITS_BY_TXID_TABLE_TYPE: u16,
    S,
    IDKVA,
    TXIDKVA,
> {
    _idkva: IDKVA,
    _txidkva: TXIDKVA,
    _store: S,
}

impl<
        const L1_DEPOSITS_BY_ID_TABLE_TYPE: u16,
        const L1_DEPOSITS_BY_TXID_TABLE_TYPE: u16,
        S: KVQBinaryStoreReader,
        IDKVA: KVQStoreAdapterReader<
            S,
            L1DepositKeyByDepositIdCore<L1_DEPOSITS_BY_ID_TABLE_TYPE>,
            CityL1Deposit,
        >,
        TXIDKVA: KVQStoreAdapterReader<
            S,
            L1DepositKeyByTransactionIdCore<L1_DEPOSITS_BY_TXID_TABLE_TYPE>,
            CityL1Deposit,
        >,
    >
    L1DepositsModelReaderCore<
        L1_DEPOSITS_BY_ID_TABLE_TYPE,
        L1_DEPOSITS_BY_TXID_TABLE_TYPE,
        S,
        IDKVA,
        TXIDKVA,
    >
    for L1DepositsModel<
        L1_DEPOSITS_BY_ID_TABLE_TYPE,
        L1_DEPOSITS_BY_TXID_TABLE_TYPE,
        S,
        IDKVA,
        TXIDKVA,
    >
{
}
impl<
        const L1_DEPOSITS_BY_ID_TABLE_TYPE: u16,
        const L1_DEPOSITS_BY_TXID_TABLE_TYPE: u16,
        S: KVQBinaryStore,
        IDKVA: KVQStoreAdapter<
            S,
            L1DepositKeyByDepositIdCore<L1_DEPOSITS_BY_ID_TABLE_TYPE>,
            CityL1Deposit,
        >,
        TXIDKVA: KVQStoreAdapter<
            S,
            L1DepositKeyByTransactionIdCore<L1_DEPOSITS_BY_TXID_TABLE_TYPE>,
            CityL1Deposit,
        >,
    >
    L1DepositsModelCore<
        L1_DEPOSITS_BY_ID_TABLE_TYPE,
        L1_DEPOSITS_BY_TXID_TABLE_TYPE,
        S,
        IDKVA,
        TXIDKVA,
    >
    for L1DepositsModel<
        L1_DEPOSITS_BY_ID_TABLE_TYPE,
        L1_DEPOSITS_BY_TXID_TABLE_TYPE,
        S,
        IDKVA,
        TXIDKVA,
    >
{
}
