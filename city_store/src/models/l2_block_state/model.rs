use city_rollup_common::api::data::store::CityL2BlockState;
use kvq::traits::{KVQBinaryStore, KVQBinaryStoreReader, KVQStoreAdapter, KVQStoreAdapterReader};

use super::data::L2BlockStateKeyCore;

pub trait L2BlockStatesModelReaderCore<
    const L2_BLOCK_STATE_TABLE_TYPE: u16,
    S: KVQBinaryStoreReader,
    KVA: KVQStoreAdapterReader<S, L2BlockStateKeyCore<L2_BLOCK_STATE_TABLE_TYPE>, CityL2BlockState>,
>
{
    fn get_block_state_by_id(store: &S, checkpoint_id: u64) -> anyhow::Result<CityL2BlockState> {
        KVA::get_exact(store, &L2BlockStateKeyCore(checkpoint_id))
    }
    fn get_block_states_by_id(
        store: &S,
        checkpoint_ids: &[u64],
    ) -> anyhow::Result<Vec<CityL2BlockState>> {
        let keys = checkpoint_ids
            .iter()
            .map(|id| L2BlockStateKeyCore(*id))
            .collect::<Vec<_>>();
        KVA::get_many_exact(store, &keys)
    }
}
pub trait L2BlockStatesModelCore<
    const L2_BLOCK_STATE_TABLE_TYPE: u16,
    S: KVQBinaryStore,
    KVA: KVQStoreAdapter<S, L2BlockStateKeyCore<L2_BLOCK_STATE_TABLE_TYPE>, CityL2BlockState>,
>: L2BlockStatesModelReaderCore<L2_BLOCK_STATE_TABLE_TYPE, S, KVA>
{
    fn delete_block_state_by_id(
        store: &mut S,
        checkpoint_id: u64,
    ) -> anyhow::Result<Option<CityL2BlockState>> {
        let key_id = L2BlockStateKeyCore::<L2_BLOCK_STATE_TABLE_TYPE>(checkpoint_id);
        let current = KVA::get_exact_if_exists(store, &key_id)?;
        if current.is_some() {
            let deposit = current.unwrap();
            KVA::delete(store, &key_id)?;
            Ok(Some(deposit))
        } else {
            Ok(None)
        }
    }
    fn set_block_state(store: &mut S, block_state: CityL2BlockState) -> anyhow::Result<()> {
        let key_id = L2BlockStateKeyCore::<L2_BLOCK_STATE_TABLE_TYPE>(block_state.checkpoint_id);
        KVA::set(store, key_id, block_state)?;
        Ok(())
    }
    fn set_block_state_ref(store: &mut S, block_state: &CityL2BlockState) -> anyhow::Result<()> {
        let key_id = L2BlockStateKeyCore::<L2_BLOCK_STATE_TABLE_TYPE>(block_state.checkpoint_id);
        KVA::set_ref(store, &key_id, &block_state)?;
        Ok(())
    }
    fn set_block_states(store: &mut S, block_states: &[CityL2BlockState]) -> anyhow::Result<()> {
        let key_ids = block_states
            .iter()
            .map(|s| L2BlockStateKeyCore::<L2_BLOCK_STATE_TABLE_TYPE>(s.checkpoint_id))
            .collect::<Vec<_>>();
        KVA::set_many_split_ref(store, &key_ids, block_states)?;

        Ok(())
    }
}
pub struct L2BlockStatesModel<const L2_BLOCK_STATE_TABLE_TYPE: u16, S, KVA> {
    _store: S,
    _kva: KVA,
}

impl<
        const L2_BLOCK_STATE_TABLE_TYPE: u16,
        S: KVQBinaryStoreReader,
        KVA: KVQStoreAdapterReader<S, L2BlockStateKeyCore<L2_BLOCK_STATE_TABLE_TYPE>, CityL2BlockState>,
    > L2BlockStatesModelReaderCore<L2_BLOCK_STATE_TABLE_TYPE, S, KVA>
    for L2BlockStatesModel<L2_BLOCK_STATE_TABLE_TYPE, S, KVA>
{
}
impl<
        const L2_BLOCK_STATE_TABLE_TYPE: u16,
        S: KVQBinaryStore,
        KVA: KVQStoreAdapter<S, L2BlockStateKeyCore<L2_BLOCK_STATE_TABLE_TYPE>, CityL2BlockState>,
    > L2BlockStatesModelCore<L2_BLOCK_STATE_TABLE_TYPE, S, KVA>
    for L2BlockStatesModel<L2_BLOCK_STATE_TABLE_TYPE, S, KVA>
{
}
/*

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
*/
