use kvq::traits::{KVQBinaryStore, KVQBinaryStoreReader, KVQStoreAdapter, KVQStoreAdapterReader};

use crate::config::CityHash;

use super::data::L2UserIdKeyByPubicKeyIdCore;
pub const USER_ID_FUZZY_SIZE: usize = 8;

pub trait L2UserIdsModelReaderCore<
    const L2_USER_IDS_BY_PUBLIC_KEY_TABLE_TYPE: u16,
    S: KVQBinaryStoreReader,
    KVA: KVQStoreAdapterReader<
        S,
        L2UserIdKeyByPubicKeyIdCore<L2_USER_IDS_BY_PUBLIC_KEY_TABLE_TYPE>,
        u64,
    >,
>
{
    fn get_user_ids_for_public_key(store: &S, public_key: CityHash) -> anyhow::Result<Vec<u64>> {
        let result = KVA::get_fuzzy_range_leq_kv(
            store,
            &L2UserIdKeyByPubicKeyIdCore {
                public_key,
                user_id: 0xffffffffffffffu64,
            },
            USER_ID_FUZZY_SIZE,
        )?
        .into_iter()
        .map(|x| x.key.user_id)
        .collect();
        Ok(result)
    }
}

pub trait L2UserIdsModelCore<
    const L2_USER_IDS_BY_PUBLIC_KEY_TABLE_TYPE: u16,
    S: KVQBinaryStore,
    KVA: KVQStoreAdapter<S, L2UserIdKeyByPubicKeyIdCore<L2_USER_IDS_BY_PUBLIC_KEY_TABLE_TYPE>, u64>,
>: L2UserIdsModelReaderCore<L2_USER_IDS_BY_PUBLIC_KEY_TABLE_TYPE, S, KVA>
{
    fn delete_user_id_public_key_pair(
        store: &mut S,
        user_id: u64,
        public_key: CityHash,
    ) -> anyhow::Result<Option<u64>> {
        let key_id = L2UserIdKeyByPubicKeyIdCore {
            public_key,
            user_id,
        };
        let current = KVA::get_exact_if_exists(store, &key_id)?;
        if current.is_some() {
            let result = current.unwrap();
            KVA::delete(store, &key_id)?;
            Ok(Some(result))
        } else {
            Ok(None)
        }
    }
    fn set_user_id_public_key_pair(
        store: &mut S,
        user_id: u64,
        public_key: CityHash,
    ) -> anyhow::Result<()> {
        let key_id = L2UserIdKeyByPubicKeyIdCore {
            public_key,
            user_id,
        };
        KVA::set(store, key_id, user_id)?;
        Ok(())
    }
}
pub struct L2UserIdsModel<const L2_USER_IDS_BY_PUBLIC_KEY_TABLE_TYPE: u16, S, KVA> {
    _store: S,
    _kva: KVA,
}

impl<
        const L2_USER_IDS_BY_PUBLIC_KEY_TABLE_TYPE: u16,
        S: KVQBinaryStoreReader,
        KVA: KVQStoreAdapterReader<
            S,
            L2UserIdKeyByPubicKeyIdCore<L2_USER_IDS_BY_PUBLIC_KEY_TABLE_TYPE>,
            u64,
        >,
    > L2UserIdsModelReaderCore<L2_USER_IDS_BY_PUBLIC_KEY_TABLE_TYPE, S, KVA>
    for L2UserIdsModel<L2_USER_IDS_BY_PUBLIC_KEY_TABLE_TYPE, S, KVA>
{
}
impl<
        const L2_USER_IDS_BY_PUBLIC_KEY_TABLE_TYPE: u16,
        S: KVQBinaryStore,
        KVA: KVQStoreAdapter<S, L2UserIdKeyByPubicKeyIdCore<L2_USER_IDS_BY_PUBLIC_KEY_TABLE_TYPE>, u64>,
    > L2UserIdsModelCore<L2_USER_IDS_BY_PUBLIC_KEY_TABLE_TYPE, S, KVA>
    for L2UserIdsModel<L2_USER_IDS_BY_PUBLIC_KEY_TABLE_TYPE, S, KVA>
{
}
