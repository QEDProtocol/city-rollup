use city_rollup_circuit::wallet::memory::CityMemoryWallet;
use kvq::traits::KVQBinaryStore;
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};


#[derive(Clone)]
pub struct DebugScenarioBuilder<S: KVQBinaryStore, C: GenericConfig<D> + 'static, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub wallet: CityMemoryWallet<C, D>,
    pub store: S,
}
