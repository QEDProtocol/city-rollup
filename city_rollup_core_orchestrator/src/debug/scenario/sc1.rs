use kvq::traits::KVQBinaryStore;
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};

use super::wallet::DebugScenarioWallet;

#[derive(Clone)]
pub struct DebugScenarioBuilder<S: KVQBinaryStore, C: GenericConfig<D> + 'static, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub wallet: DebugScenarioWallet<C, D>,
    pub store: S,
}
