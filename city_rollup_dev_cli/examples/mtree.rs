use city_crypto::hash::qhashout::QHashOut;
use city_store::store::city::base::CityStore;
use kvq::memory::simple::KVQSimpleMemoryBackingStore;

fn run_tree() -> anyhow::Result<()> {
    type S = KVQSimpleMemoryBackingStore;
    let mut store = S::new();

    let _r0 = CityStore::register_user(&mut store, 1, 0, QHashOut::from_values(1, 2, 3, 4))?;
    let leaf_1 = CityStore::get_user_tree_leaf(&store, 2, 1)?;
    tracing::info!("leaf: {}", leaf_1.to_string());
    //let r1 = CityStore::register_user(&mut store, 1, 1, QHashOut::from_values(5, 6, 7, 8))?;
    //tracing::info!("r0: {}", serde_json::to_string(&r0).unwrap());
    //tracing::info!("r0: {}", serde_json::to_string(&r1).unwrap());

    Ok(())
}

fn main() {
    run_tree().unwrap();
}
