use city_crypto::hash::qhashout::QHashOut;
use city_rollup_common::qworker::memory_proof_store::SimpleProofStoreMemory;
use city_store::store::city::base::CityStore;
use kvq::memory::simple::KVQSimpleMemoryBackingStore;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::plonk::config::PoseidonGoldilocksConfig;

fn run_tree() -> anyhow::Result<()> {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = GoldilocksField;
    type S = KVQSimpleMemoryBackingStore;
    type PS = SimpleProofStoreMemory;
    let proof_store = PS::new();
    let mut store = S::new();

    let r0 = CityStore::register_user(&mut store, 1, 0, QHashOut::from_values(1, 2, 3, 4))?;
    let leaf_1 = CityStore::get_user_tree_leaf(&store, 2, 1)?;
    println!("leaf: {}", leaf_1.to_string());
    //let r1 = CityStore::register_user(&mut store, 1, 1, QHashOut::from_values(5,
    // 6, 7, 8))?; println!("r0: {}", serde_json::to_string(&r0).unwrap());
    //println!("r0: {}", serde_json::to_string(&r1).unwrap());

    Ok(())
}

fn main() {
    run_tree().unwrap();
}
