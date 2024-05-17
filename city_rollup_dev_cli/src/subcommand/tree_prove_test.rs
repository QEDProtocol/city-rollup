use crate::build;
use crate::error::Result;
use city_common::{cli::dev_args::TreeProveTestArgs, logging::trace_timer::TraceTimer};
use city_common_circuit::{
    circuits::traits::qstandard::{
        QStandardCircuit, QStandardCircuitProvableWithProofStoreSync,
        QStandardCircuitWithDefaultMinified,
    },
    treeprover::{
        aggregation::state_transition::AggStateTransitionCircuit, prover::prove_tree_serial,
        traits::TreeProverAggCircuit,
    },
};
use city_crypto::hash::{
    merkle::treeprover::{AggStateTransitionInput, AggWTLeafAggregator, TPLeafAggregator},
    qhashout::QHashOut,
};
use city_rollup_circuit::block_circuits::ops::register_user::WCRUserRegistrationCircuit;
use city_rollup_common::{
    introspection::rollup::constants::{
        NETWORK_MAGIC_DOGE_MAINNET, NETWORK_MAGIC_DOGE_REGTEST, NETWORK_MAGIC_DOGE_TESTNET,
    },
    qworker::{
        job_witnesses::op::CRUserRegistrationCircuitInput,
        memory_proof_store::SimpleProofStoreMemory,
    },
};
use city_store::store::city::base::CityStore;
use kvq::{memory::simple::KVQSimpleMemoryBackingStore, traits::KVQBinaryStore};
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    plonk::{config::PoseidonGoldilocksConfig, proof::ProofWithPublicInputs},
};

fn get_network_magic_for_str(network: String) -> anyhow::Result<u64> {
    match network.as_str() {
        "dogeregtest" => Ok(NETWORK_MAGIC_DOGE_REGTEST),
        "dogetestnet" => Ok(NETWORK_MAGIC_DOGE_TESTNET),
        "dogemainnet" => Ok(NETWORK_MAGIC_DOGE_MAINNET),
        _ => Err(anyhow::anyhow!("Invalid network {}", network)),
    }
}

fn gen_user_registration_proofs<S: KVQBinaryStore>(
    store: &mut S,
    n: usize,
    allowed_circuit_hashes_root: QHashOut<GoldilocksField>,
) -> Vec<CRUserRegistrationCircuitInput<GoldilocksField>> {
    const _D: usize = 2;
    type _C = PoseidonGoldilocksConfig;
    type _F = GoldilocksField;
    let checkpoint_id = 0u64;
    (0..n)
        .map(|i| {
            let user_id = i as u64;
            let public_key = QHashOut::rand();
            let user_tree_delta_merkle_proof =
                CityStore::<S>::register_user(store, checkpoint_id, user_id, public_key).unwrap();

            CRUserRegistrationCircuitInput {
                user_tree_delta_merkle_proof,
                allowed_circuit_hashes_root,
            }
        })
        .collect()
}

pub async fn run(args: TreeProveTestArgs) -> Result<()> {
    println!(
        "
----------------------------------------
|           CityRollup v{}             |
----------------------------------------
",
        build::PKG_VERSION
    );
    //let indexer = city_indexer::Indexer::new(args).await?;
    //indexer.listen().await?;

    //test_basic(&args)?;

    Ok(())
}
