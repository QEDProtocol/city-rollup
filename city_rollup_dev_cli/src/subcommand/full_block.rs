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
    base_types::hash256::Hash256,
    merkle::treeprover::{AggStateTransitionInput, AggWTLeafAggregator, TPLeafAggregator},
    qhashout::QHashOut,
};
use city_rollup_circuit::{
    block_circuits::ops::register_user::WCRUserRegistrationCircuit,
    worker::toolbox::circuits::CRWorkerToolboxCoreCircuits,
};
use city_rollup_common::{
    introspection::rollup::constants::{
        NETWORK_MAGIC_DOGE_MAINNET, NETWORK_MAGIC_DOGE_REGTEST, NETWORK_MAGIC_DOGE_TESTNET,
    },
    qworker::{
        job_witnesses::op::CRUserRegistrationCircuitInput,
        memory_proof_store::SimpleProofStoreMemory,
    },
};
use city_rollup_core_orchestrator::debug::scenario::wallet::DebugScenarioWallet;
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

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = GoldilocksField;
    type S = KVQSimpleMemoryBackingStore;

    let mut wallet = DebugScenarioWallet::<C, D>::new();

    let deposit_0_public_key = wallet.add_secp256k1_private_key(Hash256(hex_literal::hex!(
        "b6340d5bf87d9149b353b2f6f315120e392dbbb0f6acac47f98982fc13771b7b"
    )))?;

    let deposit_1_public_key = wallet.add_secp256k1_private_key(Hash256(hex_literal::hex!(
        "9cb7dcd881c3aea7b3d7c0d6ce35c8ace5cb80d718eabd69b55fe0a7e5bb503c"
    )))?;

    let user_0_public_key = wallet.add_zk_private_key(QHashOut::from_values(100, 100, 100, 100));
    let user_1_public_key = wallet.add_zk_private_key(QHashOut::from_values(101, 101, 101, 101));
    let user_2_public_key = wallet.add_zk_private_key(QHashOut::from_values(102, 102, 102, 102));

    let network_magic = get_network_magic_for_str(args.network)?;
    let toolbox_circuits = CRWorkerToolboxCoreCircuits::<C, D>::new(network_magic);

    let mut store = S::new();
    // setup the block 0 with some balances

    let fingerprint_config = toolbox_circuits.get_fingerprint_config();

    println!(
        "fingerprint_config:\n{}",
        serde_json::to_string(&fingerprint_config).unwrap()
    );

    let allowed_circuit_hashes_root = fingerprint_config
        .op_register_user
        .allowed_circuit_hashes_root;
    println!("finger: {:?}", allowed_circuit_hashes_root.0);
    println!(
        "finger1: {:?}",
        fingerprint_config.op_register_user.aggregator_fingerprint
    );
    let mut store = S::new();
    let base = gen_user_registration_proofs(&mut store, 4, allowed_circuit_hashes_root);

    let mut proof_store = SimpleProofStoreMemory::new();

    let result = prove_tree_serial::<_, AggWTLeafAggregator, _, _, _, _, C, D>(
        proof_store,
        toolbox_circuits.op_register_user,
        toolbox_circuits.agg_state_transition,
        base,
    )?;
    println!("got result: {:?}", result.public_inputs);

    Ok(())
}
