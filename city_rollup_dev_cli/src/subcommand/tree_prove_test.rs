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
use city_rollup_circuit::{
    block_circuits::ops::register_user::WCRUserRegistrationCircuit,
    worker::toolbox::test_circ::CRWorkerTestToolboxCoreCircuits,
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

fn _test_basic(args: &TreeProveTestArgs) -> Result<()> {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = GoldilocksField;
    type S = KVQSimpleMemoryBackingStore;

    let network_magic = get_network_magic_for_str(args.network.to_string())?;

    let mut trace_timer = TraceTimer::new("CRWorkerToolboxCoreCircuits");
    trace_timer.lap("start => build core toolbox circuits");
    // state transition operations
    let op_register_user =
        WCRUserRegistrationCircuit::<C, D>::new_default_with_minifiers(network_magic, 1);
    trace_timer.lap("built op_register_user");

    // operation aggregators
    let agg_state_transition = AggStateTransitionCircuit::<C, D>::new(
        op_register_user.get_common_circuit_data_ref(),
        op_register_user
            .get_verifier_config_ref()
            .constants_sigmas_cap
            .height(),
    );
    trace_timer.lap("built agg_state_transition");
    let agg_state_transition2 = AggStateTransitionCircuit::<C, D>::new(
        agg_state_transition.get_common_circuit_data_ref(),
        agg_state_transition
            .get_verifier_config_ref()
            .constants_sigmas_cap
            .height(),
    );
    trace_timer.lap("built agg_state_transition2");

    println!(
        "agg_state_transition.fp: {}",
        agg_state_transition.get_fingerprint()
    );
    println!(
        "agg_state_transition2.common: {}",
        agg_state_transition2.get_fingerprint()
    );

    let mut proof_store = SimpleProofStoreMemory::new();

    let mut store = S::new();
    let base = gen_user_registration_proofs(&mut store, 4, QHashOut::from_values(1, 2, 3, 4));
    let mut base_proofs: Vec<ProofWithPublicInputs<F, C, D>> = vec![];
    for l in base.iter() {
        let proof = op_register_user.prove_with_proof_store_sync(&proof_store, l)?;
        base_proofs.push(proof);
    }

    trace_timer.lap("proved leaves");
    let mut new_outputs = vec![];
    let mut new_proofs = vec![];
    for (ichunks, leaf_inputs) in base_proofs.chunks_exact(2).zip(base.chunks_exact(2)) {
        let output = AggWTLeafAggregator::get_output_from_leaves(&leaf_inputs[0], &leaf_inputs[1]);

        let proof = agg_state_transition2.prove(
            op_register_user.get_fingerprint(),
            &op_register_user.get_verifier_config_ref(),
            &ichunks[0],
            &ichunks[1],
            &output,
        )?;
        new_outputs.push(output);
        new_proofs.push(proof);
        println!("proved agg");
    }
    let mut new_outputs2 = vec![];
    let mut new_proofs2 = vec![];
    for (ichunks, leaf_inputs) in new_proofs.chunks_exact(2).zip(new_outputs.chunks_exact(2)) {
        let output = <AggWTLeafAggregator as TPLeafAggregator<
            CRUserRegistrationCircuitInput<GoldilocksField>,
            AggStateTransitionInput<GoldilocksField>,
        >>::get_output_from_inputs(&leaf_inputs[0], &leaf_inputs[1]);

        let proof = agg_state_transition2.prove(
            op_register_user.get_fingerprint(),
            &op_register_user.get_verifier_config_ref(),
            &ichunks[0],
            &ichunks[1],
            &output,
        )?;
        new_outputs2.push(output);
        new_proofs2.push(proof);
        println!("proved agg fin");
    }

    Ok(())
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

    let network_magic = get_network_magic_for_str(args.network)?;
    let toolbox_circuits = CRWorkerTestToolboxCoreCircuits::<C, D>::new(network_magic);
    toolbox_circuits.print_op_common_data();
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

    let toolbox_circuits = CRWorkerTestToolboxCoreCircuits::<C, D>::new(network_magic);
    /*toolbox_circuits
    .agg_state_transition
    .circuit_data
    .verify(result)?;*/
    //println!("got result: {:?}", result);

    toolbox_circuits
        .agg_state_transition
        .circuit_data
        .verify(result)?;

    Ok(())
}
