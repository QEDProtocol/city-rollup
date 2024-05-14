use std::fs;
use std::path::PathBuf;

use city_common::logging::debug_timer::DebugTimer;
use city_common_circuit::field::cubic::CubicExtendable;
use city_crypto::hash::{base_types::hash256::Hash256, qhashout::QHashOut};
use city_rollup_circuit::{
    sighash_circuits::sighash::CRSigHashCircuit,
    worker::{prover::QWorkerStandardProver, toolbox::root::CRWorkerToolboxRootCircuits},
};
use city_rollup_common::{
    api::data::{block::rpc_request::CityRegisterUserRPCRequest, store::CityL2BlockState},
    introspection::{
        rollup::{
            constants::NETWORK_MAGIC_DOGE_REGTEST,
            introspection::{BlockSpendIntrospectionGadgetConfig, BlockSpendIntrospectionHint},
        },
        transaction::BTCTransaction,
    },
    qworker::memory_proof_store::SimpleProofStoreMemory,
};
use city_rollup_core_orchestrator::debug::scenario::{
    block_planner::planner::CityOrchestratorBlockPlanner,
    requested_actions::CityScenarioRequestedActions, rpc_processor::DebugRPCProcessor,
    wallet::DebugScenarioWallet,
};
use city_store::store::city::base::CityStore;
use kvq::memory::simple::KVQSimpleMemoryBackingStore;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::plonk::config::AlgebraicHasher;
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;

fn generate_circuit<C: GenericConfig<D> + 'static, const D: usize>(
    introspection_config: BlockSpendIntrospectionGadgetConfig,
) -> CRSigHashCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
    C::F: CubicExtendable,
{
    CRSigHashCircuit::<C, D>::new(introspection_config)
}

fn prove_hint<C: GenericConfig<D> + 'static, const D: usize>(
    hint: &BlockSpendIntrospectionHint,
) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>
where
    C::Hasher: AlgebraicHasher<C::F>,
    C::F: CubicExtendable,
{
    let circuit = generate_circuit::<C, D>(hint.get_config());

    let proof = circuit.prove_base(hint)?;

    let result_finalized_hash = QHashOut::from_felt_slice(&proof.public_inputs[0..4]);
    let result_sighash_felt252 = QHashOut::from_felt_slice(&proof.public_inputs[4..8]);

    println!(
        "result_finalized_hash: {}",
        result_finalized_hash.to_string()
    );
    println!(
        "result_sighash_felt252: {}",
        result_sighash_felt252.to_string_le()
    );

    let expected_result = hint.get_introspection_result::<C::Hasher, C::F>();
    let expected_finalized_result = expected_result.get_finalized_result::<C::Hasher>();
    /*println!(
        "expected_trace_result:\n{}",
        serde_json::to_string_pretty(&expected_finalized_result).unwrap()
    );*/

    let expected_finalized_hash = expected_finalized_result.get_combined_hash::<C::Hasher>();
    let expected_sighash_felt252 = expected_result.sighash_felt252;
    let real_sighash = expected_result.sighash;

    println!(
        "expected_finalized_hash: {}",
        expected_finalized_hash.to_string()
    );
    println!(
        "expected_sighash_felt252: {}",
        expected_sighash_felt252.to_string_le()
    );
    println!("real_sighash: {}", real_sighash.to_string());
    /*
        for (i, d) in expected_result.deposits.iter().enumerate() {
            let preimage = vec![
                d.txid_224.0.elements.to_vec(),
                vec![d.value],
                d.public_key.to_vec(),
            ]
            .concat()
            .iter()
            .map(|x| x.to_canonical_u64())
            .collect::<Vec<_>>();
            println!("deposit_{i}_preimage: {:?}", preimage);
            println!("deposit_{i}_hash: {}", d.get_hash::<C::Hasher>());
        }
    */
    Ok(proof)
}
fn prove_block_demo(transactions: &[BTCTransaction]) -> anyhow::Result<()> {
    let network_magic = NETWORK_MAGIC_DOGE_REGTEST;

    let toolbox_circuits = CRWorkerToolboxRootCircuits::<C, D>::new(network_magic);
    //toolbox_circuits.print_op_common_data();

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = GoldilocksField;
    type S = KVQSimpleMemoryBackingStore;
    type PS = SimpleProofStoreMemory;
    let mut proof_store = PS::new();
    let mut store = S::new();
    let mut timer = DebugTimer::new("prove_block_demo");

    timer.lap("start creating wallets");

    let mut wallet = DebugScenarioWallet::<C, D>::new();

    let deposit_0_public_key = wallet.add_secp256k1_private_key(Hash256(hex_literal::hex!(
        "07e5cae38a63f487667075c54cb7791b86179e3becd9198e5ee0557eeffcda31"
    )))?;

    let deposit_1_public_key = wallet.add_secp256k1_private_key(Hash256(hex_literal::hex!(
        "df5bf5d53e56b17602f49c56246b9e1196b2335f8571147fe2df70f3016c78a7"
    )))?;

    let user_0_public_key = wallet.add_zk_private_key(QHashOut::from_values(100, 100, 100, 100));
    let user_1_public_key = wallet.add_zk_private_key(QHashOut::from_values(101, 101, 101, 101));
    let user_2_public_key = wallet.add_zk_private_key(QHashOut::from_values(102, 102, 102, 102));

    timer.lap("end creating wallets");

    timer.lap("start setup initial state");
    let register_user_rpc_events = CityRegisterUserRPCRequest::new_batch(&[
        user_0_public_key,
        user_1_public_key,
        user_2_public_key,
    ]);
    let block_0_state = CityL2BlockState {
        checkpoint_id: 0,
        next_add_withdrawal_id: 0,
        next_process_withdrawal_id: 0,
        next_deposit_id: 0,
        total_deposits_claimed_epoch: 0,
        next_user_id: 0,
        end_balance: 0,
    };

    CityStore::set_block_state(&mut store, &block_0_state)?;

    timer.lap("end setup initial state");
    timer.lap("start process state block 1 RPC");
    let mut block_1_builder = DebugRPCProcessor::<F, D>::new(1);
    block_1_builder.process_register_users(&register_user_rpc_events)?;

    let block_1_requested = CityScenarioRequestedActions::new_from_requested_rpc(
        block_1_builder.output,
        transactions,
        &block_0_state,
        2,
    );

    let mut block_1_planner = CityOrchestratorBlockPlanner::<S, PS>::new(
        toolbox_circuits.core.fingerprints.clone(),
        block_0_state,
    );
    timer.lap("end process state block 1 RPC");
    timer.lap("start process requests block 1");

    let (_, block_1_job_ids, _, block_1_end_jobs) =
        block_1_planner.process_requests(&mut store, &mut proof_store, &block_1_requested)?;
    timer.lap("end process requests block 1");
    /*println!(
            "block_1_job_ids: {}",
            serde_json::to_string(&block_1_job_ids).unwrap()
        );
        println!("block_1_job_ids: {:?}", block_1_job_ids);
        println!(
            "block_1_state_transition: {}",
            serde_json::to_string(&block_1_state_transition).unwrap()
        );
    */
    let mut worker = QWorkerStandardProver::new();
    timer.lap("start proving op jobs");

    let all_job_ids = block_1_job_ids.plan_jobs();
    for job in all_job_ids {
        worker.prove::<PS, _, C, D>(&mut proof_store, &toolbox_circuits, job)?;
    }
    timer.lap("start proving end jobs");

    for job in block_1_end_jobs {
        worker.prove::<PS, _, C, D>(&mut proof_store, &toolbox_circuits, job)?;
    }

    timer.lap("end proving jobs");
    /*
    let root_proof_ids = block_1_job_ids.get_root_proof_outputs();

    let register_users_proof =
        proof_store.get_proof_by_id::<C, D>(root_proof_ids.register_user_job_root_id)?;

    let add_deposit_proof =
        proof_store.get_proof_by_id::<C, D>(root_proof_ids.add_deposit_job_root_id)?;
    println!("got register_users_proof: {:?}", register_users_proof);*/
    Ok(())
}
fn main() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let path = format!("{}/examples/prove_sighash_0_hints.json", root.display());
    let file_data = fs::read(path).unwrap();
    let introspection_hints: Vec<BlockSpendIntrospectionHint> =
        serde_json::from_slice(&file_data).unwrap();
    let transactions = introspection_hints[0].funding_transactions[1..].to_vec();
    prove_block_demo(&transactions).unwrap();

    //println!("Proof: {:?}", proof);
}
