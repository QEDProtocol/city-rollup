use city_common::{
    config::rollup_constants::{BLOCK_SCRIPT_SPEND_BASE_FEE_AMOUNT, WITHDRAWAL_FEE_AMOUNT},
    logging::debug_timer::DebugTimer,
};
use city_crypto::hash::base_types::{felt252::felt252_hashout_to_hash256_le, hash160::Hash160, hash256::Hash256};
use city_rollup_common::{
    actors::{
        requested_actions::CityScenarioRequestedActions,

        traits::{OrchestratorEventReceiverSync, WorkerEventTransmitterSync},
    },
    api::data::store::CityL1Withdrawal,
    block_template::{data::CityGroth16ProofData, BLOCK_GROTH16_ENCODED_VERIFIER_DATA},
    config::sighash_wrapper_config::SIGHASH_CIRCUIT_MAX_WITHDRAWALS,
    introspection::{
        rollup::introspection::BlockSpendIntrospectionHint,
        sighash::{SigHashPreimage, SIGHASH_ALL},
        transaction::{BTCTransaction, BTCTransactionInput, BTCTransactionOutput},
    },
    link::{data::BTCAddress160, traits::QBitcoinAPISync},
    qworker::{
        fingerprints::CRWorkerToolboxCoreCircuitFingerprints, job_id::{QProvingJobDataID, QProvingJobDataIDSerializedWrapped}, proof_store::QProofStore
    },
};
use city_store::{
    config::F,
    store::{city::base::CityStore, sighash::SigHashMerkleTree},
};
use kvq::traits::KVQBinaryStore;
use serde::{Deserialize, Serialize};

use crate::debug::scenario::{
    actors::job_planner::plan_jobs, block_planner::planner::CityOrchestratorBlockPlanner, sighash::finalizer::SigHashFinalizer
};
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SimpleActorOrchestratorProduceBlockStep1Result {
    pub checkpoint_id: u64,
    pub num_input_witnesses: usize,
    pub template_transaction: BTCTransaction,
}
pub struct SimpleActorOrchestrator {
    pub fingerprints: CRWorkerToolboxCoreCircuitFingerprints<F>,
}
pub fn create_hints_for_block(
    current_script: &[u8],
    next_address: Hash160,
    next_script: &[u8],
    all_inputs: &[BTCTransaction],
    withdrawals: &[CityL1Withdrawal],
) -> anyhow::Result<Vec<BlockSpendIntrospectionHint>> {
    let total_balance = all_inputs.iter().map(|x| x.outputs[0].value).sum::<u64>();
    let total_withdrawals = withdrawals.iter().map(|x| x.value).sum::<u64>();
    let total_fees =
        WITHDRAWAL_FEE_AMOUNT * (withdrawals.len() as u64) + BLOCK_SCRIPT_SPEND_BASE_FEE_AMOUNT;
    if (total_fees + total_withdrawals) > total_balance {
        anyhow::bail!("total fees + total withdrawals exceed total balance");
    }

    let next_block_balance = total_balance - total_withdrawals - total_fees;

    let outputs = [
        vec![BTCTransactionOutput {
            script: [vec![0xa9u8, 0x14u8], next_address.0.to_vec(), vec![0x87u8]].concat(),
            value: next_block_balance,
        }],
        withdrawals
            .iter()
            .map(|x| x.to_btc_tx_out())
            .collect::<Vec<_>>(),
    ]
    .concat();

    let base_tx = BTCTransaction {
        version: 2,
        inputs: all_inputs
            .iter()
            .map(|x| BTCTransactionInput {
                hash: x.get_hash(),
                sequence: 0xffffffff,
                script: vec![],
                index: 0,
            })
            .collect(),
        outputs,
        locktime: 0,
    };
    let base_sighash_preimage = SigHashPreimage {
        transaction: base_tx,
        sighash_type: SIGHASH_ALL,
    };

    let mut next_block_sighash_preimage_output = base_sighash_preimage.clone();
    next_block_sighash_preimage_output.transaction.inputs[0].script = current_script.to_vec();
    /*let hint = BlockSpendIntrospectionHint {
        sighash_preimage: next_block_sighash_preimage_output,
        last_block_spend_index: 0,
        block_spend_index: 0,
        current_spend_index: 0,
        funding_transactions: all_inputs.to_vec(),
        next_block_redeem_script: next_script.to_vec(),
    };*/
    let mut spend_hints: Vec<BlockSpendIntrospectionHint> = vec![];
    let inputs_len = all_inputs.len();
    for i in 0..inputs_len {
        let mut next_block_sighash_preimage_output = base_sighash_preimage.clone();
        next_block_sighash_preimage_output.transaction.inputs[i].script = current_script.to_vec();
        let hint = BlockSpendIntrospectionHint {
            sighash_preimage: next_block_sighash_preimage_output,
            last_block_spend_index: 0,
            block_spend_index: 0,
            current_spend_index: i,
            funding_transactions: all_inputs.to_vec(),
            next_block_redeem_script: next_script.to_vec(),
        };

        //tracing::info!("hint[{}]: {}",i, serde_json::to_string(&hint).unwrap());
        tracing::info!("sighash[{}]: {}", i, hint.sighash_preimage.get_hash().to_hex_string());
        //tracing::info!("sighash_252[{}]: {:?}", hint.sighash_preimage.get_hash_felt252::<F>());
        tracing::info!("sighash_252_hex[{}]: {}", i, felt252_hashout_to_hash256_le(hint.sighash_preimage.get_hash_felt252::<F>()).to_hex_string());

        spend_hints.push(hint);
    }

    Ok(spend_hints)
}
impl SimpleActorOrchestrator {
    pub fn step_1_produce_block_enqueue_jobs<
        PS: QProofStore,
        S: KVQBinaryStore,
        BTC: QBitcoinAPISync,
        ER: OrchestratorEventReceiverSync<F>,
        WQ: WorkerEventTransmitterSync,
    >(
        proof_store: &mut PS,
        store: &mut S,
        event_receiver: &mut ER,
        worker_queue: &mut WQ,
        btc_api: &mut BTC,
        fingerprints: &CRWorkerToolboxCoreCircuitFingerprints<F>,
        sighash_whitelist_tree: &SigHashMerkleTree,
    ) -> anyhow::Result<SimpleActorOrchestratorProduceBlockStep1Result> {
        let (leaf_jobs, checkpoint_id, num_input_witnesses, template_transaction) =
            Self::step_1_produce_block_enqueue_jobs_internal(
                proof_store,
                store,
                event_receiver,
                btc_api,
                fingerprints,
                sighash_whitelist_tree,
            )?;
        worker_queue.enqueue_jobs(&leaf_jobs)?;
        Ok(SimpleActorOrchestratorProduceBlockStep1Result {
            checkpoint_id,
            num_input_witnesses,
            template_transaction,
        })
    }
    pub fn step_2_produce_block_finalize_and_transact<PS: QProofStore, BTC: QBitcoinAPISync>(
        proof_store: &mut PS,
        btc_api: &mut BTC,
        part_1_result: &SimpleActorOrchestratorProduceBlockStep1Result,
    ) -> anyhow::Result<Hash256> {
        Self::step_2_produce_block_finalize_and_transact_internal(
            proof_store,
            btc_api,
            part_1_result,
        )
    }

    pub fn run_orchestrator<
        PS: QProofStore,
        S: KVQBinaryStore,
        BTC: QBitcoinAPISync,
        ER: OrchestratorEventReceiverSync<F>,
        WQ: WorkerEventTransmitterSync,
    >(
        proof_store: &mut PS,
        store: &mut S,
        event_receiver: &mut ER,
        worker_queue: &mut WQ,
        btc_api: &mut BTC,
        fingerprints: &CRWorkerToolboxCoreCircuitFingerprints<F>,
        sighash_whitelist_tree: &SigHashMerkleTree,
        timer: &mut DebugTimer,
    ) -> anyhow::Result<()> {
        timer.lap("start wait for next block");
        event_receiver.wait_for_produce_block()?;
        timer.lap("end wait for next block");
        let step_1_result = Self::step_1_produce_block_enqueue_jobs(
            proof_store,
            store,
            event_receiver,
            worker_queue,
            btc_api,
            fingerprints,
            sighash_whitelist_tree,
        )?;
        worker_queue.wait_for_block_proving_jobs(step_1_result.checkpoint_id)?;
        let txid =
            Self::step_2_produce_block_finalize_and_transact(proof_store, btc_api, &step_1_result)?;
        tracing::info!(
            "produce_block_l1_txid {}: {}",
            step_1_result.checkpoint_id,
            txid.to_hex_string()
        );
        timer.lap("end produce block");
        Ok(())
    }
    fn step_1_produce_block_enqueue_jobs_internal<
        PS: QProofStore,
        S: KVQBinaryStore,
        BTC: QBitcoinAPISync,
        ER: OrchestratorEventReceiverSync<F>,
    >(
        proof_store: &mut PS,
        store: &mut S,
        event_receiver: &mut ER,
        btc_api: &mut BTC,
        fingerprints: &CRWorkerToolboxCoreCircuitFingerprints<F>,
        sighash_whitelist_tree: &SigHashMerkleTree,
    ) -> anyhow::Result<(Vec<QProvingJobDataID>, u64, usize, BTCTransaction)> {

        let last_block = CityStore::get_latest_block_state(store)?;
        let last_block_address: Hash160 =
            CityStore::get_city_block_deposit_address(store, last_block.checkpoint_id)?;
        let current_block_address =
            CityStore::get_city_block_deposit_address(store, last_block.checkpoint_id + 1)?;
        let current_block_script =
            CityStore::get_city_block_script(store, last_block.checkpoint_id + 1)?;

        let checkpoint_id = last_block.checkpoint_id + 1;
        let mut timer = DebugTimer::new(&format!("produce_block [{}]", checkpoint_id));

        // let register_users = event_receiver.flush_register_users()?;
        // let claim_l1_deposits = event_receiver.flush_claim_deposits()?;
        // let add_withdrawals = event_receiver.flush_add_withdrawals()?;
        // let token_transfers = event_receiver.flush_token_transfers()?;\
        let rpc_all = event_receiver.flush_all()?;
        timer.lap(&"end process rpc_all".to_string());

        tracing::info!(
            "last_block_address: {}",
            BTCAddress160::new_p2sh(last_block_address,).to_address_string()
        );
        tracing::info!(
            "current_block_address: {}",
            BTCAddress160::new_p2sh(current_block_address,).to_address_string()
        );

        tracing::info!(
            "current_block_address: {}",
            BTCAddress160::new_p2sh(current_block_address,).to_address_string()
        );
        let utxos = btc_api
            .get_confirmed_funding_transactions_with_vout(BTCAddress160::new_p2sh(
                current_block_address,
            ))?
            .into_iter()
            //.filter(|x| x.vout == 0)
            .map(|x| x.transaction)
            .collect::<Vec<BTCTransaction>>();

        let mut deposit_utxos = vec![];
        let mut last_block_utxo = BTCTransaction::dummy();
        for utxo in utxos.into_iter() {
            //tracing::info!("utxos: {}", hex::encode(&utxo.to_bytes()));

            if utxo.is_block_spend_for_state(last_block_address) {
                last_block_utxo = utxo;
            } else if utxo.is_p2pkh() {
                deposit_utxos.push(utxo);
            } else {
                tracing::info!("abnormal utxo, ignoring: {}", hex::encode(&utxo.to_bytes()));
            }
        }
        if last_block_utxo.is_dummy() {
            anyhow::bail!("utxo not funded by last block");
        }
        tracing::info!(
            "found {} deposits for block {}",
            deposit_utxos.len(),
            checkpoint_id
        );

        let mut all_inputs = vec![last_block_utxo];
        all_inputs.append(&mut deposit_utxos);

        let block_requested = CityScenarioRequestedActions::new_from_requested_rpc(
            // CityScenarioRequestedActionsFromRPC {
            //     register_users,
            //     claim_l1_deposits,
            //     add_withdrawals,
            //     token_transfers,
            // },
            rpc_all,
            all_inputs.iter().skip(1),
            &last_block,
            SIGHASH_CIRCUIT_MAX_WITHDRAWALS,
        );

        let mut block_planner =
            CityOrchestratorBlockPlanner::<S, PS>::new(fingerprints.clone(), last_block);
        timer.lap(&format!("end process state block {} RPC", checkpoint_id));
        timer.lap(&format!(
            "start process requests block {} RPC",
            checkpoint_id
        ));

        let (_block_state, block_op_job_ids, _block_state_transition, _block_end_jobs, withdrawals) =
            block_planner.process_requests(store, proof_store, &block_requested)?;

        let next_address = CityStore::get_city_block_deposit_address(store, checkpoint_id + 1)?;
        let next_script = CityStore::get_city_block_script(store, checkpoint_id + 1)?;
        tracing::info!(
            "next_address: {}",
            BTCAddress160::new_p2sh(next_address).to_address_string()
        );


        /*tracing::info!(
            "next_address: {}",
            BTCAddress160::new_p2sh(next_address).to_address_string()
        );*/
        let hints = create_hints_for_block(
            &current_block_script,
            next_address,
            &next_script,
            &all_inputs,
            &withdrawals,
        )?;

        let root_state_transition =
            QProvingJobDataID::block_state_transition_input_witness(checkpoint_id);
        let _ = SigHashFinalizer::finalize_sighashes::<PS>(
            proof_store,
            sighash_whitelist_tree,
            checkpoint_id,
            root_state_transition,
            &hints,
        )?;
        let tpl_transaction = hints[0].sighash_preimage.transaction.clone();
        let num_input_witnesses = all_inputs.len(); // 1 dummy, but also need the last block
        let leaf_jobs = plan_jobs(proof_store, &block_op_job_ids, num_input_witnesses, checkpoint_id)?;

        let leaf_jobs_debug_serialized = leaf_jobs.iter().map(|x|QProvingJobDataIDSerializedWrapped(x.to_fixed_bytes())).collect::<Vec<_>>();
        println!("leaf_jobs: {}", serde_json::to_string(&leaf_jobs_debug_serialized)?);

        Ok((
            leaf_jobs,
            checkpoint_id,
            num_input_witnesses,
            tpl_transaction,
        ))
    }
    fn step_2_produce_block_finalize_and_transact_internal<
        PS: QProofStore,
        BTC: QBitcoinAPISync,
    >(
        proof_store: &mut PS,
        btc_api: &mut BTC,
        part_1_result: &SimpleActorOrchestratorProduceBlockStep1Result,
    ) -> anyhow::Result<Hash256> {
        let mut final_tx = part_1_result.template_transaction.clone();
        let block_script = final_tx.inputs[0].script.clone();
        let g16_proof_output_ids = (0..part_1_result.num_input_witnesses)
            .map(|i| {
                QProvingJobDataID::wrap_sighash_final_bls3812_input_witness(
                    part_1_result.checkpoint_id,
                    i,
                )
                .get_output_id()
            })
            .collect::<Vec<_>>();
        let proof_outputs = g16_proof_output_ids
            .into_iter()
            .map(|x| {
                let bytes = proof_store.get_bytes_by_id(x)?;
                //tracing::info!("proof_output_bytes: {}", hex::encode(&bytes));
                let proof = bincode::deserialize::<CityGroth16ProofData>(&bytes)?;
                Ok(proof)
            })
            .collect::<anyhow::Result<Vec<CityGroth16ProofData>>>()?;
        let input_scripts = proof_outputs
            .into_iter()
            .map(|proof_output| {
                proof_output
                    .encode_witness_script(&BLOCK_GROTH16_ENCODED_VERIFIER_DATA[0], &block_script)
            })
            .collect::<Vec<_>>();

        for (i, input_script) in input_scripts.into_iter().enumerate() {
            final_tx.inputs[i].script = input_script;
        }
        let txid = btc_api.send_transaction(&final_tx)?;
        Ok(txid)
    }
}
