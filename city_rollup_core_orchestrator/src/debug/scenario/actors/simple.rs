use city_common::{
    config::rollup_constants::{BLOCK_SCRIPT_SPEND_BASE_FEE_AMOUNT, WITHDRAWAL_FEE_AMOUNT},
    logging::debug_timer::DebugTimer,
};
use city_crypto::hash::base_types::{hash160::Hash160, hash256::Hash256};
use city_rollup_common::{
    actors::{
        requested_actions::CityScenarioRequestedActions,
        rpc_processor::CityScenarioRequestedActionsFromRPC,
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
        fingerprints::CRWorkerToolboxCoreCircuitFingerprints, job_id::QProvingJobDataID,
        proof_store::QProofStore,
    },
};
use city_store::{
    config::F,
    store::{city::base::CityStore, sighash::SigHashMerkleTree},
};
use kvq::traits::KVQBinaryStore;
use serde::{Deserialize, Serialize};

use crate::debug::scenario::{
    block_planner::planner::CityOrchestratorBlockPlanner, sighash::finalizer::SigHashFinalizer,
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
    let hint = BlockSpendIntrospectionHint {
        sighash_preimage: next_block_sighash_preimage_output,
        last_block_spend_index: 0,
        block_spend_index: 0,
        current_spend_index: 0,
        funding_transactions: all_inputs.to_vec(),
        next_block_redeem_script: next_script.to_vec(),
    };
    let mut spend_hints: Vec<BlockSpendIntrospectionHint> = vec![hint];
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
        println!(
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
        println!("a");

        let last_block = CityStore::get_latest_block_state(store)?;
        println!("last_block: {}", last_block.checkpoint_id);
        println!("current_building_block: {}", last_block.checkpoint_id + 1);
        println!("b");
        let last_block_address =
            CityStore::get_city_block_deposit_address(store, last_block.checkpoint_id - 1)?;
        println!("last_block address: {}", last_block_address.to_p2sh_address());
        println!("c");
        let current_block_address =
            CityStore::get_city_block_deposit_address(store, last_block.checkpoint_id + 1)?;
        println!("current block address: {}", current_block_address.to_p2sh_address());
        println!("d");
        let current_block_script =
            CityStore::get_city_block_script(store, last_block.checkpoint_id + 1)?;
        println!("current block script: {}", hex::encode(&current_block_script));

        let checkpoint_id = last_block.checkpoint_id + 1;
        let mut timer = DebugTimer::new(&format!("produce_block [{}]", checkpoint_id));

        let register_users = event_receiver.flush_register_users()?;
        let claim_l1_deposits = event_receiver.flush_claim_deposits()?;
        let add_withdrawals = event_receiver.flush_add_withdrawals()?;
        let token_transfers = event_receiver.flush_token_transfers()?;
        /*println!(
            "last_block_address: {}",
            BTCAddress160::new_p2sh(last_block_address,).to_address_string()
        );
        println!(
            "current_block_address: {}",
            BTCAddress160::new_p2sh(current_block_address,).to_address_string()
        );*/

        println!(
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
            //println!("utxos: {}", hex::encode(&utxo.to_bytes()));

            if utxo.is_block_spend_for_state(last_block_address) {
                last_block_utxo = utxo;
            } else if utxo.is_p2pkh() {
                deposit_utxos.push(utxo);
            } else {
                println!("abnormal utxo, ignoring: {}", hex::encode(&utxo.to_bytes()));
            }
        }
        if last_block_utxo.is_dummy() {
            anyhow::bail!("utxo not funded by last block");
        }
        println!(
            "found {} deposits for block {}",
            deposit_utxos.len(),
            checkpoint_id
        );

        let mut all_inputs = vec![last_block_utxo];
        all_inputs.append(&mut deposit_utxos);

        let block_requested = CityScenarioRequestedActions::new_from_requested_rpc(
            CityScenarioRequestedActionsFromRPC {
                register_users,
                claim_l1_deposits,
                add_withdrawals,
                token_transfers,
            },
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
        println!("d");

        let (block_state, block_op_job_ids, _block_state_transition, _block_end_jobs, withdrawals) =
            block_planner.process_requests(store, proof_store, &block_requested)?;
        println!("e");

        let next_address = CityStore::get_city_block_deposit_address(store, checkpoint_id + 1)?;
        println!("block {} address: {}", checkpoint_id + 1, next_address.to_p2sh_address());
        let next_script = CityStore::get_city_block_script(store, checkpoint_id + 1)?;
        println!("block {} script: {}", checkpoint_id + 1, hex::encode(&next_script));
        /*println!(
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
        let tpl_transaction = hints[0].sighash_preimage.transaction.clone();
        let num_input_witnesses = all_inputs.len(); // 1 dummy, but also need the last block
        let agg_jobs_for_inputs: Vec<QProvingJobDataID> = (0..num_input_witnesses)
            .map(|i| QProvingJobDataID::get_block_aggregate_jobs_group(checkpoint_id, 1, i as u32))
            .collect::<Vec<_>>();

        proof_store.write_next_jobs(
            &agg_jobs_for_inputs,
            &[QProvingJobDataID::notify_block_complete(checkpoint_id)],
        )?;

        let per_input_jobs = (0..num_input_witnesses)
            .map(|i| {
                (
                    QProvingJobDataID::wrap_sighash_final_bls3812_input_witness(checkpoint_id, i),
                    QProvingJobDataID::sighash_final_input_witness(checkpoint_id, i),
                    QProvingJobDataID::sighash_introspection_input_witness(checkpoint_id, i),
                )
            })
            .collect::<Vec<_>>();

        for (i, pij) in per_input_jobs.iter().enumerate() {
            proof_store.write_next_jobs(&[pij.0], &[agg_jobs_for_inputs[i]])?;
            proof_store.write_next_jobs(&[pij.1], &[pij.0])?;
        }
        let agg_state_and_introspections_group_id = 5;
        let agg_state_root_id = QProvingJobDataID::get_block_aggregate_jobs_group(
            checkpoint_id,
            agg_state_and_introspections_group_id,
            0,
        );
        let agg_all_introspections_ids = QProvingJobDataID::get_block_aggregate_jobs_group(
            checkpoint_id,
            agg_state_and_introspections_group_id,
            1,
        );
        let introspection_jobs = per_input_jobs.iter().map(|x| x.2).collect::<Vec<_>>();
        proof_store.write_next_jobs(&introspection_jobs, &[agg_all_introspections_ids])?;
        let final_input_witness_jobs = per_input_jobs.iter().map(|x| x.1).collect::<Vec<_>>();
        proof_store.write_next_jobs(
            &[agg_state_root_id, agg_all_introspections_ids],
            &final_input_witness_jobs,
        )?;

        let root_state_transition =
            QProvingJobDataID::block_state_transition_input_witness(checkpoint_id);
        proof_store.write_next_jobs(&[root_state_transition], &[agg_state_root_id])?;

        let op_agg_group_parts_common_id = 6;

        let state_part_1_common_id = QProvingJobDataID::get_block_aggregate_jobs_group(
            checkpoint_id,
            op_agg_group_parts_common_id,
            0,
        );
        let state_part_2_common_id = QProvingJobDataID::get_block_aggregate_jobs_group(
            checkpoint_id,
            op_agg_group_parts_common_id,
            1,
        );

        let state_part_1_id =
            QProvingJobDataID::block_agg_state_part_1_input_witness(checkpoint_id);
        let state_part_2_id =
            QProvingJobDataID::block_agg_state_part_2_input_witness(checkpoint_id);

        proof_store.write_next_jobs(
            &[state_part_1_common_id, state_part_2_common_id],
            &[root_state_transition],
        )?;

        proof_store.write_next_jobs(&[state_part_1_id], &[state_part_1_common_id])?;
        proof_store.write_next_jobs(&[state_part_2_id], &[state_part_2_common_id])?;

        let op_agg_group_part_1_id = 11;
        let register_users_agg_job_id = QProvingJobDataID::get_block_aggregate_jobs_group(
            checkpoint_id,
            op_agg_group_part_1_id,
            0,
        );
        let claim_deposits_agg_job_id = QProvingJobDataID::get_block_aggregate_jobs_group(
            checkpoint_id,
            op_agg_group_part_1_id,
            1,
        );
        let transfer_tokens_agg_job_id = QProvingJobDataID::get_block_aggregate_jobs_group(
            checkpoint_id,
            op_agg_group_part_1_id,
            2,
        );

        proof_store.write_next_jobs(
            &[
                register_users_agg_job_id,
                claim_deposits_agg_job_id,
                transfer_tokens_agg_job_id,
            ],
            &[state_part_1_id],
        )?;

        let op_agg_group_part_2_id = 12;
        let add_withdrawals_agg_job_id = QProvingJobDataID::get_block_aggregate_jobs_group(
            checkpoint_id,
            op_agg_group_part_2_id,
            0,
        );
        let process_withdrawals_agg_job_id = QProvingJobDataID::get_block_aggregate_jobs_group(
            checkpoint_id,
            op_agg_group_part_2_id,
            1,
        );
        let add_deposits_agg_job_id = QProvingJobDataID::get_block_aggregate_jobs_group(
            checkpoint_id,
            op_agg_group_part_2_id,
            2,
        );

        proof_store.write_next_jobs(
            &[
                add_withdrawals_agg_job_id,
                process_withdrawals_agg_job_id,
                add_deposits_agg_job_id,
            ],
            &[state_part_2_id],
        )?;

        let _ = SigHashFinalizer::finalize_sighashes::<PS>(
            proof_store,
            sighash_whitelist_tree,
            checkpoint_id,
            root_state_transition,
            &hints,
        )?;

        proof_store.write_multidimensional_jobs(
            &block_op_job_ids.register_user_job_ids,
            &[register_users_agg_job_id],
        )?;
        proof_store.write_multidimensional_jobs(
            &block_op_job_ids.claim_deposit_job_ids,
            &[claim_deposits_agg_job_id],
        )?;
        proof_store.write_multidimensional_jobs(
            &block_op_job_ids.token_transfer_job_ids,
            &[transfer_tokens_agg_job_id],
        )?;

        proof_store.write_multidimensional_jobs(
            &block_op_job_ids.add_withdrawal_job_ids,
            &[add_withdrawals_agg_job_id],
        )?;
        proof_store.write_multidimensional_jobs(
            &block_op_job_ids.process_withdrawal_job_ids,
            &[process_withdrawals_agg_job_id],
        )?;
        proof_store.write_multidimensional_jobs(
            &block_op_job_ids.add_deposit_job_ids,
            &[add_deposits_agg_job_id],
        )?;

        let leaf_jobs = [
            introspection_jobs,
            block_op_job_ids.register_user_job_ids[0].to_vec(),
            block_op_job_ids.claim_deposit_job_ids[0].to_vec(),
            block_op_job_ids.token_transfer_job_ids[0].to_vec(),
            block_op_job_ids.add_withdrawal_job_ids[0].to_vec(),
            block_op_job_ids.process_withdrawal_job_ids[0].to_vec(),
            block_op_job_ids.add_deposit_job_ids[0].to_vec(),
        ]
        .concat();

        CityStore::set_block_state(store, &block_state)?;

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
                //println!("proof_output_bytes: {}", hex::encode(&bytes));
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
