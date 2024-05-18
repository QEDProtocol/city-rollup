use city_common::{
    config::rollup_constants::{BLOCK_SCRIPT_SPEND_BASE_FEE_AMOUNT, WITHDRAWAL_FEE_AMOUNT},
    logging::debug_timer::DebugTimer,
};
use city_crypto::hash::base_types::hash160::Hash160;
use city_rollup_common::{
    actors::{
        requested_actions::CityScenarioRequestedActions,
        rpc_processor::CityScenarioRequestedActionsFromRPC,
        traits::{OrchestratorEventReceiverSync, QBitcoinAPISync},
    },
    api::data::store::CityL1Withdrawal,
    config::sighash_wrapper_config::SIGHASH_CIRCUIT_MAX_WITHDRAWALS,
    introspection::{
        rollup::introspection::BlockSpendIntrospectionHint,
        sighash::{SigHashPreimage, SIGHASH_ALL},
        transaction::{BTCTransaction, BTCTransactionInput, BTCTransactionOutput},
    },
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

use crate::debug::scenario::{
    block_planner::planner::CityOrchestratorBlockPlanner, sighash::finalizer::SigHashFinalizer,
};

pub struct SimpleActorOrchestrator {
    pub fingerprints: CRWorkerToolboxCoreCircuitFingerprints<F>,
}
pub fn create_hints_for_block(
    current_script: &[u8],
    next_address: Hash160,
    next_script: &[u8],
    block_utxo: BTCTransaction,
    deposits: &[BTCTransaction],
    withdrawals: &[CityL1Withdrawal],
) -> anyhow::Result<Vec<BlockSpendIntrospectionHint>> {
    let base_inputs = [
        vec![block_utxo],
        deposits.to_vec().into_iter().skip(1).collect::<Vec<_>>(),
    ]
    .concat();

    let total_balance = base_inputs.iter().map(|x| x.outputs[0].value).sum::<u64>();
    let total_withdrawals = withdrawals.iter().map(|x| x.value).sum::<u64>();
    let total_fees =
        WITHDRAWAL_FEE_AMOUNT * (withdrawals.len() as u64) + BLOCK_SCRIPT_SPEND_BASE_FEE_AMOUNT;
    if total_fees > total_balance {
        anyhow::bail!("total fees exceed total balance");
    }

    let next_block_balance = total_balance - total_withdrawals;

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
        inputs: base_inputs
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
        funding_transactions: deposits.to_vec(),
        next_block_redeem_script: next_script.to_vec(),
    };
    let mut spend_hints: Vec<BlockSpendIntrospectionHint> = vec![hint];
    let inputs_len = base_inputs.len();
    for i in 0..inputs_len {
        let mut next_block_sighash_preimage_output = base_sighash_preimage.clone();
        next_block_sighash_preimage_output.transaction.inputs[i + 1].script =
            current_script.to_vec();
        let hint = BlockSpendIntrospectionHint {
            sighash_preimage: next_block_sighash_preimage_output,
            last_block_spend_index: 0,
            block_spend_index: 0,
            current_spend_index: i,
            funding_transactions: deposits.to_vec(),
            next_block_redeem_script: next_script.to_vec(),
        };
        spend_hints.push(hint);
    }

    Ok(spend_hints)
}
impl SimpleActorOrchestrator {
    pub fn produce_block<
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
    ) -> anyhow::Result<Vec<QProvingJobDataID>> {
        let mut timer = DebugTimer::new("produce_block");
        let last_block = CityStore::get_latest_block_state(store)?;
        let last_block_address =
            CityStore::get_city_block_deposit_address(store, last_block.checkpoint_id)?;
        let last_block_script = CityStore::get_city_block_script(store, last_block.checkpoint_id)?;

        let checkpoint_id = last_block.checkpoint_id + 1;

        let register_users = event_receiver.flush_register_users()?;
        let claim_l1_deposits = event_receiver.flush_claim_deposits()?;
        let add_withdrawals = event_receiver.flush_add_withdrawals()?;
        let token_transfers = event_receiver.flush_token_transfers()?;

        let utxos = btc_api.get_utxos(last_block_address)?;
        let mut deposit_utxos = vec![BTCTransaction::dummy()];
        let mut last_block_utxo = BTCTransaction::dummy();
        for utxo in utxos.into_iter() {
            if utxo.is_p2pkh() {
                deposit_utxos.push(utxo);
            } else if utxo.is_block_spend_for_state(last_block_address) {
                last_block_utxo = utxo;
            }
        }
        if last_block_utxo.is_dummy() {
            anyhow::bail!("utxo not funded by last block");
        }

        let block_requested = CityScenarioRequestedActions::new_from_requested_rpc(
            CityScenarioRequestedActionsFromRPC {
                register_users,
                claim_l1_deposits,
                add_withdrawals,
                token_transfers,
            },
            deposit_utxos.iter(),
            &last_block,
            SIGHASH_CIRCUIT_MAX_WITHDRAWALS,
        );

        let mut block_planner =
            CityOrchestratorBlockPlanner::<S, PS>::new(fingerprints.clone(), last_block);
        timer.lap("end process state block 1 RPC");
        timer.lap("start process requests block 1");

        let (block_state, block_op_job_ids, _block_state_transition, _block_end_jobs, withdrawals) =
            block_planner.process_requests(store, proof_store, &block_requested)?;
        let next_address = CityStore::get_city_block_deposit_address(store, checkpoint_id)?;
        let next_script = CityStore::get_city_block_script(store, checkpoint_id)?;
        let hints = create_hints_for_block(
            &last_block_script,
            next_address,
            &next_script,
            last_block_utxo,
            &deposit_utxos,
            &withdrawals,
        )?;
        let agg_jobs_for_inputs = (0..(deposit_utxos.len() - 1))
            .map(|i| QProvingJobDataID::get_block_aggregate_jobs_group(checkpoint_id, 1, i as u32))
            .collect::<Vec<_>>();

        proof_store.write_next_jobs(
            &agg_jobs_for_inputs,
            &[QProvingJobDataID::notify_block_complete(checkpoint_id)],
        )?;

        let per_input_jobs = (0..(deposit_utxos.len() - 1))
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
        Ok(leaf_jobs)
    }
}
