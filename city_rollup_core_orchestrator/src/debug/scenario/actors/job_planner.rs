use city_rollup_common::qworker::{job_id::QProvingJobDataID, proof_store::QProofStore};

use crate::debug::scenario::block_planner::transition::CityOpJobIds;

pub fn plan_jobs<PS: QProofStore>(
    proof_store: &mut PS,
    block_op_job_ids: &CityOpJobIds,
    num_input_witnesses: usize,
    checkpoint_id: u64,
) -> anyhow::Result<Vec<QProvingJobDataID>> {
    let root_state_transition =
        QProvingJobDataID::block_state_transition_input_witness(checkpoint_id);

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
                QProvingJobDataID::sighash_root_input_witness(checkpoint_id, i),
                QProvingJobDataID::sighash_final_input_witness(checkpoint_id, i),
                QProvingJobDataID::sighash_introspection_input_witness(checkpoint_id, i),
            )
        })
        .collect::<Vec<_>>();

    for (i, pij) in per_input_jobs.iter().enumerate() {
        proof_store.write_next_jobs(&[pij.0], &[agg_jobs_for_inputs[i]])?;
        proof_store.write_next_jobs(&[pij.1], &[pij.0])?;
        proof_store.write_next_jobs(&[pij.2], &[pij.1])?;
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
    let introspection_jobs = per_input_jobs.iter().map(|x| x.3).collect::<Vec<_>>();
    proof_store.write_next_jobs(&introspection_jobs, &[agg_all_introspections_ids])?;
    let final_input_witness_jobs = per_input_jobs.iter().map(|x| x.2).collect::<Vec<_>>();
    proof_store.write_next_jobs(
        &[agg_state_root_id, agg_all_introspections_ids],
        &final_input_witness_jobs,
    )?;

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

    let state_part_1_id = QProvingJobDataID::block_agg_state_part_1_input_witness(checkpoint_id);
    let state_part_2_id = QProvingJobDataID::block_agg_state_part_2_input_witness(checkpoint_id);

    proof_store.write_next_jobs(
        &[state_part_1_common_id, state_part_2_common_id],
        &[root_state_transition],
    )?;

    proof_store.write_next_jobs(&[state_part_1_id], &[state_part_1_common_id])?;
    proof_store.write_next_jobs(&[state_part_2_id], &[state_part_2_common_id])?;

    let op_agg_group_part_1_id = 11;
    let register_users_agg_job_id =
        QProvingJobDataID::get_block_aggregate_jobs_group(checkpoint_id, op_agg_group_part_1_id, 0);
    let claim_deposits_agg_job_id =
        QProvingJobDataID::get_block_aggregate_jobs_group(checkpoint_id, op_agg_group_part_1_id, 1);
    let transfer_tokens_agg_job_id =
        QProvingJobDataID::get_block_aggregate_jobs_group(checkpoint_id, op_agg_group_part_1_id, 2);

    proof_store.write_next_jobs(
        &[
            register_users_agg_job_id,
            claim_deposits_agg_job_id,
            transfer_tokens_agg_job_id,
        ],
        &[state_part_1_id],
    )?;

    let op_agg_group_part_2_id = 12;
    let add_withdrawals_agg_job_id =
        QProvingJobDataID::get_block_aggregate_jobs_group(checkpoint_id, op_agg_group_part_2_id, 0);
    let process_withdrawals_agg_job_id =
        QProvingJobDataID::get_block_aggregate_jobs_group(checkpoint_id, op_agg_group_part_2_id, 1);
    let add_deposits_agg_job_id =
        QProvingJobDataID::get_block_aggregate_jobs_group(checkpoint_id, op_agg_group_part_2_id, 2);

    proof_store.write_next_jobs(
        &[
            add_withdrawals_agg_job_id,
            process_withdrawals_agg_job_id,
            add_deposits_agg_job_id,
        ],
        &[state_part_2_id],
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

    Ok(leaf_jobs)
}
