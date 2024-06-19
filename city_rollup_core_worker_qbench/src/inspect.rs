use city_common::cli::{args::InspectL2DumpArgs, modes::QDumpInspectionData};
use city_rollup_common::qworker::{
    dump::dump_job_dependencies_from_store, job_id::QProvingJobDataID,
    proof_store::QProofStoreReaderSync,
};
use city_rollup_common::qworker::{
    dump::QJobWithDependenciesSerialized,
    job_id::{ProvingJobDataType, QJobTopic},
    job_witnesses::inspect::{QJobProofPublicInputs, QJobWitnessWithId},
};
use city_rollup_core_orchestrator::debug::scenario::{
    actors::job_planner::plan_jobs, block_planner::transition::CityOpJobIds,
};
use plonky2::{
    field::goldilocks_field::GoldilocksField, hash::hash_types::RichField,
    plonk::config::PoseidonGoldilocksConfig,
};
use serde::{Deserialize, Serialize};

use crate::dump::{get_rpc_proof_dependencies, BlockProofStoreDump, DumpProofStoreConfig};

#[derive(Serialize, Deserialize, Clone)]
#[serde(bound = "")]
pub struct InspectDumpOutput<F: RichField> {
    pub dependency_map: Option<QJobWithDependenciesSerialized>,
    pub job_config: Option<DumpProofStoreConfig>,
    pub signature_proof_dependency_ids: Option<Vec<QProvingJobDataID>>,
    pub proof_witnesses: Option<Vec<QJobWitnessWithId<F>>>,
    pub proof_public_inputs: Option<Vec<QJobProofPublicInputs<F>>>,
}
pub fn run_inspect_l2_dump(args: &InspectL2DumpArgs) -> anyhow::Result<()> {
    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    let root = std::env::current_dir()?;
    let input_path = root.join(args.input.clone()).display().to_string();
    let input_bytes = std::fs::read(input_path)?;
    let dump: BlockProofStoreDump = bincode::deserialize(&input_bytes)?;
    let dump_config = dump.config.clone();
    let block_op_job_ids =
        CityOpJobIds::dummy_from_config(dump_config.checkpoint_id, &dump_config.job_config);
    let num_input_witnesses = dump_config.job_config.add_deposit_count + 1;

    let mut proof_store = dump.store.clone();

    let leaves = plan_jobs(
        &mut proof_store,
        &block_op_job_ids,
        num_input_witnesses,
        dump_config.checkpoint_id,
    )?;
    let dependency_map = dump_job_dependencies_from_store(&proof_store, &leaves)?;

    let dep_tree = dependency_map.get_dependency_tree_for_block(dump_config.checkpoint_id);
    let rpc_signature_proof_dependencies_ids = get_rpc_proof_dependencies(&dump_config)?;
    let all_job_ids = dep_tree.get_all_dependencies();
    let proof_job_input_witness_ids = all_job_ids
        .iter()
        .filter(|id| {
            id.topic.eq(&QJobTopic::GenerateStandardProof)
                && id.data_type.eq(&ProvingJobDataType::InputWitness)
        })
        .collect::<Vec<_>>();

    let proof_job_output_ids = proof_job_input_witness_ids
        .iter()
        .map(|id| id.get_output_id())
        .collect::<Vec<_>>();

    let all_proof_result_ids: Vec<QProvingJobDataID> = [
        rpc_signature_proof_dependencies_ids.clone(),
        proof_job_output_ids,
    ]
    .concat();

    let mut result = InspectDumpOutput::<F> {
        dependency_map: None,
        job_config: None,
        signature_proof_dependency_ids: None,
        proof_witnesses: None,
        proof_public_inputs: None,
    };
    if args.data.contains(&QDumpInspectionData::DependencyMap) {
        result.dependency_map = Some(dep_tree.to_serialized());
    }
    if args.data.contains(&QDumpInspectionData::JobConfig) {
        result.job_config = Some(dump_config);
    }
    if args.data.contains(&QDumpInspectionData::SignatureProofIds) {
        result.signature_proof_dependency_ids = Some(rpc_signature_proof_dependencies_ids);
    }
    if args.data.contains(&QDumpInspectionData::ProofWitnesses) {
        let proof_witnesses = proof_job_input_witness_ids
            .into_iter()
            .map(|id| {
                let data = proof_store.get_bytes_by_id(*id)?;
                QJobWitnessWithId::<F>::try_deserialize_witness(*id, &data)
            })
            .collect::<anyhow::Result<Vec<QJobWitnessWithId<F>>>>()?;
        result.proof_witnesses = Some(proof_witnesses);
    }

    if args.data.contains(&QDumpInspectionData::ProofPublicInputs) {
        /*
        let proof_public_inputs = all_proof_result_ids.iter().map(|id| {
          println!("Getting proof public inputs for id: {:?}", id);
          let data = proof_store.get_proof_by_id::<C, D>(*id)?;
          Ok(QJobProofPublicInputs::new(*id, data.public_inputs.clone()))
        }).collect::<anyhow::Result<Vec<QJobProofPublicInputs<F>>>>()?;
        result.proof_public_inputs = Some(proof_public_inputs);
        */

        let proof_public_inputs = all_proof_result_ids
            .iter()
            .map(|id| {
                let data = proof_store.get_proof_by_id::<C, D>(*id);
                if data.is_err() {
                    None
                } else {
                    Some(QJobProofPublicInputs::new(*id, data.unwrap().public_inputs))
                }
            })
            .filter(|x| x.is_some())
            .map(|x| x.unwrap())
            .collect::<Vec<QJobProofPublicInputs<F>>>();
        result.proof_public_inputs = Some(proof_public_inputs);
    }

    if args.output.is_empty() {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        let output_path = root.join(args.output.clone()).display().to_string();
        std::fs::write(output_path, serde_json::to_string_pretty(&result)?)?;
    }
    Ok(())
}
