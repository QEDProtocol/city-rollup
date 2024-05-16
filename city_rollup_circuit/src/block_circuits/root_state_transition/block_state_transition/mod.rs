use city_common_circuit::circuits::traits::qstandard::QStandardCircuit;
use city_common_circuit::proof_minifier::pm_chain_dynamic::OASProofMinifierDynamicChain;
use city_crypto::hash::qhashout::QHashOut;
use city_rollup_common::qworker::job_id::QProvingJobDataID;
use city_rollup_common::qworker::job_witnesses::agg::CRBlockStateTransitionCircuitInput;
use city_rollup_common::qworker::job_witnesses::sighash::CRSigHashFinalGLCircuitInput;
use city_rollup_common::qworker::proof_store::QProofStoreReaderSync;
use city_rollup_common::qworker::verifier::QWorkerVerifyHelper;
use gnark_plonky2_wrapper::C;
use gnark_plonky2_wrapper::D;
use gnark_plonky2_wrapper::F;
use plonky2::iop::witness::PartialWitness;
use plonky2::iop::witness::WitnessWrite;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::circuit_data::CircuitData;
use plonky2::plonk::circuit_data::CommonCircuitData;
use plonky2::plonk::circuit_data::VerifierOnlyCircuitData;
use plonky2::plonk::config::AlgebraicHasher;
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::plonk::proof::ProofWithPublicInputsTarget;

use crate::sighash_circuits::sighash_final_gl::CRSigHashFinalGLCircuit;
use crate::state::block_state_transition::BlockStateTransitionGadget;
use crate::worker::toolbox::root::CRWorkerToolboxRootCircuits;
use crate::worker::traits::QWorkerCircuitCompressWithDataSync;
use crate::worker::traits::QWorkerCircuitCustomWithDataSync;

#[derive(Debug)]
pub struct CRBlockStateTransitionCircuit<C: GenericConfig<D> + 'static, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub agg_user_register_claim_deposits_l2_transfer_proof: ProofWithPublicInputsTarget<D>,
    pub agg_add_process_withdrawals_add_l1_deposit_proof: ProofWithPublicInputsTarget<D>,

    pub transition_gadget: BlockStateTransitionGadget,
    // end circuit targets
    pub minifier_chain: OASProofMinifierDynamicChain<D, C::F, C>,
    pub circuit_data: CircuitData<C::F, C, D>,
}
impl<C: GenericConfig<D> + 'static, const D: usize> CRBlockStateTransitionCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub fn new(
        part_1_child_common_data: &CommonCircuitData<C::F, D>,
        part_1_child_verifier_data: &VerifierOnlyCircuitData<C, D>,
        part_2_child_common_data: &CommonCircuitData<C::F, D>,
        part_2_child_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);

        let agg_user_register_claim_deposits_l2_transfer_proof =
            builder.add_virtual_proof_with_pis(part_1_child_common_data);
        let agg_user_register_claim_deposits_l2_transfer_verifier_data =
            builder.constant_verifier_data(part_1_child_verifier_data);

        let agg_add_process_withdrawals_add_l1_deposit_proof =
            builder.add_virtual_proof_with_pis(part_2_child_common_data);
        let agg_add_process_withdrawals_add_l1_deposit_verifier_data =
            builder.constant_verifier_data(part_2_child_verifier_data);

        builder.verify_proof::<C>(
            &agg_user_register_claim_deposits_l2_transfer_proof,
            &agg_user_register_claim_deposits_l2_transfer_verifier_data,
            part_1_child_common_data,
        );

        builder.verify_proof::<C>(
            &agg_add_process_withdrawals_add_l1_deposit_proof,
            &agg_add_process_withdrawals_add_l1_deposit_verifier_data,
            part_2_child_common_data,
        );

        let transition_gadget = BlockStateTransitionGadget::add_virtual_to::<C::Hasher, C::F, D>(
            &mut builder,
            &agg_user_register_claim_deposits_l2_transfer_proof.public_inputs,
            &agg_add_process_withdrawals_add_l1_deposit_proof.public_inputs,
        );

        builder.register_public_inputs(
            &transition_gadget
                .combined_state_transition
                .state_transition_start
                .elements,
        );
        builder.register_public_inputs(
            &transition_gadget
                .combined_state_transition
                .state_transition_end
                .elements,
        );
        builder.register_public_inputs(&transition_gadget.withdrawal_events_hash.elements);
        builder.register_public_inputs(&transition_gadget.deposit_events_hash.elements);

        let circuit_data = builder.build::<C>();
        let minifier_chain =
            OASProofMinifierDynamicChain::new(&circuit_data.verifier_only, &circuit_data.common, 1);
        Self {
            agg_add_process_withdrawals_add_l1_deposit_proof,
            agg_user_register_claim_deposits_l2_transfer_proof,
            transition_gadget,
            circuit_data,
            minifier_chain,
        }
    }
    pub fn prove_base(
        &self,
        input: &CRBlockStateTransitionCircuitInput<C::F>,
        agg_user_register_claim_deposits_l2_transfer_proof: &ProofWithPublicInputs<C::F, C, D>,
        agg_add_process_withdrawals_add_l1_deposit_proof: &ProofWithPublicInputs<C::F, C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut pw = PartialWitness::new();
        println!("setting proof for op_add_l1_withdrawal_proof");

        pw.set_proof_with_pis_target::<C, D>(
            &self.agg_user_register_claim_deposits_l2_transfer_proof,
            agg_user_register_claim_deposits_l2_transfer_proof,
        );
        println!("setting verifier data for agg_add_process_withdrawals_add_l1_deposit_proof");

        pw.set_proof_with_pis_target::<C, D>(
            &self.agg_add_process_withdrawals_add_l1_deposit_proof,
            agg_add_process_withdrawals_add_l1_deposit_proof,
        );

        println!("proofs finished!");

        self.transition_gadget.set_witness(&mut pw, input);

        let inner_proof = self.circuit_data.prove(pw)?;
        println!("proved_inner");
        self.minifier_chain.prove(&inner_proof)
    }
}

impl<C: GenericConfig<D> + 'static, const D: usize> QStandardCircuit<C, D>
    for CRBlockStateTransitionCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn get_fingerprint(&self) -> QHashOut<C::F> {
        QHashOut(self.minifier_chain.get_fingerprint())
    }

    fn get_verifier_config_ref(&self) -> &VerifierOnlyCircuitData<C, D> {
        self.minifier_chain.get_verifier_data()
    }

    fn get_common_circuit_data_ref(&self) -> &CommonCircuitData<C::F, D> {
        self.minifier_chain.get_common_data()
    }
}

impl<
        V: QWorkerVerifyHelper<C, D>,
        S: QProofStoreReaderSync,
        C: GenericConfig<D> + 'static,
        const D: usize,
    > QWorkerCircuitCustomWithDataSync<V, S, C, D> for CRBlockStateTransitionCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn prove_q_worker_custom(
        &self,
        _verify_helper: &V,
        store: &S,
        job_id: QProvingJobDataID,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let input_data = store.get_bytes_by_id(job_id)?;
        let input = bincode::deserialize::<CRBlockStateTransitionCircuitInput<C::F>>(&input_data)?;

        let agg_user_register_claim_deposits_l2_transfer_proof =
            store.get_proof_by_id(input.agg_user_register_claim_deposits_l2_transfer.proof_id)?;
        let agg_add_process_withdrawals_add_l1_deposit_proof =
            store.get_proof_by_id(input.agg_add_process_withdrawals_add_l1_deposit.proof_id)?;
        self.prove_base(
            &input,
            &agg_user_register_claim_deposits_l2_transfer_proof,
            &agg_add_process_withdrawals_add_l1_deposit_proof,
        )
    }
}


impl<
        S: QProofStoreReaderSync,
    > QWorkerCircuitCompressWithDataSync<S> for CRWorkerToolboxRootCircuits<C, D> {
    fn prove_q_worker_compress(
        &self,
        store: &S,
        job_id: QProvingJobDataID,
    ) -> anyhow::Result<String> {
        let sighash_final_gl = CRSigHashFinalGLCircuit::<C, D>::new(
            self.block_state_transition.get_verifier_config_ref(),
            self.block_state_transition.get_common_circuit_data_ref(),
            self.sighash_wrapper.get_verifier_config_ref(),
            self.sighash_wrapper.get_common_circuit_data_ref(),
        );

        let inner_job_id = store.get_bytes_by_id(job_id)?;
        let inner_job = bincode::deserialize::<QProvingJobDataID>(&inner_job_id)?;

        let input_data = store.get_bytes_by_id(inner_job)?;
        let input = bincode::deserialize::<CRSigHashFinalGLCircuitInput<F>>(&input_data)?;

        let block_state_transition_proof =
            store.get_proof_by_id(input.state_transition_proof_id)?;
        let sighash_wrapper_proof = store.get_proof_by_id(input.sighash_introspection_proof_id)?;

        let proof = sighash_final_gl.prove_base(
            &input,
            &block_state_transition_proof,
            &sighash_wrapper_proof,
        )?;

        let g16_proof_str =
            gnark_plonky2_wrapper::wrap_plonky2_proof(sighash_final_gl.circuit_data, &proof)?;

        Ok(g16_proof_str)
    }
}
