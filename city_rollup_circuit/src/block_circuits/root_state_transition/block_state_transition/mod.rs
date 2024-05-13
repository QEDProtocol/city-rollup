use city_common_circuit::{
    circuits::traits::qstandard::QStandardCircuit,
    proof_minifier::pm_chain_dynamic::OASProofMinifierDynamicChain,
};
use city_crypto::hash::qhashout::QHashOut;
use city_rollup_common::qworker::{
    job_id::QProvingJobDataID, job_witnesses::agg::CRBlockStateTransitionCircuitInput,
    proof_store::QProofStoreReaderSync, verifier::QWorkerVerifyHelper,
};
use plonky2::{
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};

use crate::{
    state::block_state_transition::BlockStateTransitionGadget,
    worker::traits::QWorkerCircuitCustomWithDataSync,
};

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

        self.circuit_data.prove(pw)
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

        let inner_proof = self.prove_base(
            &input,
            &agg_user_register_claim_deposits_l2_transfer_proof,
            &agg_add_process_withdrawals_add_l1_deposit_proof,
        )?;
        self.minifier_chain.prove(&inner_proof)
    }
}
