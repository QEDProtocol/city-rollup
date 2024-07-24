use hashbrown::HashMap;

use city_common_circuit::{
    builder::{hash::core::CircuitBuilderHashCore, verify::CircuitBuilderVerifyProofHelpers},
    circuits::traits::qstandard::QStandardCircuit,
    field::cubic::CubicExtendable,
    hash::merkle::gadgets::merkle_proof::MerkleProofGadget,
    proof_minifier::pm_core::get_circuit_fingerprint_generic,
};
use city_crypto::hash::qhashout::QHashOut;
use city_rollup_common::{
    config::sighash_wrapper_config::{SIGHASH_CIRCUIT_WHITELIST_TREE_HEIGHT, SIGHASH_WHITELIST_DISABLED_DEV_MODE},
    introspection::rollup::introspection::BlockSpendCoreConfig,
    qworker::{
        job_id::QProvingJobDataID, job_witnesses::sighash::{CRSigHashWrapperCircuitInput, CRSigHashWrapperRefundCircuitInput},
        proof_store::QProofStoreReaderSync, verifier::QWorkerVerifyHelper,
    },
};
use plonky2::{
    field::types::Field,
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{
            CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget,
            VerifierOnlyCircuitData,
        },
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};

use crate::{sighash_circuits::sighash_refund::CRSigHashRefundCircuit, worker::traits::{
    QWorkerCircuitCustomWithDataSync, QWorkerCircuitMutCustomWithDataSync,
}};

use super::sighash::CRSigHashCircuit;

#[derive(Debug)]
pub struct CRSigHashWrapperCircuit<C: GenericConfig<D> + 'static, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
    C::F: CubicExtendable,
{
    pub sighash_circuit_cache: HashMap<usize, CRSigHashCircuit<C, D>>,
    pub sighash_refund_circuit_cache: Option<CRSigHashRefundCircuit<C, D>>,
    // [START] circuit targets
    pub proof_target: ProofWithPublicInputsTarget<D>,
    pub verifier_data_target: VerifierCircuitTarget,
    pub whitelist_merkle_proof: MerkleProofGadget,

    // [END] circuit targets
    pub circuit_data: CircuitData<C::F, C, D>,
    pub fingerprint: QHashOut<C::F>,
    //pub minifier: QEDProofMinifierDynamicChain<D, C::F, C>,
    //pub tracer: DebugCircuitTracer,
}
impl<C: GenericConfig<D>, const D: usize> CRSigHashWrapperCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
    C::F: CubicExtendable,
{
    pub fn new(sighash_circuit_whitelist_root: QHashOut<C::F>) -> Self {
        let introspection_config_base = BlockSpendCoreConfig::standard_p2sh_p2pkh()
            .generate_permutations(1, 1)
            .first()
            .unwrap()
            .to_owned();
        let child_circuit_0 = CRSigHashCircuit::<C, D>::new(introspection_config_base);
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);
        //let mut tracer = DebugCircuitTracer::new();

        let whitelist_merkle_proof = MerkleProofGadget::add_virtual_to::<C::Hasher, C::F, D>(
            &mut builder,
            SIGHASH_CIRCUIT_WHITELIST_TREE_HEIGHT as usize,
        );
        let expected_sighash_proof_fingerprint = whitelist_merkle_proof.value;

        let expected_root = builder.constant_whash(sighash_circuit_whitelist_root);
        builder.connect_hashes(whitelist_merkle_proof.root, expected_root);

        let proof_target =
            builder.add_virtual_proof_with_pis(child_circuit_0.get_common_circuit_data_ref());
        let verifier_data_target = builder.add_virtual_verifier_data(
            child_circuit_0
                .get_verifier_config_ref()
                .constants_sigmas_cap
                .height(),
        );

        builder.verify_proof::<C>(
            &proof_target,
            &verifier_data_target,
            child_circuit_0.get_common_circuit_data_ref(),
        );

        let proof_fingerprint = builder.get_circuit_fingerprint::<C::Hasher>(&verifier_data_target);

        if SIGHASH_WHITELIST_DISABLED_DEV_MODE {
            println!("\x1B[0m\x1B[38;5;227m\x1B[48;5;9m[SECURITY WARNING]\x1B[0m SIGHASH_WHITELIST_DISABLED_DEV_MODE is set to true, so the sighash wrapper circuit doesn't validate that the sighash introspection proof comes from a valid sighash circuit. SIGHASH_WHITELIST_DISABLED_DEV_MODE should \x1B[1m\x1B[38;5;9mNEVER\x1B[0m be set to true in production!\x1B[0m");
        }else{
            builder.connect_hashes(proof_fingerprint, expected_sighash_proof_fingerprint);
        }

        builder.register_public_inputs(&proof_target.public_inputs);
        let circuit_data = builder.build::<C>();
        /*
        let minifier = QEDProofMinifierDynamicChain::new_with_dynamic_constant_verifier(
            &circuit_data.verifier_only,
            &circuit_data.common,
            &[false, true, true],
        );
        */

        let fingerprint = QHashOut(get_circuit_fingerprint_generic::<D, C::F, C>(
            &circuit_data.verifier_only,
        ));
        let mut sighash_circuit_cache = HashMap::new();
        sighash_circuit_cache.insert(0, child_circuit_0);
        Self {
            sighash_circuit_cache,
            sighash_refund_circuit_cache: None,
            whitelist_merkle_proof,
            proof_target,
            verifier_data_target,
            circuit_data,
            fingerprint,
        }
    }
    pub fn prove_base_mut(
        &mut self,
        input: &CRSigHashWrapperCircuitInput<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let inner_proof = if self
            .sighash_circuit_cache
            .contains_key(&(input.whitelist_inclusion_proof.index as usize))
        {
            self.sighash_circuit_cache
                .get(&(input.whitelist_inclusion_proof.index as usize))
                .unwrap()
                .prove_base(&input.introspection_hint)?
        } else {
            let child_circuit =
                CRSigHashCircuit::<C, D>::new(input.introspection_hint.get_config());
            let proof = child_circuit.prove_base(&input.introspection_hint)?;
            self.sighash_circuit_cache.insert(
                input.whitelist_inclusion_proof.index as usize,
                child_circuit,
            );
            proof
        };
        let inner_verifier_data = self
            .sighash_circuit_cache
            .get(&(input.whitelist_inclusion_proof.index as usize))
            .unwrap()
            .get_verifier_config_ref();
        let mut pw = PartialWitness::new();

        pw.set_proof_with_pis_target(&self.proof_target, &inner_proof);
        pw.set_verifier_data_target(&self.verifier_data_target, inner_verifier_data);

        self.whitelist_merkle_proof.set_witness(
            &mut pw,
            C::F::from_canonical_u64(input.whitelist_inclusion_proof.index),
            input.whitelist_inclusion_proof.value,
            &input.whitelist_inclusion_proof.siblings,
        );
        self.circuit_data.prove(pw)
    }
    pub fn prove_base(
        &self,
        input: &CRSigHashWrapperCircuitInput<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        tracing::info!("proving sig hash introspection: {}",input.introspection_hint.sighash_preimage.get_hash().to_hex_string());
        let mut pw = PartialWitness::new();
        if self
            .sighash_circuit_cache
            .contains_key(&(input.whitelist_inclusion_proof.index as usize))
        {
            let child_circuit = self
                .sighash_circuit_cache
                .get(&(input.whitelist_inclusion_proof.index as usize))
                .unwrap();

            let inner_proof = child_circuit.prove_base(&input.introspection_hint)?;

            pw.set_proof_with_pis_target(&self.proof_target, &inner_proof);
            pw.set_verifier_data_target(
                &self.verifier_data_target,
                child_circuit.get_verifier_config_ref(),
            );
        } else {
            let child_circuit =
                CRSigHashCircuit::<C, D>::new(input.introspection_hint.get_config());
            let inner_proof = child_circuit.prove_base(&input.introspection_hint)?;
            pw.set_proof_with_pis_target(&self.proof_target, &inner_proof);
            pw.set_verifier_data_target(
                &self.verifier_data_target,
                child_circuit.get_verifier_config_ref(),
            );
        }
        self.whitelist_merkle_proof.set_witness(
            &mut pw,
            C::F::from_canonical_u64(input.whitelist_inclusion_proof.index),
            input.whitelist_inclusion_proof.value,
            &input.whitelist_inclusion_proof.siblings,
        );
        self.circuit_data.prove(pw)
    }
    pub fn prove_refund_mut(
        &mut self,
        input: &CRSigHashWrapperRefundCircuitInput<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        tracing::info!("proving sig hash refund introspection: {}",input.introspection_hint.sighash_preimage.get_hash().to_hex_string());
        let mut pw = PartialWitness::new();
        if let Some(ref refund_circuit) = self.sighash_refund_circuit_cache {
            let inner_proof = refund_circuit.prove_base(&input.introspection_hint)?;

            pw.set_proof_with_pis_target(&self.proof_target, &inner_proof);
            pw.set_verifier_data_target(
                &self.verifier_data_target,
                refund_circuit.get_verifier_config_ref(),
            );
        } else {
            let refund_circuit =
                CRSigHashRefundCircuit::<C, D>::new(input.introspection_hint.get_config());
            let inner_proof = refund_circuit.prove_base(&input.introspection_hint)?;
            pw.set_proof_with_pis_target(&self.proof_target, &inner_proof);
            pw.set_verifier_data_target(
                &self.verifier_data_target,
                refund_circuit.get_verifier_config_ref(),
            );
            self.sighash_refund_circuit_cache = Some(refund_circuit);
        }
        self.whitelist_merkle_proof.set_witness(
            &mut pw,
            C::F::from_canonical_u64(input.whitelist_inclusion_proof.index),
            input.whitelist_inclusion_proof.value,
            &input.whitelist_inclusion_proof.siblings,
        );
        self.circuit_data.prove(pw)
    }
    pub fn prove_refund(
        &self,
        input: &CRSigHashWrapperRefundCircuitInput<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        tracing::info!("proving sig hash refund introspection: {}",input.introspection_hint.sighash_preimage.get_hash().to_hex_string());
        let mut pw = PartialWitness::new();
        if let Some(ref refund_circuit) = self.sighash_refund_circuit_cache {
            let inner_proof = refund_circuit.prove_base(&input.introspection_hint)?;

            pw.set_proof_with_pis_target(&self.proof_target, &inner_proof);
            pw.set_verifier_data_target(
                &self.verifier_data_target,
                refund_circuit.get_verifier_config_ref(),
            );
        } else {
            let refund_circuit =
                CRSigHashRefundCircuit::<C, D>::new(input.introspection_hint.get_config());
            let inner_proof = refund_circuit.prove_base(&input.introspection_hint)?;
            pw.set_proof_with_pis_target(&self.proof_target, &inner_proof);
            pw.set_verifier_data_target(
                &self.verifier_data_target,
                refund_circuit.get_verifier_config_ref(),
            );
        }
        self.whitelist_merkle_proof.set_witness(
            &mut pw,
            C::F::from_canonical_u64(input.whitelist_inclusion_proof.index),
            input.whitelist_inclusion_proof.value,
            &input.whitelist_inclusion_proof.siblings,
        );
        self.circuit_data.prove(pw)
    }
}

impl<C: GenericConfig<D> + 'static, const D: usize> QStandardCircuit<C, D>
    for CRSigHashWrapperCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
    C::F: CubicExtendable,
{
    fn get_fingerprint(&self) -> QHashOut<C::F> {
        self.fingerprint
    }

    fn get_verifier_config_ref(&self) -> &VerifierOnlyCircuitData<C, D> {
        &self.circuit_data.verifier_only
    }

    fn get_common_circuit_data_ref(&self) -> &CommonCircuitData<C::F, D> {
        &self.circuit_data.common
    }
}
impl<S: QProofStoreReaderSync, C: GenericConfig<D> + 'static, const D: usize>
    QWorkerCircuitMutCustomWithDataSync<S, C, D> for CRSigHashWrapperCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
    C::F: CubicExtendable,
{
    fn prove_q_worker_mut_custom(
        &mut self,
        store: &S,
        job_id: QProvingJobDataID,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let input_bytes = store.get_bytes_by_id(job_id)?;
        let input: CRSigHashWrapperCircuitInput<C::F> = bincode::deserialize(&input_bytes)?;
        self.prove_base_mut(&input)
    }
}

impl<
        V: QWorkerVerifyHelper<C, D>,
        S: QProofStoreReaderSync,
        C: GenericConfig<D> + 'static,
        const D: usize,
    > QWorkerCircuitCustomWithDataSync<V, S, C, D> for CRSigHashWrapperCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
    C::F: CubicExtendable,
{
    fn prove_q_worker_custom(
        &self,
        _verify_helper: &V,
        store: &S,
        job_id: QProvingJobDataID,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let input_bytes = store.get_bytes_by_id(job_id)?;
        let input: CRSigHashWrapperCircuitInput<C::F> = bincode::deserialize(&input_bytes)?;
        self.prove_base(&input)
    }
}
