
use hashbrown::HashMap;

use city_common_circuit::{
    circuits::traits::qstandard::{
        provable::QStandardCircuitProvable, QStandardCircuit,
        QStandardCircuitProvableWithProofStoreSync,
    },
    field::cubic::CubicExtendable,
    hash::accelerator::sha256::{
        planner::{Sha256AcceleratorDomainPlanner, SmartSha256AcceleratorGadgetWithDomain},
        smartgadget::Sha256AirParametersStandard,
        Sha256Acc,
    },
    proof_minifier::pm_chain_dynamic::QEDProofMinifierDynamicChain,
};
use city_crypto::hash::qhashout::QHashOut;
use city_rollup_common::{
    introspection::rollup::{introspection::{
        BlockSpendCoreConfig, RefundIntrospectionGadgetConfig, RefundSpendIntrospectionHint
    }, introspection_result::BTCRollupRefundIntrospectionResult},
    qworker::{job_id::QProvingJobDataID, proof_store::QProofStoreReaderSync, verifier::QWorkerVerifyHelper},
};
use plonky2::{
    hash::hash_types::RichField, iop::{target::Target, witness::PartialWitness}, plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    }
};
use serde::{Deserialize, Serialize};

use crate::{introspection::gadgets::rollup::refund::BTCRollupRefundIntrospectionGadget, worker::traits::{QWorkerCircuitCustomWithDataSync, QWorkerCircuitMutCustomWithDataSync}};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(bound = "")]
pub struct CRSigHashRefundCircuitInput<F: RichField> {
    pub introspection_hint: RefundSpendIntrospectionHint,
    pub result: BTCRollupRefundIntrospectionResult<F>,
}

#[derive(Debug)]
pub struct CRSigHashRefundCircuit<C: GenericConfig<D> + 'static, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
    C::F: CubicExtendable,
{
    pub introspection_config: RefundIntrospectionGadgetConfig,

    // [START] circuit targets
    pub introspection_gadget: BTCRollupRefundIntrospectionGadget,
    pub sha256_acceleration_gadget: SmartSha256AcceleratorGadgetWithDomain<
        Sha256Acc,
        Sha256AirParametersStandard<C::F>,
        C,
        D,
        64,
    >,
    // [END] circuit targets
    pub circuit_data: CircuitData<C::F, C, D>,
    pub targets_to_constants: HashMap<Target, C::F>,
    pub fingerprint: QHashOut<C::F>,

    pub minifier: QEDProofMinifierDynamicChain<D, C::F, C>,
    //pub tracer: DebugCircuitTracer,
}
impl<C: GenericConfig<D> + 'static, const D: usize> Clone for CRSigHashRefundCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
    C::F: CubicExtendable,
{
    fn clone(&self) -> Self {
        Self::new()
    }
}
impl<C: GenericConfig<D>, const D: usize> CRSigHashRefundCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
    C::F: CubicExtendable,
{
    pub fn new() -> Self {
        let introspection_config_base = BlockSpendCoreConfig::standard_p2sh_p2pkh();
        let introspection_config = RefundIntrospectionGadgetConfig::generate_from_template(&introspection_config_base);
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);
        //let mut tracer = DebugCircuitTracer::new();

        let mut dp = Sha256AcceleratorDomainPlanner::new();

        let mut introspection_gadget =
            BTCRollupRefundIntrospectionGadget::add_virtual_to(&mut builder, &introspection_config);
        let sighash_felt252 = introspection_gadget.get_sighash_felt252(&mut builder);

        builder.register_public_inputs(&introspection_gadget.current_state_hash.elements);
        builder.register_public_inputs(&sighash_felt252.elements);

        introspection_gadget.finalize(&mut builder, &mut dp);

        let sha256_acceleration_gadget = SmartSha256AcceleratorGadgetWithDomain::<
            Sha256Acc,
            Sha256AirParametersStandard<C::F>,
            C,
            D,
            64,
        >::new(&mut builder, dp);

        let targets_to_constants = builder.get_targets_to_constants_map();
        let circuit_data = builder.build::<C>();

        let minifier = QEDProofMinifierDynamicChain::new_with_dynamic_constant_verifier(
            &circuit_data.verifier_only,
            &circuit_data.common,
            &[false, true, true],
        );

        let fingerprint = QHashOut(minifier.get_fingerprint());

        Self {
            sha256_acceleration_gadget,
            targets_to_constants,
            introspection_config,
            introspection_gadget,
            circuit_data,
            fingerprint,
            minifier,
        }
    }
    pub fn prove_base(
        &self,
        introspection_hint: &RefundSpendIntrospectionHint,
        result: &BTCRollupRefundIntrospectionResult<C::F>
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut pw = PartialWitness::new();
        //todo, refactor sha256_acceleration_gadget to separate mutable state in a separate struct
        let mut g = self.sha256_acceleration_gadget.clone();

        self.introspection_gadget
            .set_witness::<_, C::F, D, _>(&mut pw, &mut g, introspection_hint, result);
        // do this at the end
        g.finalize_witness(&mut pw, &self.targets_to_constants);
        /*let trace_result = self.tracer.resolve_partition::<C::F, C, D>(
            &pw,
            &self.circuit_data.prover_only,
            &self.circuit_data.common,
            &self.targets_to_constants,
        );
        tracing::info!(
            "trace_result: {}",
            serde_json::to_string_pretty(&trace_result).unwrap()
        );*/
        let inner_proof = self.circuit_data.prove(pw)?;
        self.minifier.prove(&inner_proof)
    }
}

impl<C: GenericConfig<D> + 'static, const D: usize> QStandardCircuit<C, D>
    for CRSigHashRefundCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
    C::F: CubicExtendable,
{
    fn get_fingerprint(&self) -> QHashOut<C::F> {
        QHashOut(self.minifier.get_fingerprint())
    }

    fn get_verifier_config_ref(&self) -> &VerifierOnlyCircuitData<C, D> {
        self.minifier.get_verifier_data()
    }

    fn get_common_circuit_data_ref(&self) -> &CommonCircuitData<C::F, D> {
        self.minifier.get_common_data()
    }
}
impl<C: GenericConfig<D> + 'static, const D: usize>
    QStandardCircuitProvable<CRSigHashRefundCircuitInput<C::F>, C, D>
    for CRSigHashRefundCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
    C::F: CubicExtendable,
{
    fn prove_standard(
        &self,
        input: &CRSigHashRefundCircuitInput<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.prove_base(&input.introspection_hint, &input.result)
    }
}

impl<S: QProofStoreReaderSync, C: GenericConfig<D> + 'static, const D: usize>
    QStandardCircuitProvableWithProofStoreSync<S, CRSigHashRefundCircuitInput<C::F>, C, D>
    for CRSigHashRefundCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
    C::F: CubicExtendable,
{
    fn prove_with_proof_store_sync(
        &self,
        _store: &S,
        input: &CRSigHashRefundCircuitInput<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.prove_standard(input)
    }
}

impl<S: QProofStoreReaderSync, C: GenericConfig<D> + 'static, const D: usize>
    QWorkerCircuitMutCustomWithDataSync<S, C, D> for CRSigHashRefundCircuit<C, D>
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
        let input: CRSigHashRefundCircuitInput<C::F> = bincode::deserialize(&input_bytes)?;
        self.prove_base(&input.introspection_hint, &input.result)
    }
}

impl<
        V: QWorkerVerifyHelper<C, D>,
        S: QProofStoreReaderSync,
        C: GenericConfig<D> + 'static,
        const D: usize,
    > QWorkerCircuitCustomWithDataSync<V, S, C, D> for CRSigHashRefundCircuit<C, D>
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
        let input: CRSigHashRefundCircuitInput<C::F> = bincode::deserialize(&input_bytes)?;
        self.prove_base(&input.introspection_hint, &input.result)
    }
}
