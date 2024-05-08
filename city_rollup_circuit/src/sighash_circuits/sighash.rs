use city_common_circuit::circuits::traits::qstandard::provable::QStandardCircuitProvable;
use city_common_circuit::circuits::traits::qstandard::QStandardCircuit;
use city_common_circuit::circuits::traits::qstandard::QStandardCircuitProvableWithProofStoreSync;
use city_common_circuit::field::cubic::CubicExtendable;
use city_common_circuit::hash::accelerator::sha256::planner::Sha256AcceleratorDomainPlanner;
use city_common_circuit::hash::accelerator::sha256::planner::SmartSha256AcceleratorGadgetWithDomain;
use city_common_circuit::hash::accelerator::sha256::smartgadget::Sha256AirParametersStandard;
use city_common_circuit::hash::accelerator::sha256::Sha256Acc;
use city_common_circuit::proof_minifier::pm_chain_dynamic::OASProofMinifierDynamicChain;
use city_crypto::hash::qhashout::QHashOut;
use city_rollup_common::introspection::rollup::introspection::BlockSpendIntrospectionGadgetConfig;
use city_rollup_common::introspection::rollup::introspection::BlockSpendIntrospectionHint;
use city_rollup_common::qworker::proof_store::QProofStoreReaderSync;
use hashbrown::HashMap;
use plonky2::hash::hash_types::RichField;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::Target;
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::circuit_data::CircuitData;
use plonky2::plonk::circuit_data::CommonCircuitData;
use plonky2::plonk::circuit_data::VerifierOnlyCircuitData;
use plonky2::plonk::config::AlgebraicHasher;
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;
use serde::Deserialize;
use serde::Serialize;

use crate::introspection::gadgets::rollup::introspection::BTCRollupIntrospectionGadget;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(bound = "")]
pub struct CRSigHashCircuitInput<F: RichField> {
    pub introspection_hint: BlockSpendIntrospectionHint,
    pub _dummy: F, // in case we need F later
}
#[derive(Debug)]
pub struct CRSigHashCircuit<C: GenericConfig<D> + 'static, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
    C::F: CubicExtendable,
{
    pub introspection_config: BlockSpendIntrospectionGadgetConfig,

    // [START] circuit targets
    pub introspection_gadget: BTCRollupIntrospectionGadget,
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

    pub minifier: OASProofMinifierDynamicChain<D, C::F, C>,
    //pub tracer: DebugCircuitTracer,
}
impl<C: GenericConfig<D> + 'static, const D: usize> Clone for CRSigHashCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
    C::F: CubicExtendable,
{
    fn clone(&self) -> Self {
        Self::new(self.introspection_config.clone())
    }
}
impl<C: GenericConfig<D>, const D: usize> CRSigHashCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
    C::F: CubicExtendable,
{
    pub fn new(introspection_config: BlockSpendIntrospectionGadgetConfig) -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);
        //let mut tracer = DebugCircuitTracer::new();

        let mut dp = Sha256AcceleratorDomainPlanner::new();

        let mut introspection_gadget =
            BTCRollupIntrospectionGadget::add_virtual_to(&mut builder, &introspection_config);

        let introspection_result = introspection_gadget.generate_result(&mut builder);
        let introspection_finalized =
            introspection_result.get_finalized_result::<PoseidonHash, _, D>(&mut builder);
        let introspection_finalized_hash =
            introspection_finalized.get_combined_hash::<PoseidonHash, _, D>(&mut builder);

        builder.register_public_inputs(&introspection_finalized_hash.elements);
        builder.register_public_inputs(&introspection_result.sighash_felt252.elements);

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

        let minifier = OASProofMinifierDynamicChain::new_with_dynamic_constant_verifier(
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
        introspection_hint: &BlockSpendIntrospectionHint,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut pw = PartialWitness::new();
        //todo, refactor sha256_acceleration_gadget to separate mutable state in a
        // separate struct
        let mut g = self.sha256_acceleration_gadget.clone();

        self.introspection_gadget
            .set_witness::<_, C::F, D, _>(&mut pw, &mut g, introspection_hint);
        // do this at the end
        g.finalize_witness(&mut pw, &self.targets_to_constants);
        /*let trace_result = self.tracer.resolve_partition::<C::F, C, D>(
            &pw,
            &self.circuit_data.prover_only,
            &self.circuit_data.common,
            &self.targets_to_constants,
        );
        println!(
            "trace_result: {}",
            serde_json::to_string_pretty(&trace_result).unwrap()
        );*/
        let inner_proof = self.circuit_data.prove(pw)?;
        self.minifier.prove(&inner_proof)
    }
}

impl<C: GenericConfig<D> + 'static, const D: usize> QStandardCircuit<C, D>
    for CRSigHashCircuit<C, D>
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
    QStandardCircuitProvable<CRSigHashCircuitInput<C::F>, C, D> for CRSigHashCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
    C::F: CubicExtendable,
{
    fn prove_standard(
        &self,
        input: &CRSigHashCircuitInput<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.prove_base(&input.introspection_hint)
    }
}

impl<S: QProofStoreReaderSync, C: GenericConfig<D> + 'static, const D: usize>
    QStandardCircuitProvableWithProofStoreSync<S, CRSigHashCircuitInput<C::F>, C, D>
    for CRSigHashCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
    C::F: CubicExtendable,
{
    fn prove_with_proof_store_sync(
        &self,
        _store: &S,
        input: &CRSigHashCircuitInput<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.prove_standard(input)
    }
}
