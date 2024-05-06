use anyhow::Result;
use city_common::logging::debug_timer::DebugTimer;
use plonky2::{
    field::extension::Extendable,
    gates::gate::GateRef,
    hash::hash_types::{HashOut, RichField},
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{
            CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget,
            VerifierOnlyCircuitData,
        },
        config::{AlgebraicHasher, GenericConfig, Hasher},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};

use super::{pm_core::get_circuit_fingerprint_generic, pm_custom::PMCircuitCustomizer};

#[derive(Debug)]
pub struct OASProofMinifierDynamic<
    const D: usize,
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub circuit_data: CircuitData<F, C, D>,
    pub circuit_fingerprint: HashOut<F>,
    pub proof_target: ProofWithPublicInputsTarget<D>,
    pub verifier_data_target: VerifierCircuitTarget,
    pub verifier_data: VerifierOnlyCircuitData<C, D>,
}

impl<const D: usize, F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static>
    OASProofMinifierDynamic<D, F, C>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new(
        base_circuit_verifier_data: &VerifierOnlyCircuitData<C, D>,
        base_circuit_common_data: &CommonCircuitData<F, D>,
    ) -> Self {
        let standard_config = CircuitConfig::standard_recursion_config();
        Self::new_with_cfg(
            standard_config,
            base_circuit_verifier_data,
            base_circuit_common_data,
            None,
        )
    }
    pub fn new_with_cfg(
        config: CircuitConfig,
        base_circuit_verifier_data: &VerifierOnlyCircuitData<C, D>,
        base_circuit_common_data: &CommonCircuitData<F, D>,
        add_gates: Option<&[GateRef<F, D>]>,
    ) -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let verifier_data_target = builder
            .add_virtual_verifier_data(base_circuit_verifier_data.constants_sigmas_cap.height());
        let proof_target = builder.add_virtual_proof_with_pis(base_circuit_common_data);

        builder.register_public_inputs(&proof_target.public_inputs);
        builder.verify_proof::<C>(
            &proof_target,
            &verifier_data_target,
            base_circuit_common_data,
        );

        if add_gates.is_some() {
            add_gates.unwrap().iter().for_each(|g| {
                builder.add_gate_to_gate_set(g.clone());
            });
        }

        let circuit_data = builder.build::<C>();

        let circuit_fingerprint = get_circuit_fingerprint_generic(&circuit_data.verifier_only);

        Self {
            circuit_data,
            circuit_fingerprint,
            proof_target,
            verifier_data_target,
            verifier_data: base_circuit_verifier_data.clone(),
        }
    }
    pub fn new_with_cfg_customizer<PMCC: PMCircuitCustomizer<F, D>>(
        config: CircuitConfig,
        base_circuit_verifier_data: &VerifierOnlyCircuitData<C, D>,
        base_circuit_common_data: &CommonCircuitData<F, D>,
        add_gates: Option<&[GateRef<F, D>]>,
        customizer: Option<&PMCC>,
    ) -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let verifier_data_target = builder
            .add_virtual_verifier_data(base_circuit_verifier_data.constants_sigmas_cap.height());
        let proof_target = builder.add_virtual_proof_with_pis(base_circuit_common_data);

        builder.register_public_inputs(&proof_target.public_inputs);
        builder.verify_proof::<C>(
            &proof_target,
            &verifier_data_target,
            base_circuit_common_data,
        );

        if add_gates.is_some() {
            add_gates.unwrap().iter().for_each(|g| {
                builder.add_gate_to_gate_set(g.clone());
            });
        }
        if customizer.is_some() {
            customizer.unwrap().augment_circuit(&mut builder);
        }

        let circuit_data = builder.build::<C>();

        let circuit_fingerprint = get_circuit_fingerprint_generic(&circuit_data.verifier_only);

        Self {
            circuit_data,
            circuit_fingerprint,
            proof_target,
            verifier_data_target,
            verifier_data: base_circuit_verifier_data.clone(),
        }
    }
    pub fn prove(
        &self,
        base_proof: &ProofWithPublicInputs<F, C, D>, //verifier_data: &VerifierOnlyCircuitData<C, D>,
                                                     //proof: &ProofWithPublicInputs<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>> {
        let mut pw = PartialWitness::new();
        pw.set_verifier_data_target(&self.verifier_data_target, &self.verifier_data);
        pw.set_proof_with_pis_target(&self.proof_target, base_proof);
        let mut timer = DebugTimer::new("compress");
        let result = self.circuit_data.prove(pw);
        timer.lap("proved compress");
        result
    }
}
