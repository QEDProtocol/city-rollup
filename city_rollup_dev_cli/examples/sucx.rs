use city_common_circuit::{
    builder::hash::core::CircuitBuilderHashCore, circuits::{simple_wrapper::{constant::SimpleWrapper, dynamic::SimpleWrapperDynamic}, traits::qstandard::QStandardCircuit},
    proof_minifier::pm_core::get_circuit_fingerprint_generic,
};
use city_crypto::hash::qhashout::QHashOut;
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::PrimeField64}, hash::hash_types::HashOutTarget, iop::witness::{PartialWitness, WitnessWrite}, plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig, PoseidonGoldilocksConfig},
        proof::ProofWithPublicInputs,
    }
};
use plonky2::field::types::Field;

#[derive(Debug)]
pub struct BasicCircuit<C: GenericConfig<D> + 'static, const D: usize> {
    pub a: HashOutTarget,
    pub b: HashOutTarget,
    pub circuit_data: CircuitData<C::F, C, D>,
    pub fingerprint: QHashOut<C::F>,
}
impl<C: GenericConfig<D>, const D: usize> BasicCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub fn new() -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);

        let a = builder.add_virtual_hash();
        let b = builder.add_virtual_hash();
        let c = builder.hash_two_to_one::<C::Hasher>(a, b);
        let e = c.elements.iter().map(|x|{
            builder.split_le(*x, 64).into_iter().map(|y| y.target).collect::<Vec<_>>()
        }).collect::<Vec<_>>().into_iter().flatten().collect::<Vec<_>>();
        let two_hundred = builder.constant(C::F::from_canonical_u64(200));
        let res = e.iter().map(|c|{
            builder.mul(two_hundred, *c)
        }).collect::<Vec<_>>();

        builder.register_public_inputs(&e[0..8]);
        //builder.register_public_inputs(&c.elements);
        
        let circuit_data = builder.build::<C>();
        let fingerprint = QHashOut(get_circuit_fingerprint_generic::<D, C::F, C>(
            &circuit_data.verifier_only,
        ));
        Self {
            a,
            b,
            circuit_data,
            fingerprint,
        }
    }
    pub fn prove_base(
        &self,
        a: QHashOut<C::F>,
        b: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut pw = PartialWitness::new();
        pw.set_hash_target(self.a, a.0);
        pw.set_hash_target(self.b, b.0);
        self.circuit_data.prove(pw)
    }
}
impl<C: GenericConfig<D>, const D: usize> QStandardCircuit<C, D> for BasicCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
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
fn run_prover() -> anyhow::Result<()> {
  type C = PoseidonGoldilocksConfig;
  type F = GoldilocksField;
  const D: usize = 2;
  let circ_a = BasicCircuit::<C, D>::new();
  let circ_b = BasicCircuit::<C, D>::new();
  let wrapper = SimpleWrapperDynamic::<C, D>::new(circ_b.get_common_circuit_data_ref(), circ_b.get_fingerprint(), circ_b.get_verifier_config_ref().constants_sigmas_cap.height());
  let proof = circ_a.prove_base(QHashOut::from_values(1, 1, 1, 1), QHashOut::from_values(2, 2, 2, 2))?;
  let proof_2 = wrapper.prove_base(&proof, circ_b.get_verifier_config_ref())?;

  let result = gnark_plonky2_wrapper::wrap_plonky2_proof(wrapper.circuit_data, &proof_2)?;


    Ok(())
}
fn main() {
  run_prover().unwrap();
  
}
