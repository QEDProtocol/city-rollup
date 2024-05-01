use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::witness::Witness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CommonCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};

use crate::common::{
    builder::verify::CircuitBuilderVerifyProofHelpers,
    hash::merkle::gadgets::merkle_proof::hash_merkle_leaves,
};

pub struct RecursiveVerificationGadget<const D: usize> {
    pub proof: ProofWithPublicInputsTarget<D>,
    pub verifier_data: VerifierCircuitTarget,
    pub verifier_data_fingerprint: HashOutTarget,
    pub proof_attestation_hash: HashOutTarget,
}

impl<const D: usize> RecursiveVerificationGadget<D> {
    pub fn add_virtual_to<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static>(
        builder: &mut CircuitBuilder<F, D>,
        common_data: &CommonCircuitData<F, D>,
    ) -> Self
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        // Pr_n
        let pr_n = builder.add_virtual_proof_with_pis(common_data);
        /*
           Note:
           To ensure that all proofs have the same format, generating P_n is actually done by the child proof,
           so when we say "Hash the public inputs of Pr_n", we really mean the proof Pr_n exposes "verifiable inputs" by
           making the hash of the inputs that need to be public the actual public inputs, hence if you need to later check the "verifiable inputs"
           you can just rehash them and see if the hash matches the actual public inputs of the proof
        */
        assert_eq!(
            pr_n.public_inputs.len(),
            4,
            r#"the public inputs must have 4 elements, if you need more data to be accessible, 
            please hash your data and use the hash of your previously used public inputs as the new public inputs instead"#
        );

        // public_inputs_hash = Hash(P_n) where P_n are the "public inputs" of our circuit before porting to the new system
        // (public_inputs_hash are the actual public inputs, see above)
        let public_inputs_hash = HashOutTarget {
            elements: [
                pr_n.public_inputs[0],
                pr_n.public_inputs[1],
                pr_n.public_inputs[2],
                pr_n.public_inputs[3],
            ],
        };

        // V_n, all must share same cap height
        let v_n = builder.add_virtual_verifier_data(common_data.config.fri_config.cap_height);

        // fingerprint_n = Hash(v_n), identifies the circuit
        let fingerprint_n = builder.get_circuit_fingerprint::<C::Hasher>(&v_n);

        // proof_attestation_hash = Hash(Hash(P_n), Hash(V_n))
        let proof_attestation_hash = builder.hash_n_to_hash_no_pad::<C::Hasher>(
            vec![public_inputs_hash.elements, fingerprint_n.elements].concat(),
        );

        builder.verify_proof::<C>(&pr_n, &v_n, common_data);
        Self {
            proof: pr_n,
            verifier_data: v_n,
            verifier_data_fingerprint: fingerprint_n,
            proof_attestation_hash: proof_attestation_hash,
        }
    }

    pub fn set_witness<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static>(
        &self,
        witness: &mut impl Witness<F>,
        proof_input: &ProofWithPublicInputs<F, C, D>, // Pr_n
        verifier_data_input: &VerifierOnlyCircuitData<C, D>, // V_n
    ) where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        witness.set_verifier_data_target(&self.verifier_data, verifier_data_input);
        witness.set_proof_with_pis_target(&self.proof, proof_input);
    }
}
pub struct RecursiveVerificationGadgetMulti<const D: usize, const PROOF_COUNT: usize> {
    pub proofs: [ProofWithPublicInputsTarget<D>; PROOF_COUNT],
    pub verifier_data: VerifierCircuitTarget,
    pub verifier_data_fingerprint: HashOutTarget,
    pub root: HashOutTarget,
}

impl<const D: usize, const PROOF_COUNT: usize> RecursiveVerificationGadgetMulti<D, PROOF_COUNT> {
    pub fn add_virtual_to<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static>(
        builder: &mut CircuitBuilder<F, D>,
        common_data: &CommonCircuitData<F, D>,
    ) -> Self
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        // PROOF_COUNT = number of leaves, so tree_height = log2(PROOF_COUNT)
        let tree_height = (PROOF_COUNT as f64).log2().ceil() as usize;
        // panic if PROOF_COUNT is not a power of 2
        assert_eq!(
            PROOF_COUNT,
            2usize.pow(tree_height as u32),
            "PROOF_COUNT must be a power of 2"
        );

        assert_eq!(
            common_data.num_public_inputs, 4,
            r#"the public inputs must have 4 elements, if you need more data to be accessible, 
            please hash your data and use the hash of your previously used public inputs as the new public inputs instead"#
        );

        // V_n, all must share same cap height
        let v_n = builder.add_virtual_verifier_data(common_data.config.fri_config.cap_height);

        // fingerprint_n = Hash(V_n), identifies the circuit
        let fingerprint_n = builder.get_circuit_fingerprint::<C::Hasher>(&v_n);
        let proofs = core::array::from_fn::<ProofWithPublicInputsTarget<D>, PROOF_COUNT, _>(|_| {
            let proof = builder.add_virtual_proof_with_pis(common_data);
            builder.verify_proof::<C>(&proof, &v_n, common_data);
            proof
        });

        // ProofAttestationHash_n = Hash(Pub_n, Hash(V_n))
        let proof_attestation_hashes = core::array::from_fn::<HashOutTarget, PROOF_COUNT, _>(|n| {
            builder.hash_n_to_hash_no_pad::<C::Hasher>(vec![
                fingerprint_n.elements[0],
                fingerprint_n.elements[1],
                fingerprint_n.elements[2],
                fingerprint_n.elements[3],
                proofs[n].public_inputs[0],
                proofs[n].public_inputs[1],
                proofs[n].public_inputs[2],
                proofs[n].public_inputs[3],
            ])
        });
        // Compute merkle root for tree where Leaf_n = ProofAttestationHash_n
        let root = hash_merkle_leaves::<F, D, C::Hasher>(builder, &proof_attestation_hashes);

        Self {
            proofs: proofs,
            verifier_data: v_n,
            verifier_data_fingerprint: fingerprint_n,
            root: root,
        }
    }

    pub fn set_witness<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static>(
        &self,
        witness: &mut impl Witness<F>,
        proof_input: &[ProofWithPublicInputs<F, C, D>], // Pr_n
        verifier_data_input: &VerifierOnlyCircuitData<C, D>, // V_n
    ) where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        witness.set_verifier_data_target(&self.verifier_data, verifier_data_input);
        for (i, proof) in proof_input.iter().enumerate() {
            witness.set_proof_with_pis_target(&self.proofs[i], proof);
        }
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::{goldilocks_field::GoldilocksField, types::Field},
        hash::poseidon::PoseidonHash,
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::{CircuitConfig, CircuitData},
            config::PoseidonGoldilocksConfig,
            proof::ProofWithPublicInputs,
        },
    };

    use crate::{
        common::verify::gadgets::verify_two_to_one::RecursiveVerificationGadgetMulti,
        debug::debug_timer::DebugTimer,
    };

    use super::RecursiveVerificationGadget;

    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    fn example_1_circuit_and_proof(
        x: F,
        y: F,
    ) -> (CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>) {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let input_x = builder.add_virtual_target();
        let input_y = builder.add_virtual_target();
        let x_times_y = builder.mul(input_x, input_y);
        let zero = builder.zero();

        let result =
            builder.hash_n_to_hash_no_pad::<PoseidonHash>(vec![x_times_y, zero, zero, zero]);
        builder.register_public_inputs(&result.elements);
        let data = builder.build::<C>();
        let mut witness = PartialWitness::<F>::new();
        witness.set_target(input_x, x);
        witness.set_target(input_y, y);
        let proof = data.prove(witness).unwrap();
        return (data, proof);
    }

    fn _example_2_circuit_and_proof(
        x: F,
        y: F,
    ) -> (CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>) {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let input_x = builder.add_virtual_target();
        let input_y = builder.add_virtual_target();
        let x_squared = builder.mul(input_x, input_x);
        let y_squared = builder.mul(input_y, input_y);
        let x_squared_minus_y_squared = builder.sub(x_squared, y_squared);
        let zero = builder.zero();

        let result = builder.hash_n_to_hash_no_pad::<PoseidonHash>(vec![
            x_squared_minus_y_squared,
            zero,
            zero,
            zero,
        ]);
        builder.register_public_inputs(&result.elements);
        let data = builder.build::<C>();
        let mut witness = PartialWitness::<F>::new();
        witness.set_target(input_x, x);
        witness.set_target(input_y, y);
        let proof = data.prove(witness).unwrap();
        return (data, proof);
    }

    #[test]
    pub fn test() {
        let (ex_circuit_1_data, ex_circuit_1_proof) =
            example_1_circuit_and_proof(F::from_canonical_u64(3), F::from_canonical_u64(6));
        let (ex_circuit_2_data, ex_circuit_2_proof) =
            example_1_circuit_and_proof(F::from_canonical_u64(5), F::from_canonical_u64(3));
        let common_data_inner = ex_circuit_1_data.common.clone();

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        // verify Pr_0
        let verify_a = RecursiveVerificationGadget::<D>::add_virtual_to::<F, C>(
            &mut builder,
            &common_data_inner,
        );
        // verify Pr_1
        let verify_b = RecursiveVerificationGadget::<D>::add_virtual_to::<F, C>(
            &mut builder,
            &common_data_inner,
        );

        // result = Hash( Hash(Hash(P_0),Hash(V_0)), Hash(Hash(P_1),Hash(V_1)) )
        let result = builder.hash_n_to_hash_no_pad::<PoseidonHash>(
            vec![
                verify_a.proof_attestation_hash.elements,
                verify_b.proof_attestation_hash.elements,
            ]
            .concat(),
        );
        builder.register_public_inputs(&result.elements); // public inputs for this proof = result
        let data = builder.build::<C>();

        let mut witness = PartialWitness::<F>::new();
        verify_a.set_witness(
            &mut witness,
            &ex_circuit_1_proof,
            &ex_circuit_1_data.verifier_only,
        );
        verify_b.set_witness(
            &mut witness,
            &ex_circuit_2_proof,
            &ex_circuit_2_data.verifier_only,
        );
        let mut timer = DebugTimer::new("recursive 2-to-1 circuit");
        let proof = data.prove(witness).unwrap();
        timer.lap("proved 2-to-1");
        data.verify(proof).unwrap();
        timer.lap("verified 2-to-1");
    }
    fn gen_basic_proofs_and_circuit<const CT: usize>(
    ) -> (CircuitData<F, C, D>, [ProofWithPublicInputs<F, C, D>; CT]) {
        let config_a = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config_a);
        let input_x = builder.add_virtual_target();
        let val = builder.constant(F::from_canonical_u64(18));
        let hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(vec![input_x, val, val, val]);
        builder.register_public_inputs(&hash.elements);
        let data_a = builder.build::<C>();
        let proofs = core::array::from_fn::<ProofWithPublicInputs<F, C, D>, CT, _>(|n| {
            let mut witness_a = PartialWitness::<F>::new();
            witness_a.set_target(input_x, F::from_canonical_u64(n as u64));
            data_a.prove(witness_a).unwrap()
        });
        (data_a, proofs)
    }

    pub fn _test_recur_count(_n: usize) {
        let config_a = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config_a);
        let input_x = builder.add_virtual_target();
        let input_y = builder.add_virtual_target();
        let x_times_y = builder.mul(input_x, input_y);
        let val = builder.constant(F::from_canonical_u64(18));
        builder.connect(x_times_y, val);
        let data_a = builder.build::<C>();
        let mut witness_a = PartialWitness::<F>::new();
        witness_a.set_target(input_x, F::from_canonical_u64(3));
        witness_a.set_target(input_y, F::from_canonical_u64(6));
        let proof_a = data_a.prove(witness_a).unwrap();
        let mut witness_b = PartialWitness::<F>::new();
        witness_b.set_target(input_x, F::from_canonical_u64(9));
        witness_b.set_target(input_y, F::from_canonical_u64(2));
        let proof_b = data_a.prove(witness_b).unwrap();

        let config_r = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config_r);
        let proof_target_a = builder.add_virtual_proof_with_pis(&data_a.common);
        let proof_target_b = builder.add_virtual_proof_with_pis(&data_a.common);
        let verifier_data_target =
            builder.add_virtual_verifier_data(data_a.common.config.fri_config.cap_height);
        builder.verify_proof::<C>(&proof_target_a, &verifier_data_target, &data_a.common);
        builder.verify_proof::<C>(&proof_target_b, &verifier_data_target, &data_a.common);
        let data_r = builder.build::<C>();
        let mut witness_r = PartialWitness::<F>::new();
        witness_r.set_proof_with_pis_target(&proof_target_a, &proof_a);
        witness_r.set_proof_with_pis_target(&proof_target_b, &proof_b);
        witness_r.set_verifier_data_target(&verifier_data_target, &data_a.verifier_only);
        let mut timer = DebugTimer::new("recursive 2-to-1 circuit single verifier data");
        let proof_r = data_r.prove(witness_r).unwrap();
        timer.lap("proved 2-to-1");

        data_r.verify(proof_r).unwrap();
        timer.lap("verified 2-to-1");
    }

    fn recur_basic_tree<const CT: usize>() {
        let (data_a, proofs) = gen_basic_proofs_and_circuit::<CT>();
        let config_r = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config_r);
        let tree_gadget = RecursiveVerificationGadgetMulti::<D, CT>::add_virtual_to::<F, C>(
            &mut builder,
            &data_a.common,
        );
        builder.register_public_inputs(&tree_gadget.root.elements);
        let data_r = builder.build::<C>();
        let mut witness_r = PartialWitness::<F>::new();
        tree_gadget.set_witness(&mut witness_r, &proofs, &data_a.verifier_only);
        let mut timer = DebugTimer::new("recursive 8-to-1 circuit single verifier data");
        let proof_r = data_r.prove(witness_r).unwrap();
        timer.lap(format!("proved {}-to-1", CT).as_str());

        data_r.verify(proof_r).unwrap();
        timer.lap(format!("verified {}-to-1", CT).as_str());

        println!("common_data {}-to-1: {:?}", CT, data_r.common);
    }
    #[test]
    pub fn test_recur_basic_tree() {
        recur_basic_tree::<2>();
        recur_basic_tree::<4>();
        recur_basic_tree::<8>();
        recur_basic_tree::<16>();
        recur_basic_tree::<32>();
        recur_basic_tree::<64>();
    }
    #[test]
    pub fn test_recur_basic() {
        let config_a = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config_a);
        let input_x = builder.add_virtual_target();
        let input_y = builder.add_virtual_target();
        let x_times_y = builder.mul(input_x, input_y);
        let val = builder.constant(F::from_canonical_u64(18));
        builder.connect(x_times_y, val);
        let data_a = builder.build::<C>();
        let mut witness_a = PartialWitness::<F>::new();
        witness_a.set_target(input_x, F::from_canonical_u64(3));
        witness_a.set_target(input_y, F::from_canonical_u64(6));
        let proof_a = data_a.prove(witness_a).unwrap();
        let mut witness_b = PartialWitness::<F>::new();
        witness_b.set_target(input_x, F::from_canonical_u64(9));
        witness_b.set_target(input_y, F::from_canonical_u64(2));
        let proof_b = data_a.prove(witness_b).unwrap();

        let config_r = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config_r);
        let proof_target_a = builder.add_virtual_proof_with_pis(&data_a.common);
        let proof_target_b = builder.add_virtual_proof_with_pis(&data_a.common);
        let verifier_data_target =
            builder.add_virtual_verifier_data(data_a.common.config.fri_config.cap_height);
        builder.verify_proof::<C>(&proof_target_a, &verifier_data_target, &data_a.common);
        builder.verify_proof::<C>(&proof_target_b, &verifier_data_target, &data_a.common);
        let data_r = builder.build::<C>();
        let mut witness_r = PartialWitness::<F>::new();
        witness_r.set_proof_with_pis_target(&proof_target_a, &proof_a);
        witness_r.set_proof_with_pis_target(&proof_target_b, &proof_b);
        witness_r.set_verifier_data_target(&verifier_data_target, &data_a.verifier_only);
        let mut timer = DebugTimer::new("recursive 2-to-1 circuit single verifier data");
        let proof_r = data_r.prove(witness_r).unwrap();
        timer.lap("proved 2-to-1");

        data_r.verify(proof_r).unwrap();
        timer.lap("verified 2-to-1");
    }

    #[test]
    pub fn test_recur_basic_4() {
        let config_a = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config_a);
        let input_x = builder.add_virtual_target();
        let input_y = builder.add_virtual_target();
        let x_times_y = builder.mul(input_x, input_y);
        let val = builder.constant(F::from_canonical_u64(18));
        builder.connect(x_times_y, val);
        let data_a = builder.build::<C>();
        let mut witness_a = PartialWitness::<F>::new();
        witness_a.set_target(input_x, F::from_canonical_u64(3));
        witness_a.set_target(input_y, F::from_canonical_u64(6));
        let proof_a = data_a.prove(witness_a).unwrap();

        let mut witness_b = PartialWitness::<F>::new();
        witness_b.set_target(input_x, F::from_canonical_u64(9));
        witness_b.set_target(input_y, F::from_canonical_u64(2));
        let proof_b = data_a.prove(witness_b).unwrap();

        let mut witness_c = PartialWitness::<F>::new();
        witness_c.set_target(input_x, F::from_canonical_u64(6));
        witness_c.set_target(input_y, F::from_canonical_u64(3));
        let proof_c = data_a.prove(witness_c).unwrap();

        let mut witness_d = PartialWitness::<F>::new();
        witness_d.set_target(input_x, F::from_canonical_u64(2));
        witness_d.set_target(input_y, F::from_canonical_u64(9));
        let proof_d = data_a.prove(witness_d).unwrap();

        let config_r = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config_r);
        let proof_target_a = builder.add_virtual_proof_with_pis(&data_a.common);
        let proof_target_b = builder.add_virtual_proof_with_pis(&data_a.common);
        let proof_target_c = builder.add_virtual_proof_with_pis(&data_a.common);
        let proof_target_d = builder.add_virtual_proof_with_pis(&data_a.common);
        let verifier_data_target =
            builder.add_virtual_verifier_data(data_a.common.config.fri_config.cap_height);
        builder.verify_proof::<C>(&proof_target_a, &verifier_data_target, &data_a.common);
        builder.verify_proof::<C>(&proof_target_b, &verifier_data_target, &data_a.common);
        builder.verify_proof::<C>(&proof_target_c, &verifier_data_target, &data_a.common);
        builder.verify_proof::<C>(&proof_target_d, &verifier_data_target, &data_a.common);
        let data_r = builder.build::<C>();
        let mut witness_r = PartialWitness::<F>::new();
        witness_r.set_proof_with_pis_target(&proof_target_a, &proof_a);
        witness_r.set_proof_with_pis_target(&proof_target_b, &proof_b);
        witness_r.set_proof_with_pis_target(&proof_target_c, &proof_c);
        witness_r.set_proof_with_pis_target(&proof_target_d, &proof_d);
        witness_r.set_verifier_data_target(&verifier_data_target, &data_a.verifier_only);
        let mut timer = DebugTimer::new("recursive 4-to-1 circuit single verifier data");
        let proof_r = data_r.prove(witness_r).unwrap();
        timer.lap("proved 4-to-1");

        data_r.verify(proof_r).unwrap();
        timer.lap("verified 4-to-1");
        println!("common_data: {:?}", data_r.common);
    }
    #[test]
    pub fn test_recur_basic_constant_ver() {
        let config_a = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config_a);
        let input_x = builder.add_virtual_target();
        let input_y = builder.add_virtual_target();
        let x_times_y = builder.mul(input_x, input_y);
        let val = builder.constant(F::from_canonical_u64(18));
        builder.connect(x_times_y, val);
        let data_a = builder.build::<C>();
        let mut witness_a = PartialWitness::<F>::new();
        witness_a.set_target(input_x, F::from_canonical_u64(3));
        witness_a.set_target(input_y, F::from_canonical_u64(6));
        let proof_a = data_a.prove(witness_a).unwrap();
        let mut witness_b = PartialWitness::<F>::new();
        witness_b.set_target(input_x, F::from_canonical_u64(9));
        witness_b.set_target(input_y, F::from_canonical_u64(2));
        let proof_b = data_a.prove(witness_b).unwrap();

        let config_r = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config_r);
        let proof_target_a = builder.add_virtual_proof_with_pis(&data_a.common);
        let proof_target_b = builder.add_virtual_proof_with_pis(&data_a.common);
        let verifier_data_c_target = builder.constant_verifier_data(&data_a.verifier_only);

        //let verifier_data_target = builder.add_virtual_verifier_data(data_a.common.config.fri_config.cap_height);
        builder.verify_proof::<C>(&proof_target_a, &verifier_data_c_target, &data_a.common);
        builder.verify_proof::<C>(&proof_target_b, &verifier_data_c_target, &data_a.common);
        let data_r = builder.build::<C>();
        let mut witness_r = PartialWitness::<F>::new();
        witness_r.set_proof_with_pis_target(&proof_target_a, &proof_a);
        witness_r.set_proof_with_pis_target(&proof_target_b, &proof_b);
        //witness_r.set_verifier_data_target(&verifier_data_target, &data_a.verifier_only);
        let mut timer = DebugTimer::new("recursive 2-to-1 circuit single verifier data");
        let proof_r = data_r.prove(witness_r).unwrap();
        timer.lap("proved 2-to-1");

        data_r.verify(proof_r).unwrap();
        timer.lap("verified 2-to-1");
    }
    #[test]
    pub fn test_recur_basic3() {
        let config_a = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config_a);
        let input_x = builder.add_virtual_target();
        let input_y = builder.add_virtual_target();
        let x_times_y = builder.mul(input_x, input_y);
        let val = builder.constant(F::from_canonical_u64(18));
        builder.connect(x_times_y, val);
        builder.register_public_inputs(&vec![x_times_y, val, val, val]);
        let data_a = builder.build::<C>();
        let mut witness_a = PartialWitness::<F>::new();
        witness_a.set_target(input_x, F::from_canonical_u64(3));
        witness_a.set_target(input_y, F::from_canonical_u64(6));
        let proof_a = data_a.prove(witness_a).unwrap();

        let config_r = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config_r);
        let pt =
            RecursiveVerificationGadget::<D>::add_virtual_to::<F, C>(&mut builder, &data_a.common);
        let data_r = builder.build::<C>();
        let mut witness_r = PartialWitness::<F>::new();
        pt.set_witness(&mut witness_r, &proof_a, &data_a.verifier_only);
        let proof_r = data_r.prove(witness_r).unwrap();
        data_r.verify(proof_r).unwrap();
    }
}
