use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::common::builder::hash::hash256::{CircuitBuilderHash, Hash256Target, WitnessHash256};
use crate::common::builder::hash::sha256::CircuitBuilderHashSha256;
use crate::common::u32::arithmetic_u32::U32Target;

pub fn compute_merkle_root<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    index_bits: &[BoolTarget],
    value: Hash256Target,
    siblings: &[Hash256Target],
) -> Hash256Target {
    let mut current = value;
    for (i, sibling) in siblings.iter().enumerate() {
        let bit = index_bits[i];

        let left: [U32Target; 8] = builder.select_hash256(bit, *sibling, current);
        let right = builder.select_hash256(bit, current, *sibling);
        current = builder.two_to_one_sha256(left, right);
    }
    current
}

pub struct MerkleProofSha256Gadget {
    pub root: Hash256Target,
    pub value: Hash256Target,
    pub siblings: Vec<Hash256Target>,
    pub index: Target,
}

impl MerkleProofSha256Gadget {
    pub fn add_virtual_to<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        height: usize,
    ) -> Self {
        let siblings: Vec<Hash256Target> = (0..height)
            .map(|_| builder.add_virtual_hash256_target())
            .collect();

        let value = builder.add_virtual_hash256_target();
        let index = builder.add_virtual_target();
        let index_bits = builder.split_le(index, height);
        let root = compute_merkle_root(builder, &index_bits, value, &siblings);

        Self {
            root,
            value,
            siblings,
            index,
        }
    }

    pub fn set_witness<F: RichField, W: WitnessHash256<F>>(
        &self,
        witness: &mut W,
        index: u64,
        value: &[u8; 32],
        siblings: &[[u8; 32]],
    ) {
        witness.set_hash256_target(&self.value, value);
        witness.set_target(self.index, F::from_noncanonical_u64(index));
        for (i, sibling) in self.siblings.iter().enumerate() {
            witness.set_hash256_target(sibling, &siblings[i]);
        }
    }
}

#[cfg(test)]
mod tests {
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

    use crate::common::base_types::hash::hash256::MerkleProof256;
    use crate::common::builder::hash::hash256::{CircuitBuilderHash, WitnessHash256};
    use crate::common::hash::merkle::gadgets::sha256::merkle_proof::MerkleProofSha256Gadget;

    #[test]
    fn test_verify_small_merkle_proof() {
        // build circuit once
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let merkle_proof_gadget = MerkleProofSha256Gadget::add_virtual_to(&mut builder, 3);
        let expected_root_target = builder.add_virtual_hash256_target();
        builder.connect_hash256(expected_root_target, merkle_proof_gadget.root);
        let num_gates = builder.num_gates();
        // let copy_constraints = builder.copy_constraints.len();
        let data = builder.build::<C>();
        println!(
            "circuit num_gates={}, quotient_degree_factor={}",
            num_gates, data.common.quotient_degree_factor
        );

        let mut pw = PartialWitness::new();
        let proof_serialized = r#"
        {
          "root": "7e286a6721a66675ea033a4dcdec5abbdc7d3c81580e2d6ded7433ed113b7737",
          "siblings": [
            "0000000000000000000000000000000000000000000000000000000000000007",
            "ce44a8ee02db1a76906b0e9fd753893971c4db9a2341b0049d61f7fcd2a60adf",
            "81b1e323f0e91a785dfd155817e09949a7d66fe8fdc4f31f39530845e88ab63c"
          ],
          "index": 2,
          "value": "0000000000000000000000000000000000000000000000000000000000000003"
        }
        "#;
        let proof: MerkleProof256 =
            serde_json::from_str::<MerkleProof256>(proof_serialized).unwrap();
        merkle_proof_gadget.set_witness_from_proof(&mut pw, &proof);
        pw.set_hash256_target(&expected_root_target, &proof.root.0);

        let start_time = std::time::Instant::now();
        let proof = data.prove(pw).unwrap();
        let duration_ms = start_time.elapsed().as_millis();
        println!("proved in {}ms", duration_ms);

        assert!(data.verify(proof).is_ok());
    }
}
