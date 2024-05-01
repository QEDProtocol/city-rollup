use plonky2::field::extension::Extendable;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::common::builder::hash::hash192::{CircuitBuilderHash192, Hash192Target, WitnessHash192};
use crate::common::builder::hash::sha256_truncated::CircuitBuilderTruncatedSha256;
use crate::common::qfield::QRichField;

pub fn compute_merkle_root<F: QRichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    index_bits: &[BoolTarget],
    value: Hash192Target,
    siblings: &[Hash192Target],
) -> Hash192Target {
    let mut current = value;
    for (i, sibling) in siblings.iter().enumerate() {
        let bit = index_bits[i];

        let left = builder.select_hash192(bit, *sibling, current);
        let right = builder.select_hash192(bit, current, *sibling);
        current = builder.two_to_one_truncated_sha256(left, right);
    }
    current
}

pub struct MerkleProofTruncatedSha256Gadget {
    pub root: Hash192Target,
    pub value: Hash192Target,
    pub siblings: Vec<Hash192Target>,
    pub index: Target,
}

impl MerkleProofTruncatedSha256Gadget {
    pub fn add_virtual_to<F: QRichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        height: usize,
    ) -> Self {
        let siblings: Vec<Hash192Target> = (0..height)
            .map(|_| builder.add_virtual_hash192_target())
            .collect();

        let value = builder.add_virtual_hash192_target();
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

    pub fn set_witness<F: QRichField, W: WitnessHash192<F>>(
        &self,
        witness: &mut W,
        index: u64,
        value: &[u8; 24],
        siblings: &[[u8; 24]],
    ) {
        witness.set_hash192_target(&self.value, value);
        witness.set_target(self.index, F::from_noncanonical_u64(index));
        for (i, sibling) in self.siblings.iter().enumerate() {
            witness.set_hash192_target(sibling, &siblings[i]);
        }
    }
}
pub fn compute_merkle_root_from_leaves_sha256_192<F: QRichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    leaves: &[Hash192Target],
) -> Hash192Target {
    if (leaves.len() as f64).log2().ceil() != (leaves.len() as f64).log2().floor() {
        panic!("The length of the merkle tree's leaves array must be a power of 2 (2^n)");
    }
    let num_levels = (leaves.len() as f64).log2().ceil() as usize;
    let mut current = leaves.to_vec();
    for _ in 0..num_levels {
        let tmp = current
            .chunks_exact(2)
            .map(|f| builder.two_to_one_truncated_sha256(f[0], f[1]))
            .collect();
        current = tmp;
    }
    current[0]
}
#[cfg(test)]
mod tests {

    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

    use crate::common::base_types::hash::hash192::MerkleProof192;
    use crate::common::builder::hash::hash192::{CircuitBuilderHash192, WitnessHash192};
    use crate::common::hash::merkle::gadgets::sha256_truncated::merkle_proof::MerkleProofTruncatedSha256Gadget;
    const SMALL_MERKLE_PROOFS: &str = r#"
    [
      {
        "root": "8ce47831fa9e8fc6dc2631cc676d8392313f7228bf2628d0",
        "siblings": [
          "93a7b526b4539b1519c03dc81b1f92ed31acbdadb8c930be",
          "81201c69c29f02d7015cc2564db231c5ac5d07c24bbd06a4",
          "e4c0e62041f91b6c90bd2832182b3a52b1c334f398f0246c",
          "f1dde9ea14d2ee93786d7d5e8f04d5ac19143e6d3cf21ada",
          "da0d5558f7797e3a37b1ee3c6fe1da0fac6589ef0ec85121"
        ],
        "index": 15,
        "value": "6c652a08d06186cdf550f67eda642202cbe4c747716ed550"
      },
      {
        "root": "5313e65c747b7c7aa81b5fefedf42b10c9333327cb07af34",
        "siblings": [
          "000000000000000000000000000000000000000000000000",
          "fe46d376e67c2254694c347d0afe236b75336490394afb0d",
          "e99a7762a88398781a5033622920f7ab6718257eb19ccca9",
          "b7df18f989925b15e03bec732cf46af8e0c2a9c6050e9dfb",
          "5befbf2e8a1a141cf6133d8e8129f32e78ac61062f9a239f"
        ],
        "index": 29,
        "value": "000000000000000000000000000000000000000000000000"
      },
      {
        "root": "ced84c2700c11e72495a35caa606019609794dda50caaddd",
        "siblings": [
          "77ee6c1b0b7e95bbca3ff6a34445b079668467912bb47500",
          "9bfd545a14fc6572c898eb9200a84b2e454b972b3905cbc0",
          "1e09e6cb66cec2c8a92a4fc345376be6d6b4c4c0570ed781"
        ],
        "index": 4,
        "value": "43c8b70308380de1224d64d7196760ab2a06f47085ff13df"
      },
      {
        "root": "ced84c2700c11e72495a35caa606019609794dda50caaddd",
        "siblings": [
          "521a640c1caafc21a4bd6b48ced3d60c3aeacf2ab5ea09ba",
          "14a1c68279ad393d4bd7625b065bf17c10fe13ca0f27f492",
          "e854c3850894f7a5a7cc74cffaa7d8d646972f5b4d6ee8b9"
        ],
        "index": 1,
        "value": "f071d559a4d8f6014f9ad03f7b0121a01518341694529897"
      },
      {
        "root": "79666b3e60a7f629ab7622a0f5df5fd84005a288134d959b",
        "siblings": [
          "000000000000000000000000000000000000000000000000",
          "c2a103ad1e2e923fc1993318a63ea714eda3630d4680dd78",
          "68a957640671cd2073f5b043482bf9e35d02339bcd5c03e9",
          "a88c2f54b0bc3e9d50f58c1d4811cf266af5b0cface893bc"
        ],
        "index": 6,
        "value": "8fb2d850018d9f09aabe74babdd26395c52ba6c36bcc27ed"
      },
      {
        "root": "79666b3e60a7f629ab7622a0f5df5fd84005a288134d959b",
        "siblings": [
          "be4b9875a18800889c3e66552b6397a6b25db7652563f299",
          "f94127607bd87b313aebb372b36cba913d95fca15e6d74a1",
          "1da273ba38b033fa58b4754e8d689f0c2b6a12026cc511fd",
          "a88c2f54b0bc3e9d50f58c1d4811cf266af5b0cface893bc"
        ],
        "index": 0,
        "value": "e12a01166536ec83377a1ce0918a6c5a0b89ff823f4062cf"
      },
      {
        "root": "dc7429c8e343c23fbaabc16b83739454632ed633311a7aef",
        "siblings": [
          "42c3ae0c727ee637ee564133dfbbedbcf2555f5f1534b4cd",
          "4ee11667fe4b4b5947959535fa03e1489ee13c09fd2794e9",
          "9ea75858f5c3b2538398d172aecec24232c52fcd63ae9fff"
        ],
        "index": 6,
        "value": "6bbe9138924947c94509a6d0f7390e98dca63a38d326bfdf"
      },
      {
        "root": "dc7429c8e343c23fbaabc16b83739454632ed633311a7aef",
        "siblings": [
          "3027eac7dc2a14ef779a04e66203ce16ae3bf95472b766a8",
          "813eb55b59a858f2b28d926102a30fa6aa0468091e6d9988",
          "c1f1a1d1638e9761f1677268b53e38bb44c036ae116a9bed"
        ],
        "index": 1,
        "value": "a9611ac7ab506b57cee7c38b3b83715eaa08aa0d77bcf61f"
      },
      {
        "root": "a8c4553513d62785d0765b29d53cfa46fea878378f95c7e9",
        "siblings": [
          "4c264204a6eb3a88d3e3cbfa06f0a4b486f01055cb82c10e",
          "321d0799406db01521c341d23bd7314968b5cba8b3d46eb8"
        ],
        "index": 3,
        "value": "0ec33d7d3c23c18a4144b88201f4cde556cae5dfb1916891"
      },
      {
        "root": "a8c4553513d62785d0765b29d53cfa46fea878378f95c7e9",
        "siblings": [
          "30a6ef35e30168d832e97cd4fed35220a2f3009a21a430a9",
          "c5b3c3bb728f1c6c4021ba924602a843ea6b7df205793664"
        ],
        "index": 1,
        "value": "bdeaea5c0c08869c53a36a8e7644f7ebebf6e32be2e5cfcb"
      },
      {
        "root": "28bbb2970f9a64051670779baf00d3db0ccb613a484a4fc5",
        "siblings": [
          "c296afe32a478134777b6b0588a2c9b1f86a3a0bfa55c625",
          "6b4c3568c45cc4d3026388c71be5411466b491148788fd23",
          "f783c89a5c67bdc98466dae1ec56b0efba582892780e20d0"
        ],
        "index": 3,
        "value": "cc10f18b06dd6365366690550c48c947fd8144c11cc976be"
      },
      {
        "root": "28bbb2970f9a64051670779baf00d3db0ccb613a484a4fc5",
        "siblings": [
          "f76a0a71f724c37b8eed0be4280b9c2b668b53dc862a5ceb",
          "7815cc410f24f77e9384d63e8efc187e86bb4d8187b70050",
          "409e63f8d1c7c2ca2da8a7d2c56ece3aa40eb0cd420b261f"
        ],
        "index": 5,
        "value": "e1a9ddd171e191ed2e9e34bbb3a1b2e665e65b750bdfa6b7"
      },
      {
        "root": "afce7d182834e48a88d45db6c3833ad51ceb60e5e5caa5e2",
        "siblings": [
          "f2f55ffbf696831576323d0bfac6710073e8ce7694eae99f",
          "d52c0c15507beee68123f8dd38a28eccc1f56de03388cfa0",
          "4e0fac824e2dfbbca047d85c6f05c523e3db2e31ac6d75d6"
        ],
        "index": 4,
        "value": "775aca6a322df3887dc19fe7da4b262b9dc02c3650630bf3"
      },
      {
        "root": "afce7d182834e48a88d45db6c3833ad51ceb60e5e5caa5e2",
        "siblings": [
          "e6aeed73c5843735fb3ac567abd4dbcfb894f7c5659b5e86",
          "ee53fc721f076d76ab64c995aa23d4a54382d82f27954b15",
          "943e3435a20752cc53ce03215c535e8b9c21016a7016df71"
        ],
        "index": 0,
        "value": "1de9f130254ec6a8ee3a8df8a539a205b3509ab0e3bff6cf"
      },
      {
        "root": "be224af255dd6bf53d56738040a8207bf8bb98027b59ae61",
        "siblings": [
          "b9f754b505eff11d424c1e6983a0db68b0c54b0bb6ae1059",
          "cc9181ae4127c5c8ee4b3d1adae560e09d3293acccd9b7e5",
          "4819814478941d48d8921a7b289b79c2709622517f826f56",
          "66341692f46741c611a709596135b09f4842ecca593f08a3"
        ],
        "index": 14,
        "value": "380f2b167ce130efcd797b77fb3eba3e18539a7bf3fe8772"
      },
      {
        "root": "be224af255dd6bf53d56738040a8207bf8bb98027b59ae61",
        "siblings": [
          "64fb394242203a7771adfeed453965654d3397f6c797ea13",
          "4ec9ff57795e4ccb7507c7f0e98fd18a9b47ad911df71c11",
          "e9cb96ba853ed70ffe9c3a0ddbf4ccc43770a278a01938db",
          "489c8649984fe624e6eee7588b8bde493c05e486e73023da"
        ],
        "index": 1,
        "value": "8bd918726e6167d1db01ba26a54cfc2b2d50c126381955ad"
      }
    ]
    "#;

    #[test]
    fn test_verify_small_merkle_proofs() {
        // build circuit once
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let parsed_proofs: Vec<MerkleProof192> = serde_json::from_str(SMALL_MERKLE_PROOFS).unwrap();
        for proof in parsed_proofs {
            let config = CircuitConfig::standard_recursion_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);

            let merkle_proof_gadget = MerkleProofTruncatedSha256Gadget::add_virtual_to(
                &mut builder,
                proof.siblings.len(),
            );
            let expected_root_target = builder.add_virtual_hash192_target();
            builder.connect_hash192(expected_root_target, merkle_proof_gadget.root);
            let num_gates = builder.num_gates();
            let data = builder.build::<C>();
            println!(
                "MerkleProofTruncatedSha256Gadget (height = {}) circuit num_gates={}, quotient_degree_factor={}",
                proof.siblings.len(), num_gates, data.common.quotient_degree_factor
            );

            let mut pw = PartialWitness::new();
            merkle_proof_gadget.set_witness_from_proof(&mut pw, &proof);
            pw.set_hash192_target(&expected_root_target, &proof.root.0);

            let start_time = std::time::Instant::now();

            let proof = data.prove(pw).unwrap();
            let duration_ms = start_time.elapsed().as_millis();
            println!("proved in {}ms", duration_ms);
            assert!(data.verify(proof).is_ok());
        }
    }
}
