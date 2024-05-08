use city_crypto::field::qfield::QRichField;
use plonky2::field::extension::Extendable;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use super::merkle_proof::compute_merkle_root;
use crate::hash::base_types::hash192::CircuitBuilderHash192;
use crate::hash::base_types::hash192::Hash192Target;
use crate::hash::base_types::hash192::WitnessHash192;
pub struct DeltaMerkleProofTruncatedSha256Gadget {
    pub old_root: Hash192Target,
    pub old_value: Hash192Target,

    pub new_root: Hash192Target,
    pub new_value: Hash192Target,

    pub siblings: Vec<Hash192Target>,
    pub index: Target,
}

impl DeltaMerkleProofTruncatedSha256Gadget {
    pub fn add_virtual_to<F: QRichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        height: usize,
    ) -> Self {
        let siblings: Vec<Hash192Target> = (0..height)
            .map(|_| builder.add_virtual_hash192_target())
            .collect();

        let old_value = builder.add_virtual_hash192_target();
        let new_value = builder.add_virtual_hash192_target();
        let index = builder.add_virtual_target();
        let index_bits = builder.split_le(index, height);
        let old_root = compute_merkle_root(builder, &index_bits, old_value, &siblings);
        let new_root = compute_merkle_root(builder, &index_bits, new_value, &siblings);

        Self {
            old_root,
            old_value,
            new_root,
            new_value,
            siblings,
            index,
        }
    }

    pub fn set_witness<F: QRichField, W: WitnessHash192<F>>(
        &self,
        witness: &mut W,
        index: u64,
        old_value: &[u8; 24],
        new_value: &[u8; 24],
        siblings: &[[u8; 24]],
    ) {
        witness.set_hash192_target(&self.old_value, old_value);
        witness.set_hash192_target(&self.new_value, new_value);
        witness.set_target(self.index, F::from_noncanonical_u64(index));
        for (i, sibling) in self.siblings.iter().enumerate() {
            witness.set_hash192_target(sibling, &siblings[i]);
        }
    }
}
#[cfg(test)]
mod tests {

    use city_crypto::hash::base_types::hash192::DeltaMerkleProof192;
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::GenericConfig;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;

    use crate::hash::base_types::hash192::CircuitBuilderHash192;
    use crate::hash::base_types::hash192::WitnessHash192;
    use crate::hash::merkle::gadgets::sha256_truncated::delta_merkle_proof::DeltaMerkleProofTruncatedSha256Gadget;

    const SMALL_DELTA_MERKLE_PROOFS: &str = r#"
    [
      {
        "index": 0,
        "siblings": [
          "000000000000000000000000000000000000000000000000",
          "df99695b9d441940e4e1adf727dc1c48d06f54afc9b2ffa6"
        ],
        "old_root": "8bb06fd2062223553c51e18f916a7ea2b3e519f400c4ddf6",
        "old_value": "000000000000000000000000000000000000000000000000",
        "new_value": "4b4b4ee152393271516423e92114bee4079859d0738e2e68",
        "new_root": "0e3aa6291d830f230dbe50907d496f4688527c6ad7fef833"
      },
      {
        "index": 2,
        "siblings": [
          "29337a6b91d34765a42d322b50c5fc673f9a8155dada38d5",
          "946660c9cd5c7116aa281248fdbf20c510ac65a85cea7e89"
        ],
        "old_root": "c35efd846a566c448964eaddbb0a0021abf18bc89476f631",
        "old_value": "467ee0cb54eb282384b15acd57563d70839f6a9353655657",
        "new_value": "9bdad0b5266866eb4ff6a4a5c89dbed940ccacf10db82d1f",
        "new_root": "f4c133e368fea599142cbf639a67d5870c06eefd671fb284"
      },
      {
        "index": 16,
        "siblings": [
          "a636b48f4ba58651e9f5ffa75917a28d6a92805d7707246c",
          "17b0761f87b081d5cf10757ccc89f12be355c70e2e29df28",
          "5b253a40fe440e2c1240afc1bc1ebdb355fce135f0d99097",
          "5a5c27f6767ebefeeb36acf5cb5bc978a52a9256e71e44b2",
          "34be2b390cd59779ee74f2942d2ba3f12176d07bb746b2af"
        ],
        "old_root": "adf4d0fd2a199895ae9193fdaab7d36ec080e75e420b160f",
        "old_value": "644108dd19e5a1f405c56fd6df1c6ff1c610b7d42561af2f",
        "new_value": "98cbbdaaa136ff0c42c34c07fcd876355df87052b6da63b9",
        "new_root": "de664d9bf989519d291363272520bb5d216fd20688e2b1b0"
      },
      {
        "index": 0,
        "siblings": [
          "000000000000000000000000000000000000000000000000",
          "17b0761f87b081d5cf10757ccc89f12be355c70e2e29df28",
          "5b253a40fe440e2c1240afc1bc1ebdb355fce135f0d99097",
          "f88fc9dc701329cbc8b855d67d4ad10e02190fdfeb78e6bb",
          "c277b62cd67e797e7b5c7142c392ca47a3730b399df2a0f4"
        ],
        "old_root": "58b53b7ec1ae789137bff540511a52b5a666c6bd9efb4b53",
        "old_value": "000000000000000000000000000000000000000000000000",
        "new_value": "045ace8b8f1a87385c3907241b5741e4b443ccb75e38b63f",
        "new_root": "c442c624e211aeb65a0e20750c9d7255c99e1fdff2b1dca8"
      },
      {
        "index": 6,
        "siblings": [
          "000000000000000000000000000000000000000000000000",
          "17b0761f87b081d5cf10757ccc89f12be355c70e2e29df28",
          "c205db5acaeee273bf4a36c2b9bb786d60400daaaab97077",
          "7f3640fc38c1888f8bcb4fd91074f16fb99e4479bc8aa6c8",
          "98e9ecb812ba1e96b20606c27b8baa95ac514cf8328c2d8f"
        ],
        "old_root": "e91eb054d74f257cf29734126e9f5fe1190f1f25cbf00e6a",
        "old_value": "5b181ca38a95331682ed666298af3a1773d21208ef4571d6",
        "new_value": "9935a6359038a6750966c9e2dd0327c6cf2f0d7ffe5110b8",
        "new_root": "75d66f9f33bb0a68cec9ded2b140c60800fa9a8941cabc87"
      },
      {
        "index": 23,
        "siblings": [
          "bcee8bc9cf701c33085580d858b6c765ec6172db34cfa62d",
          "e6680586a8925814396a8611a8a14e5c6a739cac0b24b374",
          "dbed913941a5d383bfe8f22c8ac0aab233ce2f4dda92ad9d",
          "8a67de69396927030e297acdea71f1a5bdf026dc373f618f",
          "119e81ebc51feea64117661eb263678b9a2acda0e363a704"
        ],
        "old_root": "9befd18443b5a9ff4d056fc460f35d4e9fcb7ecb2a81742d",
        "old_value": "abbfbf7fa78e9fc73267cf4ad0254cb9c4a35c7006b26b3b",
        "new_value": "4b8ad08f621022e95cb7e57522ebee76c77902d0f2c88a05",
        "new_root": "61cea17b1e4e18cb3d1f970b2a9765c76e84f80202dffefc"
      },
      {
        "index": 3,
        "siblings": [
          "000000000000000000000000000000000000000000000000",
          "537509bc887735cd284909580e34e43c8aa3c46d8387c02d",
          "9ff7cf34f94da25dfb5e354b0776f964e9fecf0de81e2509",
          "cacb3ca2589221d459911a0e7bff3f0a62e7c85016e239bb",
          "53464025934ba9b24b98b99e1337f106a29aa94a404aab2f"
        ],
        "old_root": "13a0c9fa7de022658f8c29dcb8c3ef6aeaa5c0e82ea07d41",
        "old_value": "000000000000000000000000000000000000000000000000",
        "new_value": "b9b94fe36a7188868d7392f98d776c3daa9cc2eff31e9d8f",
        "new_root": "545f9896f215d23ea516851799412c2d0fd41a079a3c75c7"
      },
      {
        "index": 25,
        "siblings": [
          "b5bbc9ca920933ceb3157330fbd9bd8edf919efdb8dfe7c8",
          "a470094ab070ab1ce6fc218b5d593d247649d96be90d93ef",
          "167ee6a38a2e85b19f00973df3960aa3badf70af7e3b9d23",
          "feb9ea7befe2cf08484efb33e8485cc6cfb617b01fa1b505",
          "13af4f8d184975534e42840c30d0a2804ba0037d0fe6a333"
        ],
        "old_root": "d30ef4068a30505322dc4576f2a4b701f5b76dc87f83f10a",
        "old_value": "000000000000000000000000000000000000000000000000",
        "new_value": "fa8828e6d55156099c625f3144404003415074d48e27f90d",
        "new_root": "4a9a6660a3b067e8afa015c80bbdcc2359e90e2569b7bc66"
      },
      {
        "index": 15,
        "siblings": [
          "a6c8ac63d731870f83d045771fa54a551dc1ec90e973b3d6",
          "5032aa0ed7644cfabb2cf73de88333901529e8dca34fa39c",
          "5b253a40fe440e2c1240afc1bc1ebdb355fce135f0d99097",
          "b50764d3cc0bc182c92679736f9fba7d47c14485af1234aa",
          "7ce1decb1e7d9eb29cb5000fa5d42ff5e0c08bc91d47677d"
        ],
        "old_root": "8539ae1b0468cd7b8738f79531b28481e17fa5d794809eac",
        "old_value": "3bf9c5a574d3897537c6068dfc474ecb72a1024a61cb6d11",
        "new_value": "5c4c7561bcf9cf2f0e376d226335dd506af9baed711222d1",
        "new_root": "7ea8cdb533fa66abaa413e60a5e93f38e0b808204a42b340"
      },
      {
        "index": 6,
        "siblings": [
          "000000000000000000000000000000000000000000000000",
          "10e359b3140973a869c54130413af692214a3434853475ca",
          "fea97c7b334d36f915a6664d5ca24a9d6b8a7f99c4106c9f",
          "2e1b582854d0d65efc1c38ee2ae12bf8bf68d3579703ec6b",
          "7ce1decb1e7d9eb29cb5000fa5d42ff5e0c08bc91d47677d"
        ],
        "old_root": "7ea8cdb533fa66abaa413e60a5e93f38e0b808204a42b340",
        "old_value": "ea932d6176fdbc36b6ff23d181ae07074517ceb6fbdc283d",
        "new_value": "e0f5e8fe395b2b7c7fbd13c31c9203551f51845be96ba07e",
        "new_root": "779452dad24be67db48d6ef8d5a4badfc040f1daa164c72e"
      },
      {
        "index": 13,
        "siblings": [
          "297d38dcc9c0a1db5d0a82a2a04d4a32fa52ba843a1aa732",
          "bedf6a6fc5b02b1d73661400155c1b249514deac6d4deb57",
          "b288da51d73ea51f75ab1bfd61e0fe006dc646a1f102e3b8",
          "6004dbf8bd6cf6b8483adc0bcd5e86fe8935f15f00059e8e"
        ],
        "old_root": "cd9c40176fd925daf613c897b9c121f26a315003f826308b",
        "old_value": "57598afea9d52df5e9fab747fa91e87357965670fc6b08a4",
        "new_value": "7055dc8053550062d278ee5da44c64d1e201e8bddec0a4a3",
        "new_root": "36091ce0057a596db89a6c3a6678c1b2fe05d1be78da0b88"
      },
      {
        "index": 5,
        "siblings": [
          "bbfe8a0bba40939c061e2153b2b59e2d25a3a2f0cbaabcdb",
          "ce586b1ce6f10beeacc41857c223d3a2fc108da3050a5ed6",
          "5b253a40fe440e2c1240afc1bc1ebdb355fce135f0d99097",
          "fea5eb2983a9bded7d01cd0332c3aa66718954b5e6e5b851"
        ],
        "old_root": "7a9061a251cae7c17305150835fe1e7d21dc0803cf42455a",
        "old_value": "000000000000000000000000000000000000000000000000",
        "new_value": "305c9a542e6840fdeadafeb72efbf6e9b17d23635b4e4cf0",
        "new_root": "eeaee4014b5be08e28eec7adefd38b37888a4623f29f5997"
      }
    ]
    "#;

    #[test]
    fn test_verify_small_delta_merkle_proofs() {
        // build circuit once
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let parsed_proofs: Vec<DeltaMerkleProof192> =
            serde_json::from_str(SMALL_DELTA_MERKLE_PROOFS).unwrap();
        for proof in parsed_proofs {
            let config = CircuitConfig::standard_recursion_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);

            let delta_merkle_proof_gadget = DeltaMerkleProofTruncatedSha256Gadget::add_virtual_to(
                &mut builder,
                proof.siblings.len(),
            );
            let expected_old_root_target = builder.add_virtual_hash192_target();
            let expected_new_root_target = builder.add_virtual_hash192_target();
            builder.connect_hash192(expected_old_root_target, delta_merkle_proof_gadget.old_root);
            builder.connect_hash192(expected_new_root_target, delta_merkle_proof_gadget.new_root);
            let num_gates = builder.num_gates();
            let data = builder.build::<C>();
            println!(
                "DeltaMerkleProofTruncatedSha256Gadget (height = {}) circuit num_gates={}, quotient_degree_factor={}",
                proof.siblings.len(), num_gates, data.common.quotient_degree_factor
            );

            let mut pw = PartialWitness::new();
            delta_merkle_proof_gadget.set_witness_from_proof(&mut pw, &proof);
            pw.set_hash192_target(&expected_old_root_target, &proof.old_root.0);
            pw.set_hash192_target(&expected_new_root_target, &proof.new_root.0);

            let start_time = std::time::Instant::now();

            let proof = data.prove(pw).unwrap();
            let duration_ms = start_time.elapsed().as_millis();
            println!("proved in {}ms", duration_ms);
            assert!(data.verify(proof).is_ok());
        }
    }
}
