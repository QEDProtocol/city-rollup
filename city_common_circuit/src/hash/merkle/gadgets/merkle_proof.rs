use bitflags::bitflags;
use city_crypto::hash::merkle::core::MerkleProof;
use city_crypto::hash::merkle::core::MerkleProofBase;
use city_crypto::hash::qhashout::QHashOut;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::BoolTarget;
use plonky2::iop::target::Target;
use plonky2::iop::witness::PartialWitness;
use plonky2::iop::witness::WitnessWrite;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::config::AlgebraicHasher;

use crate::builder::optional_inputs::CircuitBuilderOptionalInputs;
use crate::builder::select::CircuitBuilderSelectHelpers;

pub const NUM_HASH_OUT_ELEMENTS: usize = 4;
bitflags! {
  #[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
    pub struct MerkleProofGadgetOptionFlags: u64 {
        const none_value_placeholder = 0;
        const root = 0b1;
        const value = 0b10;
        const index = 0b100;
        const siblings = 0b1000;
    }
}
#[derive(Debug, Clone)]
pub struct MerkleProofGadget {
    pub root: HashOutTarget,
    pub value: HashOutTarget,
    pub index: Target,
    pub siblings: Vec<HashOutTarget>,
    pub option_flags: MerkleProofGadgetOptionFlags,
}
#[derive(Debug, Clone)]
pub struct OptionalMerkleProofGadget {
    pub root: Option<HashOutTarget>,
    pub value: Option<HashOutTarget>,
    pub index: Option<Target>,
    pub siblings: Option<Vec<HashOutTarget>>,
}
pub fn hash_merkle_leaves<F: RichField + Extendable<D>, const D: usize, H: AlgebraicHasher<F>>(
    builder: &mut CircuitBuilder<F, D>,
    leaves: &[HashOutTarget],
) -> HashOutTarget {
    // log2(leaves.len())
    let height = leaves.len().next_power_of_two().trailing_zeros() as usize;
    // ensure leaves.len() is a power of 2
    assert_eq!(
        1 << height,
        leaves.len(),
        "leaves.len() must be a power of 2"
    );
    let mut state = leaves.to_vec();
    for _ in 0..height {
        let mut next_state = vec![];
        for i in (0..state.len()).step_by(2) {
            let left = state[i];
            let right = if i + 1 < state.len() {
                state[i + 1]
            } else {
                state[i]
            };
            next_state
                .push(builder.hash_n_to_hash_no_pad::<H>([left.elements, right.elements].concat()));
        }
        state = next_state;
    }
    state[0]
}
impl MerkleProofGadget {
    pub fn add_virtual_to<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        height: usize,
    ) -> Self {
        let index = builder.add_virtual_target();
        let value = builder.add_virtual_hash();
        let siblings = (0..height)
            .map(|_| builder.add_virtual_hash())
            .collect::<Vec<_>>();
        let root = Self::compute_root::<H, F, D>(builder, index, value, &siblings);
        Self {
            root,
            value,
            index,
            siblings,
            option_flags: MerkleProofGadgetOptionFlags::none_value_placeholder,
        }
    }
    pub fn add_virtual_to_with_options<
        H: AlgebraicHasher<F>,
        F: RichField + Extendable<D>,
        const D: usize,
    >(
        builder: &mut CircuitBuilder<F, D>,
        height: usize,
        options: OptionalMerkleProofGadget,
    ) -> Self {
        let mut option_flags: u64 = 0;
        let index = builder.add_virtual_target_if_none_op(
            options.index,
            &mut option_flags,
            MerkleProofGadgetOptionFlags::index.bits(),
        );
        let value = builder.add_virtual_hash_if_none_op(
            options.value,
            &mut option_flags,
            MerkleProofGadgetOptionFlags::value.bits(),
        );
        let siblings = builder.add_virtual_hashes_if_none_op(
            options.siblings,
            height,
            &mut option_flags,
            MerkleProofGadgetOptionFlags::siblings.bits(),
        );

        let root = Self::compute_root::<H, F, D>(builder, index, value, &siblings);
        if options.root.is_some() {
            builder.connect_hashes(options.root.unwrap(), root);
        }
        Self {
            root,
            value,
            index,
            siblings,
            option_flags: MerkleProofGadgetOptionFlags::from_bits(option_flags).unwrap(),
        }
    }
    pub fn compute_root<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        index: Target,
        value: HashOutTarget,
        siblings: &[HashOutTarget],
    ) -> HashOutTarget {
        let height = siblings.len();
        builder.range_check(index, height);
        let index_bits = builder.split_le(index, height);

        Self::compute_root_bits::<H, F, D>(builder, &index_bits, value, siblings)
    }
    pub fn compute_root_bits<
        H: AlgebraicHasher<F>,
        F: RichField + Extendable<D>,
        const D: usize,
    >(
        builder: &mut CircuitBuilder<F, D>,
        index_bits: &[BoolTarget],
        value: HashOutTarget,
        siblings: &[HashOutTarget],
    ) -> HashOutTarget {
        //let zero = builder.zero();
        let mut state: HashOutTarget = value;
        //debug_assert_eq!(state.elements.len(), NUM_HASH_OUT_ELEMENTS);

        for (&bit, &sibling) in index_bits.iter().zip(siblings) {
            /*
            debug_assert_eq!(sibling.elements.len(), NUM_HASH_OUT_ELEMENTS);

            let mut perm_inputs = H::AlgebraicPermutation::default();
            perm_inputs.set_from_slice(&state.elements, 0);
            perm_inputs.set_from_slice(&sibling.elements, NUM_HASH_OUT_ELEMENTS);
            for i in (2 * NUM_HASH_OUT_ELEMENTS)..(H::AlgebraicPermutation::WIDTH) {
                perm_inputs.set_elt(zero, i);
            }
            let perm_outs = H::permute_swapped(perm_inputs, bit, builder);
            let hash_outs = perm_outs.squeeze()[0..NUM_HASH_OUT_ELEMENTS]
                .try_into()
                .unwrap();
            state = HashOutTarget {
                elements: hash_outs,
            };*/

            let left = builder.select_hash(bit, sibling, state);
            let right = builder.select_hash(bit, state, sibling);
            state = builder.hash_n_to_hash_no_pad::<H>([left.elements, right.elements].concat())
        }
        state
    }
    pub fn set_witness<F: RichField>(
        &self,
        witness: &mut PartialWitness<F>,
        index: F,
        value: QHashOut<F>,
        siblings: &[QHashOut<F>],
    ) {
        if !self
            .option_flags
            .contains(MerkleProofGadgetOptionFlags::index)
        {
            witness.set_target(self.index, index);
        }
        if !self
            .option_flags
            .contains(MerkleProofGadgetOptionFlags::value)
        {
            witness.set_hash_target(self.value, value.0);
        }
        if !self
            .option_flags
            .contains(MerkleProofGadgetOptionFlags::siblings)
        {
            for (i, sibling) in self.siblings.iter().enumerate() {
                witness.set_hash_target(*sibling, siblings[i].0);
            }
        }
    }
    pub fn set_witness_proof<F: RichField>(
        &self,
        witness: &mut PartialWitness<F>,
        input: &MerkleProof<F>,
    ) {
        self.set_witness(witness, input.index, input.value, &input.siblings);
    }
    pub fn set_witness_base_proof<F: RichField>(
        &self,
        witness: &mut PartialWitness<F>,
        input: &MerkleProofBase<F>,
    ) {
        self.set_witness(witness, input.index, input.value, &input.siblings);
    }
}

#[cfg(test)]
mod tests {
    use city_crypto::hash::merkle::core::MerkleProof;
    use plonky2::field::types::Field;
    use plonky2::hash::poseidon::PoseidonHash;
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::GenericConfig;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;

    use crate::hash::merkle::gadgets::merkle_proof::MerkleProofGadget;
    use crate::hash::merkle::gadgets::merkle_proof::OptionalMerkleProofGadget;

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    const TEST_CASES_JSON: &str = r#"
[
  {
    "root": "48a168b970925f21d4c6297f7a0fa82c138a938f20386ba5e2ee4675d27c16bf",
    "value": "ce75c39a1ed37647098c48dde52205b4b233356ed406e926fe2444e25940e732",
    "siblings": [
      "d9dae482b281470087f8a508320d187a76dcf670fe4ce941687bf512cf5a8064",
      "58b33930ef101821169d7301a9a54a28976c5dd4ca2ace11f831c13698441556"
    ],
    "index": 0
  },
  {
    "root": "401dcc57a36decd4597fc23e36e44055a5ca6d82114ee6ce31c9f1843a8f3348",
    "value": "599950c20672990eac192bc9778ba9d823a6f948ea273529a2143b00f0f37bf0",
    "siblings": [
      "d9dae482b281470087f8a508320d187a76dcf670fe4ce941687bf512cf5a8064",
      "58b33930ef101821169d7301a9a54a28976c5dd4ca2ace11f831c13698441556"
    ],
    "index": 0
  },
  {
    "root": "f522eaa0af88a040167d7cf3bf854d278cc1b30d2e2c09475154921a06462644",
    "value": "0000000000000000000000000000000000000000000000000000000000000000",
    "siblings": [
      "0000000000000000000000000000000000000000000000000000000000000000",
      "c71603f33a1144ca7953db0ab48808f4c4055e3364a246c33c18a9786cb0b359",
      "2196fc41328ae503de8f9ad762a30af28d85581b9901b2cfb61a4ad1aaf14fcc",
      "67703a0cc73ca54246fb94bfe956c05f9a247cc59da2de6461e00af7295ce05a"
    ],
    "index": 0
  },
  {
    "root": "b1b42f0b21a744c843cc801e7f2b982de86cdff6157856f08d0a6f21c2b437fe",
    "value": "ad73b8d4bf403e239a9eb242256f58f1f603022a116936db5c47eddd529a1c8f",
    "siblings": [
      "0000000000000000000000000000000000000000000000000000000000000000",
      "c71603f33a1144ca7953db0ab48808f4c4055e3364a246c33c18a9786cb0b359",
      "2196fc41328ae503de8f9ad762a30af28d85581b9901b2cfb61a4ad1aaf14fcc",
      "67703a0cc73ca54246fb94bfe956c05f9a247cc59da2de6461e00af7295ce05a"
    ],
    "index": 0
  },
  {
    "root": "ba0a3d1933494662054b17e44f944cf2a1fc84cfb7ecda34a864899123c9e636",
    "value": "0000000000000000000000000000000000000000000000000000000000000000",
    "siblings": [
      "28c4a86c5a02d68a7f6c13f974b18d16ba868e4232f58d65dd2ea76764c89669",
      "ccbf796be23810cee16885fde7d7ee35dfc46335739db561ee185f4490c84871",
      "b2676cba96d7ccf9c6372d3cdccd592e2959d48b5d7823d0d0575d3d17f76446",
      "2e0aa7bfcf3368a13b39816c86760095fa50f05acb50ad37b53ab25a190c0592"
    ],
    "index": 4
  },
  {
    "root": "197ad572f5dcdfc1a29095691114b512ba644408e71c7a5f1c166a05f4e0bc41",
    "value": "d24d98e8fa73ab9e13e063ee42aae88dcd9468d5ec29c3c45236de300a4510a0",
    "siblings": [
      "28c4a86c5a02d68a7f6c13f974b18d16ba868e4232f58d65dd2ea76764c89669",
      "ccbf796be23810cee16885fde7d7ee35dfc46335739db561ee185f4490c84871",
      "b2676cba96d7ccf9c6372d3cdccd592e2959d48b5d7823d0d0575d3d17f76446",
      "2e0aa7bfcf3368a13b39816c86760095fa50f05acb50ad37b53ab25a190c0592"
    ],
    "index": 4
  },
  {
    "root": "d860ca274d278faf1db95617bd8c1be9356a4d2721bd5011bcaccc05baa8ba6e",
    "value": "c4a49a93c9b40b68199c69307f217ec55b046d7ec0ab7fa4886663c2d864bda0",
    "siblings": [
      "361ad4684e61adc9f9b5647c74bf1dd50691c6fe1de48c27973e514c9eb667ae",
      "de492a33e2b5f2252b29266c102987ddebd8374268696f9c98bcc0ad29ee5b9f",
      "850501d8cff858fe9fc51dd2decde27b163ed739b235fcf5a21af3887e584f26",
      "5c3677a96d5c21ce08670bd2bda3cef28b8ffb0c3b3d3f8af1deb7c721045cc1"
    ],
    "index": 8
  },
  {
    "root": "8fb689e858aa2eb5023ea8537ff3e9a99b4dc1b09586ba02b52b293c27c0036a",
    "value": "5859adba12675a8d1fb9e4078992f54f7c26137e7ae724328843dbf5cc467bef",
    "siblings": [
      "361ad4684e61adc9f9b5647c74bf1dd50691c6fe1de48c27973e514c9eb667ae",
      "de492a33e2b5f2252b29266c102987ddebd8374268696f9c98bcc0ad29ee5b9f",
      "850501d8cff858fe9fc51dd2decde27b163ed739b235fcf5a21af3887e584f26",
      "5c3677a96d5c21ce08670bd2bda3cef28b8ffb0c3b3d3f8af1deb7c721045cc1"
    ],
    "index": 8
  },
  {
    "root": "8d4be89dc402dcd3ef7063840a59bc76f8162053634dd6f81293d5e607c7d4e7",
    "value": "361ad4684e61adc9f9b5647c74bf1dd50691c6fe1de48c27973e514c9eb667ae",
    "siblings": [
      "5859adba12675a8d1fb9e4078992f54f7c26137e7ae724328843dbf5cc467bef",
      "a174e5d43736335c23fb68a672cb6547fcc0ed891c170b172c2d47e231dea466",
      "ba4bbd3bae48820cab9b4a2373c4b68815c91c1d14a817b530dc90629a0184e3",
      "c64caf2311994fe26807a31669102359dac37267987405a0fe81c37f36a83c0a"
    ],
    "index": 9
  },
  {
    "root": "a3c79f7475cadfea7cc08d9d6df86fe9d5d084356b04924cf445c2fb98cec05b",
    "value": "58415022e6792d2175abc2915036d8fc5e5d220e02a5ae87242ccc9880f1f4b2",
    "siblings": [
      "5859adba12675a8d1fb9e4078992f54f7c26137e7ae724328843dbf5cc467bef",
      "a174e5d43736335c23fb68a672cb6547fcc0ed891c170b172c2d47e231dea466",
      "ba4bbd3bae48820cab9b4a2373c4b68815c91c1d14a817b530dc90629a0184e3",
      "c64caf2311994fe26807a31669102359dac37267987405a0fe81c37f36a83c0a"
    ],
    "index": 9
  },
  {
    "root": "b87eed46f6fd906d094036a531c6eba64a2bfa986ab8b01fa9d782e69a9362df",
    "value": "cb97308d10df5240c7632d85c15df3d613a4f9e0ec188ac4c188c3e9b1664cfb",
    "siblings": [
      "9b4157478535bdeddfdb5322a145e25cd22d1cbe0153f8d3fccd512a44519f71",
      "fc603a9dca3d0e9359dd96cf23ca9d0d7abb249c5f24072918adcc2cb76fb4a4",
      "6d84b46ae901c7074c840846806364f5887fcb187877828ec32c5dee17830740",
      "026c1cbee4b4ee8b2e3134e41e42743a1efc5534c720e336bded878f5fb39d8b"
    ],
    "index": 7
  },
  {
    "root": "e65beed3aba31b6258c2d26b95e97a032b84680e62f69bf21033819bd2b72be2",
    "value": "41b753dad014504a128b0edba3a5fa4fa273df097d74597235022a9b7acc1870",
    "siblings": [
      "9b4157478535bdeddfdb5322a145e25cd22d1cbe0153f8d3fccd512a44519f71",
      "fc603a9dca3d0e9359dd96cf23ca9d0d7abb249c5f24072918adcc2cb76fb4a4",
      "6d84b46ae901c7074c840846806364f5887fcb187877828ec32c5dee17830740",
      "026c1cbee4b4ee8b2e3134e41e42743a1efc5534c720e336bded878f5fb39d8b"
    ],
    "index": 7
  },
  {
    "root": "bde22809447fe4f773750f0c1ece7a65e1666d21fb5924f955b89b3e825a04ad",
    "value": "19a3360f7ff66d21dd59258bb031d963e5b6bd20be6d1f3c7fb8ef238e41c31c",
    "siblings": [
      "1935c822114bfffdd5c9dc6b1af39a070186fb71093d465cb4ef1d537b683c49",
      "6b150d51239162205fdb069a32b6bb440245799a312279ad1993d26ffbca383f",
      "6432b0a97ec875a5acbb2c48922e540fe083a13b92e9c3a813c1f42a77409bca"
    ],
    "index": 6
  },
  {
    "root": "aeeb04c54fd5b82629a8db49678d518d2a6fdb83bce1199156e8aa332c6a0e9e",
    "value": "de549ffafc39aa0da2c18c83252340501898a1d4043c9f781e76573a0b08af90",
    "siblings": [
      "1935c822114bfffdd5c9dc6b1af39a070186fb71093d465cb4ef1d537b683c49",
      "6b150d51239162205fdb069a32b6bb440245799a312279ad1993d26ffbca383f",
      "6432b0a97ec875a5acbb2c48922e540fe083a13b92e9c3a813c1f42a77409bca"
    ],
    "index": 6
  },
  {
    "root": "28161e1f31ebb03524096d16e69bba006bcdad73f0029f30728bc4e117a6c303",
    "siblings": [
      "0000000000000000000000000000000000000000000000000000000000000000",
      "c71603f33a1144ca7953db0ab48808f4c4055e3364a246c33c18a9786cb0b359",
      "2196fc41328ae503de8f9ad762a30af28d85581b9901b2cfb61a4ad1aaf14fcc",
      "67703a0cc73ca54246fb94bfe956c05f9a247cc59da2de6461e00af7295ce05a",
      "09e52b12f83053bddbf974430003e5b7ff549991ce90c14a6e832a2c3e51ba74",
      "d74135736c4c0566e6cf3c08065874eee4599f77bcb163929299f3f67588dcc9",
      "887df68a5badb025aec7926724d8bd3badbb162c502e07dee13c211b06c01a79",
      "f5d7bf6822225843d5ff7d6103d9bb5ca3be7b9134a113991f998d7d22e2b826",
      "2828673d59e21e6ba900e5a505e2206fb4806142bd6418faea9b8887c2a4573a"
    ],
    "index": 288,
    "value": "e67e2fa1c90484783e7100ad158656c08e6226a02e08f01b0f07ca9ea011a160"
  },
  {
    "root": "28161e1f31ebb03524096d16e69bba006bcdad73f0029f30728bc4e117a6c303",
    "siblings": [
      "0000000000000000000000000000000000000000000000000000000000000000",
      "c71603f33a1144ca7953db0ab48808f4c4055e3364a246c33c18a9786cb0b359",
      "2196fc41328ae503de8f9ad762a30af28d85581b9901b2cfb61a4ad1aaf14fcc",
      "459408c907ffeb65aa4bd0ae46b1b8bbe4f280eef6e5ed2f879f82b203ba27aa",
      "f522eaa0af88a040167d7cf3bf854d278cc1b30d2e2c09475154921a06462644",
      "ddc70023cf1c46d2c487578d6ed80a277c941193c8aa3ff9663fa763b170b197",
      "0eb0b32fcee961b2935cca5ce3366a285b128f35e9979237bd714295795c6b7f",
      "1a708854e08e26780c759a3f956365b990c284a5c4ffda08db9190d67cb2f05d",
      "2828673d59e21e6ba900e5a505e2206fb4806142bd6418faea9b8887c2a4573a"
    ],
    "index": 408,
    "value": "0000000000000000000000000000000000000000000000000000000000000000"
  },
  {
    "root": "5b2fa83de63806dc3fd9d48f69dd9b808b9cccb515b648597da211bbe18c6100",
    "siblings": [
      "0000000000000000000000000000000000000000000000000000000000000000",
      "c71603f33a1144ca7953db0ab48808f4c4055e3364a246c33c18a9786cb0b359",
      "2196fc41328ae503de8f9ad762a30af28d85581b9901b2cfb61a4ad1aaf14fcc",
      "67703a0cc73ca54246fb94bfe956c05f9a247cc59da2de6461e00af7295ce05a",
      "f522eaa0af88a040167d7cf3bf854d278cc1b30d2e2c09475154921a06462644",
      "d0053597686f6672b77e23f0fc59019786ac9b34bd97d439e9e6b5c8d15b61ae",
      "49561260080d30c3dda8f741c47dfb105a1d2a648eee8f0325225f1a5d49614a",
      "b768e4fc8b0b79f516c9da6ea83aa4b13c9a42c646c4c1f9e979ed3ee20855e3",
      "2bd367124a2989b3d31bd45195f9a9278d72cff3db0a7a5afe6fd7720cfd2916",
      "fcf1da35791ff4452cf0c633ee9d9197954ec02c35af849e3ca2442157c9f14e",
      "c27e8f4600af2a41707c71f51d338df791e919b1e4a3ea53ccf7b63f7b1140c3",
      "218bc75b3bc83675e1c5ac76b0d9d44c0d1baab6f05098e38d6ebaad0ab5d3c3",
      "61618c69e9d26f4c8ee39e4c215804e2fb01846fee718016ed2589168e839d21",
      "ec76a20799cf5dc50841b1fa4588f4f8c975d7aec7a1c669296ff821d8378f7f",
      "f55d5d12107b371efb4650fb6b8880811f7867621b8c1c1a0168a392cc7b542c",
      "6c9890682b94dee9cd45643c378df78c64e3f7a7160f8f0de73c5360c4b3ecd8",
      "a389c2c6eab51bf0defcc71c25a6f23f26a0d96510bb6510dfe41b9a1becde73",
      "0aa45be01f9e161002f8e22c79467775279949e14530c2505587ad00b6ddf0cb",
      "d2e3dd2bdd2907959ef35a5aeb905682388540a0f77810a8d108cd9026164f3b",
      "33a8e0b809ce2532ae94d561f2e16def904fa2e7b99bd3f1707d95a1148000a1",
      "7c9f51793bca6ffb713d0a918edaa60557184cbbc85f535743926baabe5db81f",
      "9d79dbbe85c8280c7c24ee99e983af2c7a3ac75de42bf8edd6195d74e60407c8",
      "29750df3163288b9e34810f015aa58a85912d8f8b46e79096826535ba8900473",
      "573b947295fc96cedc0846e224ccdf739e5ded030b0dae9603378e274781d0a7",
      "534cb952ccdffa820f68c72b417656f91be266b59551b2a199deb3cc813ba967"
    ],
    "index": 9821781,
    "value": "0000000000000000000000000000000000000000000000000000000000000000"
  },
  {
    "root": "5b2fa83de63806dc3fd9d48f69dd9b808b9cccb515b648597da211bbe18c6100",
    "siblings": [
      "0000000000000000000000000000000000000000000000000000000000000000",
      "c71603f33a1144ca7953db0ab48808f4c4055e3364a246c33c18a9786cb0b359",
      "2196fc41328ae503de8f9ad762a30af28d85581b9901b2cfb61a4ad1aaf14fcc",
      "67703a0cc73ca54246fb94bfe956c05f9a247cc59da2de6461e00af7295ce05a",
      "f522eaa0af88a040167d7cf3bf854d278cc1b30d2e2c09475154921a06462644",
      "d0053597686f6672b77e23f0fc59019786ac9b34bd97d439e9e6b5c8d15b61ae",
      "49561260080d30c3dda8f741c47dfb105a1d2a648eee8f0325225f1a5d49614a",
      "b768e4fc8b0b79f516c9da6ea83aa4b13c9a42c646c4c1f9e979ed3ee20855e3",
      "2bd367124a2989b3d31bd45195f9a9278d72cff3db0a7a5afe6fd7720cfd2916",
      "fcf1da35791ff4452cf0c633ee9d9197954ec02c35af849e3ca2442157c9f14e",
      "c27e8f4600af2a41707c71f51d338df791e919b1e4a3ea53ccf7b63f7b1140c3",
      "218bc75b3bc83675e1c5ac76b0d9d44c0d1baab6f05098e38d6ebaad0ab5d3c3",
      "61618c69e9d26f4c8ee39e4c215804e2fb01846fee718016ed2589168e839d21",
      "ec76a20799cf5dc50841b1fa4588f4f8c975d7aec7a1c669296ff821d8378f7f",
      "f55d5d12107b371efb4650fb6b8880811f7867621b8c1c1a0168a392cc7b542c",
      "6c9890682b94dee9cd45643c378df78c64e3f7a7160f8f0de73c5360c4b3ecd8",
      "9e1c5239e937026b57b8f931187d6dc4b555892ea200cfe4ab95f0ae94f7cde6",
      "0aa45be01f9e161002f8e22c79467775279949e14530c2505587ad00b6ddf0cb",
      "d2e3dd2bdd2907959ef35a5aeb905682388540a0f77810a8d108cd9026164f3b",
      "33a8e0b809ce2532ae94d561f2e16def904fa2e7b99bd3f1707d95a1148000a1",
      "7c9f51793bca6ffb713d0a918edaa60557184cbbc85f535743926baabe5db81f",
      "4b0a0088d268bcb44f42d9e9b917b0d422ef15fc98a2f27b68a9bfa5141e6728",
      "8b838ab50fb712e651aa83e8d199fe532195384acc47d2dc7e328b40bf80067e",
      "9205697b0fd185bb5cae7e3ac6d707c909f5671d026b7db00d3ca9c212664b74",
      "8648cb231df38dee492cd6a398fedf70c5cb9be4756053c40f6f79d864c49c92"
    ],
    "index": 32505673,
    "value": "0000000000000000000000000000000000000000000000000000000000000000"
  },
  {
    "root": "c379ed886391ac6a4ea8c91bc3107b16b85452433c670d04424dc28a6b537876",
    "siblings": [
      "0000000000000000000000000000000000000000000000000000000000000000",
      "c71603f33a1144ca7953db0ab48808f4c4055e3364a246c33c18a9786cb0b359",
      "2196fc41328ae503de8f9ad762a30af28d85581b9901b2cfb61a4ad1aaf14fcc",
      "67703a0cc73ca54246fb94bfe956c05f9a247cc59da2de6461e00af7295ce05a",
      "f522eaa0af88a040167d7cf3bf854d278cc1b30d2e2c09475154921a06462644",
      "d0053597686f6672b77e23f0fc59019786ac9b34bd97d439e9e6b5c8d15b61ae",
      "49561260080d30c3dda8f741c47dfb105a1d2a648eee8f0325225f1a5d49614a",
      "b768e4fc8b0b79f516c9da6ea83aa4b13c9a42c646c4c1f9e979ed3ee20855e3",
      "2bd367124a2989b3d31bd45195f9a9278d72cff3db0a7a5afe6fd7720cfd2916",
      "fcf1da35791ff4452cf0c633ee9d9197954ec02c35af849e3ca2442157c9f14e",
      "ad32a484a6ca7160651f979e52f7652ed9c82c68ccfe8d2b514258efd2c2c617",
      "218bc75b3bc83675e1c5ac76b0d9d44c0d1baab6f05098e38d6ebaad0ab5d3c3",
      "e0bb32e6bdffc467af072de74894469a34030f79b687b1960ee0fd4d6af9c7be",
      "ec76a20799cf5dc50841b1fa4588f4f8c975d7aec7a1c669296ff821d8378f7f",
      "10858921e5616ace519ce4e26de6a7db0cf7b05710f3e12b6784277c9ace19e9",
      "b61205a9270c3fc262f7185ea2484f1229d3f6aa56f8ecba8562b51fbfbcf33f",
      "d0056908b9cbd1fed1da495a58e819feabb3ad44788e1ede494952a8da998d29"
    ],
    "index": 94655,
    "value": "0000000000000000000000000000000000000000000000000000000000000000"
  },

  {
    "root": "e0c55886db8e5a00bfa58f8faf71ab1e1f12ae8ff82875c95b3c0f2c8ee070cc",
    "value": "0000000000000000000000000000000000000000000000000000000000000000",
    "siblings": [
      "0000000000000000000000000000000000000000000000000000000000000000",
      "c71603f33a1144ca7953db0ab48808f4c4055e3364a246c33c18a9786cb0b359",
      "2196fc41328ae503de8f9ad762a30af28d85581b9901b2cfb61a4ad1aaf14fcc",
      "67703a0cc73ca54246fb94bfe956c05f9a247cc59da2de6461e00af7295ce05a",
      "f522eaa0af88a040167d7cf3bf854d278cc1b30d2e2c09475154921a06462644",
      "d0053597686f6672b77e23f0fc59019786ac9b34bd97d439e9e6b5c8d15b61ae",
      "49561260080d30c3dda8f741c47dfb105a1d2a648eee8f0325225f1a5d49614a",
      "b768e4fc8b0b79f516c9da6ea83aa4b13c9a42c646c4c1f9e979ed3ee20855e3",
      "2bd367124a2989b3d31bd45195f9a9278d72cff3db0a7a5afe6fd7720cfd2916",
      "fcf1da35791ff4452cf0c633ee9d9197954ec02c35af849e3ca2442157c9f14e",
      "c27e8f4600af2a41707c71f51d338df791e919b1e4a3ea53ccf7b63f7b1140c3",
      "218bc75b3bc83675e1c5ac76b0d9d44c0d1baab6f05098e38d6ebaad0ab5d3c3",
      "61618c69e9d26f4c8ee39e4c215804e2fb01846fee718016ed2589168e839d21",
      "ec76a20799cf5dc50841b1fa4588f4f8c975d7aec7a1c669296ff821d8378f7f",
      "f55d5d12107b371efb4650fb6b8880811f7867621b8c1c1a0168a392cc7b542c",
      "6c9890682b94dee9cd45643c378df78c64e3f7a7160f8f0de73c5360c4b3ecd8",
      "9e1c5239e937026b57b8f931187d6dc4b555892ea200cfe4ab95f0ae94f7cde6",
      "0aa45be01f9e161002f8e22c79467775279949e14530c2505587ad00b6ddf0cb",
      "d2e3dd2bdd2907959ef35a5aeb905682388540a0f77810a8d108cd9026164f3b",
      "33a8e0b809ce2532ae94d561f2e16def904fa2e7b99bd3f1707d95a1148000a1",
      "7c9f51793bca6ffb713d0a918edaa60557184cbbc85f535743926baabe5db81f",
      "fa58391e7c0d394d317903270df6e518b34770c62a38e6697621f88cdcdfb5fd",
      "60e99b7ea5b1187d4293a24d51cc07ac39f874beb115877f8bd1878dd7f1026d",
      "c043477d124292017879345b4f881eb71d31cd8564acce2a617f3c6d0b4b8b44",
      "5793fc6d609c47c365b9470bc3e00cd4f19dece13278be693612ac9d812a8f8c"
    ],
    "index": 29452237
  },
  {
    "root": "88f7b5bccc9e88db39213fbd5b51559d3799da1bcdf9aaf59eef6bfbe944005a",
    "value": "d3b9d6acd52002889a458772e060062060bb6d9f3c01717464835f62eca6752e",
    "siblings": [
      "0000000000000000000000000000000000000000000000000000000000000000",
      "c71603f33a1144ca7953db0ab48808f4c4055e3364a246c33c18a9786cb0b359",
      "2196fc41328ae503de8f9ad762a30af28d85581b9901b2cfb61a4ad1aaf14fcc",
      "67703a0cc73ca54246fb94bfe956c05f9a247cc59da2de6461e00af7295ce05a",
      "f522eaa0af88a040167d7cf3bf854d278cc1b30d2e2c09475154921a06462644",
      "d0053597686f6672b77e23f0fc59019786ac9b34bd97d439e9e6b5c8d15b61ae",
      "49561260080d30c3dda8f741c47dfb105a1d2a648eee8f0325225f1a5d49614a",
      "b768e4fc8b0b79f516c9da6ea83aa4b13c9a42c646c4c1f9e979ed3ee20855e3",
      "2bd367124a2989b3d31bd45195f9a9278d72cff3db0a7a5afe6fd7720cfd2916",
      "fcf1da35791ff4452cf0c633ee9d9197954ec02c35af849e3ca2442157c9f14e",
      "c27e8f4600af2a41707c71f51d338df791e919b1e4a3ea53ccf7b63f7b1140c3",
      "218bc75b3bc83675e1c5ac76b0d9d44c0d1baab6f05098e38d6ebaad0ab5d3c3",
      "61618c69e9d26f4c8ee39e4c215804e2fb01846fee718016ed2589168e839d21",
      "ec76a20799cf5dc50841b1fa4588f4f8c975d7aec7a1c669296ff821d8378f7f",
      "f55d5d12107b371efb4650fb6b8880811f7867621b8c1c1a0168a392cc7b542c",
      "6c9890682b94dee9cd45643c378df78c64e3f7a7160f8f0de73c5360c4b3ecd8",
      "9e1c5239e937026b57b8f931187d6dc4b555892ea200cfe4ab95f0ae94f7cde6",
      "0aa45be01f9e161002f8e22c79467775279949e14530c2505587ad00b6ddf0cb",
      "d2e3dd2bdd2907959ef35a5aeb905682388540a0f77810a8d108cd9026164f3b",
      "33a8e0b809ce2532ae94d561f2e16def904fa2e7b99bd3f1707d95a1148000a1",
      "7c9f51793bca6ffb713d0a918edaa60557184cbbc85f535743926baabe5db81f",
      "fa58391e7c0d394d317903270df6e518b34770c62a38e6697621f88cdcdfb5fd",
      "60e99b7ea5b1187d4293a24d51cc07ac39f874beb115877f8bd1878dd7f1026d",
      "c043477d124292017879345b4f881eb71d31cd8564acce2a617f3c6d0b4b8b44",
      "5793fc6d609c47c365b9470bc3e00cd4f19dece13278be693612ac9d812a8f8c"
    ],
    "index": 29452237
  },
  {
    "root": "136d1e4de0ec40976bbc33f7629585b0d61bd7fc765b146828be4825a134fb10",
    "value": "0000000000000000000000000000000000000000000000000000000000000000",
    "siblings": [
      "0000000000000000000000000000000000000000000000000000000000000000",
      "c71603f33a1144ca7953db0ab48808f4c4055e3364a246c33c18a9786cb0b359",
      "2196fc41328ae503de8f9ad762a30af28d85581b9901b2cfb61a4ad1aaf14fcc",
      "67703a0cc73ca54246fb94bfe956c05f9a247cc59da2de6461e00af7295ce05a",
      "f522eaa0af88a040167d7cf3bf854d278cc1b30d2e2c09475154921a06462644",
      "d0053597686f6672b77e23f0fc59019786ac9b34bd97d439e9e6b5c8d15b61ae",
      "49561260080d30c3dda8f741c47dfb105a1d2a648eee8f0325225f1a5d49614a",
      "b768e4fc8b0b79f516c9da6ea83aa4b13c9a42c646c4c1f9e979ed3ee20855e3",
      "2bd367124a2989b3d31bd45195f9a9278d72cff3db0a7a5afe6fd7720cfd2916",
      "fcf1da35791ff4452cf0c633ee9d9197954ec02c35af849e3ca2442157c9f14e",
      "c27e8f4600af2a41707c71f51d338df791e919b1e4a3ea53ccf7b63f7b1140c3",
      "218bc75b3bc83675e1c5ac76b0d9d44c0d1baab6f05098e38d6ebaad0ab5d3c3",
      "61618c69e9d26f4c8ee39e4c215804e2fb01846fee718016ed2589168e839d21",
      "ec76a20799cf5dc50841b1fa4588f4f8c975d7aec7a1c669296ff821d8378f7f",
      "f55d5d12107b371efb4650fb6b8880811f7867621b8c1c1a0168a392cc7b542c",
      "6c9890682b94dee9cd45643c378df78c64e3f7a7160f8f0de73c5360c4b3ecd8",
      "9e1c5239e937026b57b8f931187d6dc4b555892ea200cfe4ab95f0ae94f7cde6",
      "0aa45be01f9e161002f8e22c79467775279949e14530c2505587ad00b6ddf0cb",
      "d2e3dd2bdd2907959ef35a5aeb905682388540a0f77810a8d108cd9026164f3b",
      "33a8e0b809ce2532ae94d561f2e16def904fa2e7b99bd3f1707d95a1148000a1",
      "f4961fc98b4ded038d2d045f362fa4b334de410d1e5c2cbd2cd53d3e5fa8c492",
      "fa58391e7c0d394d317903270df6e518b34770c62a38e6697621f88cdcdfb5fd",
      "b79cb96883fe8a077e5c6386913997550a9f90334dffc3709bac58d0f738539d",
      "6915fd3578c61ee777a15fbb51b97f1b4a73eef678b4f994269bc26afbea702d",
      "a50b870a929f15d260dbee4f95b0ac3f9772a0dca9e8be531499ffecd76dead3"
    ],
    "index": 23376084
  },
  {
    "root": "0f2f6f0f022bbf3ca215d3b404c499867ab3494d0130d487949215e0936cbab7",
    "value": "67ca468ade96685df6f87d07dfe95713c2b0e496d7e132b83432e9e9b27409cc",
    "siblings": [
      "0000000000000000000000000000000000000000000000000000000000000000",
      "c71603f33a1144ca7953db0ab48808f4c4055e3364a246c33c18a9786cb0b359",
      "2196fc41328ae503de8f9ad762a30af28d85581b9901b2cfb61a4ad1aaf14fcc",
      "67703a0cc73ca54246fb94bfe956c05f9a247cc59da2de6461e00af7295ce05a",
      "f522eaa0af88a040167d7cf3bf854d278cc1b30d2e2c09475154921a06462644",
      "d0053597686f6672b77e23f0fc59019786ac9b34bd97d439e9e6b5c8d15b61ae",
      "49561260080d30c3dda8f741c47dfb105a1d2a648eee8f0325225f1a5d49614a",
      "b768e4fc8b0b79f516c9da6ea83aa4b13c9a42c646c4c1f9e979ed3ee20855e3",
      "2bd367124a2989b3d31bd45195f9a9278d72cff3db0a7a5afe6fd7720cfd2916",
      "fcf1da35791ff4452cf0c633ee9d9197954ec02c35af849e3ca2442157c9f14e",
      "c27e8f4600af2a41707c71f51d338df791e919b1e4a3ea53ccf7b63f7b1140c3",
      "218bc75b3bc83675e1c5ac76b0d9d44c0d1baab6f05098e38d6ebaad0ab5d3c3",
      "61618c69e9d26f4c8ee39e4c215804e2fb01846fee718016ed2589168e839d21",
      "ec76a20799cf5dc50841b1fa4588f4f8c975d7aec7a1c669296ff821d8378f7f",
      "f55d5d12107b371efb4650fb6b8880811f7867621b8c1c1a0168a392cc7b542c",
      "6c9890682b94dee9cd45643c378df78c64e3f7a7160f8f0de73c5360c4b3ecd8",
      "9e1c5239e937026b57b8f931187d6dc4b555892ea200cfe4ab95f0ae94f7cde6",
      "0aa45be01f9e161002f8e22c79467775279949e14530c2505587ad00b6ddf0cb",
      "d2e3dd2bdd2907959ef35a5aeb905682388540a0f77810a8d108cd9026164f3b",
      "33a8e0b809ce2532ae94d561f2e16def904fa2e7b99bd3f1707d95a1148000a1",
      "f4961fc98b4ded038d2d045f362fa4b334de410d1e5c2cbd2cd53d3e5fa8c492",
      "fa58391e7c0d394d317903270df6e518b34770c62a38e6697621f88cdcdfb5fd",
      "b79cb96883fe8a077e5c6386913997550a9f90334dffc3709bac58d0f738539d",
      "6915fd3578c61ee777a15fbb51b97f1b4a73eef678b4f994269bc26afbea702d",
      "a50b870a929f15d260dbee4f95b0ac3f9772a0dca9e8be531499ffecd76dead3"
    ],
    "index": 23376084
  },
  {
    "root": "9da3631d9134277b20de4627d6caa3b576b04b8f21b3db6c5bf41a3e798dcf50",
    "value": "0000000000000000000000000000000000000000000000000000000000000000",
    "siblings": [
      "0000000000000000000000000000000000000000000000000000000000000000",
      "c71603f33a1144ca7953db0ab48808f4c4055e3364a246c33c18a9786cb0b359",
      "2196fc41328ae503de8f9ad762a30af28d85581b9901b2cfb61a4ad1aaf14fcc",
      "67703a0cc73ca54246fb94bfe956c05f9a247cc59da2de6461e00af7295ce05a",
      "f522eaa0af88a040167d7cf3bf854d278cc1b30d2e2c09475154921a06462644",
      "d0053597686f6672b77e23f0fc59019786ac9b34bd97d439e9e6b5c8d15b61ae",
      "49561260080d30c3dda8f741c47dfb105a1d2a648eee8f0325225f1a5d49614a",
      "b768e4fc8b0b79f516c9da6ea83aa4b13c9a42c646c4c1f9e979ed3ee20855e3",
      "2bd367124a2989b3d31bd45195f9a9278d72cff3db0a7a5afe6fd7720cfd2916",
      "fcf1da35791ff4452cf0c633ee9d9197954ec02c35af849e3ca2442157c9f14e",
      "c27e8f4600af2a41707c71f51d338df791e919b1e4a3ea53ccf7b63f7b1140c3",
      "218bc75b3bc83675e1c5ac76b0d9d44c0d1baab6f05098e38d6ebaad0ab5d3c3",
      "61618c69e9d26f4c8ee39e4c215804e2fb01846fee718016ed2589168e839d21",
      "ec76a20799cf5dc50841b1fa4588f4f8c975d7aec7a1c669296ff821d8378f7f",
      "f55d5d12107b371efb4650fb6b8880811f7867621b8c1c1a0168a392cc7b542c",
      "6c9890682b94dee9cd45643c378df78c64e3f7a7160f8f0de73c5360c4b3ecd8",
      "9e1c5239e937026b57b8f931187d6dc4b555892ea200cfe4ab95f0ae94f7cde6",
      "0aa45be01f9e161002f8e22c79467775279949e14530c2505587ad00b6ddf0cb",
      "d2e3dd2bdd2907959ef35a5aeb905682388540a0f77810a8d108cd9026164f3b",
      "33a8e0b809ce2532ae94d561f2e16def904fa2e7b99bd3f1707d95a1148000a1",
      "7c9f51793bca6ffb713d0a918edaa60557184cbbc85f535743926baabe5db81f",
      "fa58391e7c0d394d317903270df6e518b34770c62a38e6697621f88cdcdfb5fd",
      "b668387b2d03e4a4d0ef642d0ebe9539737f65cd1815b7e4ba80f5b13b0d9143",
      "87609936484f5c7dc888d7a67f416d27d33ed73a6827ebb0585729bc8ba6f0eb",
      "1cbbe778d52946eee72cdbbe4e237717de928bfd6c8a9acbbb56b7a473823fac"
    ],
    "index": 4355416
  },
  {
    "root": "324d6820019466e3ca070627561725e141499c8d5d39feee68d13c259c1c3945",
    "value": "cf883d908883933003e2aef9994250c8fbac444fc2a4cdbae1e8dd1c9930836a",
    "siblings": [
      "0000000000000000000000000000000000000000000000000000000000000000",
      "c71603f33a1144ca7953db0ab48808f4c4055e3364a246c33c18a9786cb0b359",
      "2196fc41328ae503de8f9ad762a30af28d85581b9901b2cfb61a4ad1aaf14fcc",
      "67703a0cc73ca54246fb94bfe956c05f9a247cc59da2de6461e00af7295ce05a",
      "f522eaa0af88a040167d7cf3bf854d278cc1b30d2e2c09475154921a06462644",
      "d0053597686f6672b77e23f0fc59019786ac9b34bd97d439e9e6b5c8d15b61ae",
      "49561260080d30c3dda8f741c47dfb105a1d2a648eee8f0325225f1a5d49614a",
      "b768e4fc8b0b79f516c9da6ea83aa4b13c9a42c646c4c1f9e979ed3ee20855e3",
      "2bd367124a2989b3d31bd45195f9a9278d72cff3db0a7a5afe6fd7720cfd2916",
      "fcf1da35791ff4452cf0c633ee9d9197954ec02c35af849e3ca2442157c9f14e",
      "c27e8f4600af2a41707c71f51d338df791e919b1e4a3ea53ccf7b63f7b1140c3",
      "218bc75b3bc83675e1c5ac76b0d9d44c0d1baab6f05098e38d6ebaad0ab5d3c3",
      "61618c69e9d26f4c8ee39e4c215804e2fb01846fee718016ed2589168e839d21",
      "ec76a20799cf5dc50841b1fa4588f4f8c975d7aec7a1c669296ff821d8378f7f",
      "f55d5d12107b371efb4650fb6b8880811f7867621b8c1c1a0168a392cc7b542c",
      "6c9890682b94dee9cd45643c378df78c64e3f7a7160f8f0de73c5360c4b3ecd8",
      "9e1c5239e937026b57b8f931187d6dc4b555892ea200cfe4ab95f0ae94f7cde6",
      "0aa45be01f9e161002f8e22c79467775279949e14530c2505587ad00b6ddf0cb",
      "d2e3dd2bdd2907959ef35a5aeb905682388540a0f77810a8d108cd9026164f3b",
      "33a8e0b809ce2532ae94d561f2e16def904fa2e7b99bd3f1707d95a1148000a1",
      "7c9f51793bca6ffb713d0a918edaa60557184cbbc85f535743926baabe5db81f",
      "fa58391e7c0d394d317903270df6e518b34770c62a38e6697621f88cdcdfb5fd",
      "b668387b2d03e4a4d0ef642d0ebe9539737f65cd1815b7e4ba80f5b13b0d9143",
      "87609936484f5c7dc888d7a67f416d27d33ed73a6827ebb0585729bc8ba6f0eb",
      "1cbbe778d52946eee72cdbbe4e237717de928bfd6c8a9acbbb56b7a473823fac"
    ],
    "index": 4355416
  },
  {
    "root": "6cc6e544755064dc6f1e9a7d3eece2edf1593734671ede912a8089e62b38c766",
    "value": "0000000000000000000000000000000000000000000000000000000000000000",
    "siblings": [
      "0000000000000000000000000000000000000000000000000000000000000000",
      "c71603f33a1144ca7953db0ab48808f4c4055e3364a246c33c18a9786cb0b359",
      "2196fc41328ae503de8f9ad762a30af28d85581b9901b2cfb61a4ad1aaf14fcc",
      "67703a0cc73ca54246fb94bfe956c05f9a247cc59da2de6461e00af7295ce05a",
      "f522eaa0af88a040167d7cf3bf854d278cc1b30d2e2c09475154921a06462644",
      "d0053597686f6672b77e23f0fc59019786ac9b34bd97d439e9e6b5c8d15b61ae",
      "49561260080d30c3dda8f741c47dfb105a1d2a648eee8f0325225f1a5d49614a",
      "b768e4fc8b0b79f516c9da6ea83aa4b13c9a42c646c4c1f9e979ed3ee20855e3",
      "2bd367124a2989b3d31bd45195f9a9278d72cff3db0a7a5afe6fd7720cfd2916",
      "fcf1da35791ff4452cf0c633ee9d9197954ec02c35af849e3ca2442157c9f14e",
      "c27e8f4600af2a41707c71f51d338df791e919b1e4a3ea53ccf7b63f7b1140c3",
      "218bc75b3bc83675e1c5ac76b0d9d44c0d1baab6f05098e38d6ebaad0ab5d3c3",
      "61618c69e9d26f4c8ee39e4c215804e2fb01846fee718016ed2589168e839d21",
      "ec76a20799cf5dc50841b1fa4588f4f8c975d7aec7a1c669296ff821d8378f7f",
      "f55d5d12107b371efb4650fb6b8880811f7867621b8c1c1a0168a392cc7b542c",
      "6c9890682b94dee9cd45643c378df78c64e3f7a7160f8f0de73c5360c4b3ecd8",
      "9e1c5239e937026b57b8f931187d6dc4b555892ea200cfe4ab95f0ae94f7cde6",
      "0aa45be01f9e161002f8e22c79467775279949e14530c2505587ad00b6ddf0cb",
      "d2e3dd2bdd2907959ef35a5aeb905682388540a0f77810a8d108cd9026164f3b",
      "33a8e0b809ce2532ae94d561f2e16def904fa2e7b99bd3f1707d95a1148000a1",
      "7c9f51793bca6ffb713d0a918edaa60557184cbbc85f535743926baabe5db81f",
      "8835403210e865f4cf7256fd0cdf9e255f76d890212252906349e3321d982af9",
      "015a31e22bd615e2ef1a21e852f09690b05c08b2e25f43f759a4554f17635c89",
      "a1a5f8d24291c9f2fddf6ad4b7335957d56db4f91cb3c0e4eee03a5b39e72967",
      "e04c7e07aa911947f266241dba9a3c11f499eee71036019279b79798b964ff15"
    ],
    "index": 25344999
  },
  {
    "root": "d24ff565c461eab65d77fb7e9afd67e168ecfb0a4c2f5ca22e863dd1dee1ba11",
    "value": "8b825a485d63a4a22e592c5d76d4f0d4b63469633bfbc0e9cb97308d10df5240",
    "siblings": [
      "0000000000000000000000000000000000000000000000000000000000000000",
      "c71603f33a1144ca7953db0ab48808f4c4055e3364a246c33c18a9786cb0b359",
      "2196fc41328ae503de8f9ad762a30af28d85581b9901b2cfb61a4ad1aaf14fcc",
      "67703a0cc73ca54246fb94bfe956c05f9a247cc59da2de6461e00af7295ce05a",
      "f522eaa0af88a040167d7cf3bf854d278cc1b30d2e2c09475154921a06462644",
      "d0053597686f6672b77e23f0fc59019786ac9b34bd97d439e9e6b5c8d15b61ae",
      "49561260080d30c3dda8f741c47dfb105a1d2a648eee8f0325225f1a5d49614a",
      "b768e4fc8b0b79f516c9da6ea83aa4b13c9a42c646c4c1f9e979ed3ee20855e3",
      "2bd367124a2989b3d31bd45195f9a9278d72cff3db0a7a5afe6fd7720cfd2916",
      "fcf1da35791ff4452cf0c633ee9d9197954ec02c35af849e3ca2442157c9f14e",
      "c27e8f4600af2a41707c71f51d338df791e919b1e4a3ea53ccf7b63f7b1140c3",
      "218bc75b3bc83675e1c5ac76b0d9d44c0d1baab6f05098e38d6ebaad0ab5d3c3",
      "61618c69e9d26f4c8ee39e4c215804e2fb01846fee718016ed2589168e839d21",
      "ec76a20799cf5dc50841b1fa4588f4f8c975d7aec7a1c669296ff821d8378f7f",
      "f55d5d12107b371efb4650fb6b8880811f7867621b8c1c1a0168a392cc7b542c",
      "6c9890682b94dee9cd45643c378df78c64e3f7a7160f8f0de73c5360c4b3ecd8",
      "9e1c5239e937026b57b8f931187d6dc4b555892ea200cfe4ab95f0ae94f7cde6",
      "0aa45be01f9e161002f8e22c79467775279949e14530c2505587ad00b6ddf0cb",
      "d2e3dd2bdd2907959ef35a5aeb905682388540a0f77810a8d108cd9026164f3b",
      "33a8e0b809ce2532ae94d561f2e16def904fa2e7b99bd3f1707d95a1148000a1",
      "7c9f51793bca6ffb713d0a918edaa60557184cbbc85f535743926baabe5db81f",
      "8835403210e865f4cf7256fd0cdf9e255f76d890212252906349e3321d982af9",
      "015a31e22bd615e2ef1a21e852f09690b05c08b2e25f43f759a4554f17635c89",
      "a1a5f8d24291c9f2fddf6ad4b7335957d56db4f91cb3c0e4eee03a5b39e72967",
      "e04c7e07aa911947f266241dba9a3c11f499eee71036019279b79798b964ff15"
    ],
    "index": 25344999
  },
  {
    "root": "985e78d9c2bd0451a551442fd284bf6961e2028f1f7010613670ee9f4ac83fe3",
    "value": "0000000000000000000000000000000000000000000000000000000000000000",
    "siblings": [
      "0000000000000000000000000000000000000000000000000000000000000000",
      "c71603f33a1144ca7953db0ab48808f4c4055e3364a246c33c18a9786cb0b359",
      "2196fc41328ae503de8f9ad762a30af28d85581b9901b2cfb61a4ad1aaf14fcc",
      "67703a0cc73ca54246fb94bfe956c05f9a247cc59da2de6461e00af7295ce05a",
      "f522eaa0af88a040167d7cf3bf854d278cc1b30d2e2c09475154921a06462644",
      "d0053597686f6672b77e23f0fc59019786ac9b34bd97d439e9e6b5c8d15b61ae",
      "49561260080d30c3dda8f741c47dfb105a1d2a648eee8f0325225f1a5d49614a",
      "b768e4fc8b0b79f516c9da6ea83aa4b13c9a42c646c4c1f9e979ed3ee20855e3",
      "2bd367124a2989b3d31bd45195f9a9278d72cff3db0a7a5afe6fd7720cfd2916",
      "fcf1da35791ff4452cf0c633ee9d9197954ec02c35af849e3ca2442157c9f14e",
      "c27e8f4600af2a41707c71f51d338df791e919b1e4a3ea53ccf7b63f7b1140c3",
      "218bc75b3bc83675e1c5ac76b0d9d44c0d1baab6f05098e38d6ebaad0ab5d3c3",
      "61618c69e9d26f4c8ee39e4c215804e2fb01846fee718016ed2589168e839d21",
      "ec76a20799cf5dc50841b1fa4588f4f8c975d7aec7a1c669296ff821d8378f7f",
      "f55d5d12107b371efb4650fb6b8880811f7867621b8c1c1a0168a392cc7b542c",
      "6c9890682b94dee9cd45643c378df78c64e3f7a7160f8f0de73c5360c4b3ecd8",
      "9e1c5239e937026b57b8f931187d6dc4b555892ea200cfe4ab95f0ae94f7cde6",
      "0aa45be01f9e161002f8e22c79467775279949e14530c2505587ad00b6ddf0cb",
      "d2e3dd2bdd2907959ef35a5aeb905682388540a0f77810a8d108cd9026164f3b",
      "33a8e0b809ce2532ae94d561f2e16def904fa2e7b99bd3f1707d95a1148000a1",
      "7c9f51793bca6ffb713d0a918edaa60557184cbbc85f535743926baabe5db81f",
      "3f07be6f7c4b594befaef804ca27f09a1889aea85c071ba00a4a521638645349",
      "c2815eb3673cb2e1d41c1e2ef3c94f13c254c7768f8ca27f440a0ed0b0bbbd1f",
      "0a242b3ea6fc2e0dd7cb83ec004cee1441e296581b0b7eb32d59b54687769967",
      "7574d03cffff25369633c854ddb5a9b34031495aab6ddb47891d77bd91fb7b89"
    ],
    "index": 14436111
  },
  {
    "root": "813d7cf3a5bf573e197d2e0160091506f00ac3844c58183f4dc366d97a18248c",
    "value": "e5d7f66753a98908f7f7e29e297eb9e44ee5b0dbb3229a55a915106348fbe1eb",
    "siblings": [
      "0000000000000000000000000000000000000000000000000000000000000000",
      "c71603f33a1144ca7953db0ab48808f4c4055e3364a246c33c18a9786cb0b359",
      "2196fc41328ae503de8f9ad762a30af28d85581b9901b2cfb61a4ad1aaf14fcc",
      "67703a0cc73ca54246fb94bfe956c05f9a247cc59da2de6461e00af7295ce05a",
      "f522eaa0af88a040167d7cf3bf854d278cc1b30d2e2c09475154921a06462644",
      "d0053597686f6672b77e23f0fc59019786ac9b34bd97d439e9e6b5c8d15b61ae",
      "49561260080d30c3dda8f741c47dfb105a1d2a648eee8f0325225f1a5d49614a",
      "b768e4fc8b0b79f516c9da6ea83aa4b13c9a42c646c4c1f9e979ed3ee20855e3",
      "2bd367124a2989b3d31bd45195f9a9278d72cff3db0a7a5afe6fd7720cfd2916",
      "fcf1da35791ff4452cf0c633ee9d9197954ec02c35af849e3ca2442157c9f14e",
      "c27e8f4600af2a41707c71f51d338df791e919b1e4a3ea53ccf7b63f7b1140c3",
      "218bc75b3bc83675e1c5ac76b0d9d44c0d1baab6f05098e38d6ebaad0ab5d3c3",
      "61618c69e9d26f4c8ee39e4c215804e2fb01846fee718016ed2589168e839d21",
      "ec76a20799cf5dc50841b1fa4588f4f8c975d7aec7a1c669296ff821d8378f7f",
      "f55d5d12107b371efb4650fb6b8880811f7867621b8c1c1a0168a392cc7b542c",
      "6c9890682b94dee9cd45643c378df78c64e3f7a7160f8f0de73c5360c4b3ecd8",
      "9e1c5239e937026b57b8f931187d6dc4b555892ea200cfe4ab95f0ae94f7cde6",
      "0aa45be01f9e161002f8e22c79467775279949e14530c2505587ad00b6ddf0cb",
      "d2e3dd2bdd2907959ef35a5aeb905682388540a0f77810a8d108cd9026164f3b",
      "33a8e0b809ce2532ae94d561f2e16def904fa2e7b99bd3f1707d95a1148000a1",
      "7c9f51793bca6ffb713d0a918edaa60557184cbbc85f535743926baabe5db81f",
      "3f07be6f7c4b594befaef804ca27f09a1889aea85c071ba00a4a521638645349",
      "c2815eb3673cb2e1d41c1e2ef3c94f13c254c7768f8ca27f440a0ed0b0bbbd1f",
      "0a242b3ea6fc2e0dd7cb83ec004cee1441e296581b0b7eb32d59b54687769967",
      "7574d03cffff25369633c854ddb5a9b34031495aab6ddb47891d77bd91fb7b89"
    ],
    "index": 14436111
  },
  {
    "root": "3595b7ae58983c72aa9aef7e7bebbf7a05ec395b1e32708be2074b613eb30459",
    "value": "0000000000000000000000000000000000000000000000000000000000000000",
    "siblings": [
      "0000000000000000000000000000000000000000000000000000000000000000",
      "c71603f33a1144ca7953db0ab48808f4c4055e3364a246c33c18a9786cb0b359",
      "2196fc41328ae503de8f9ad762a30af28d85581b9901b2cfb61a4ad1aaf14fcc",
      "67703a0cc73ca54246fb94bfe956c05f9a247cc59da2de6461e00af7295ce05a",
      "f522eaa0af88a040167d7cf3bf854d278cc1b30d2e2c09475154921a06462644",
      "d0053597686f6672b77e23f0fc59019786ac9b34bd97d439e9e6b5c8d15b61ae",
      "49561260080d30c3dda8f741c47dfb105a1d2a648eee8f0325225f1a5d49614a",
      "b768e4fc8b0b79f516c9da6ea83aa4b13c9a42c646c4c1f9e979ed3ee20855e3",
      "2bd367124a2989b3d31bd45195f9a9278d72cff3db0a7a5afe6fd7720cfd2916",
      "fcf1da35791ff4452cf0c633ee9d9197954ec02c35af849e3ca2442157c9f14e",
      "c27e8f4600af2a41707c71f51d338df791e919b1e4a3ea53ccf7b63f7b1140c3",
      "218bc75b3bc83675e1c5ac76b0d9d44c0d1baab6f05098e38d6ebaad0ab5d3c3",
      "61618c69e9d26f4c8ee39e4c215804e2fb01846fee718016ed2589168e839d21",
      "ec76a20799cf5dc50841b1fa4588f4f8c975d7aec7a1c669296ff821d8378f7f",
      "f55d5d12107b371efb4650fb6b8880811f7867621b8c1c1a0168a392cc7b542c",
      "6c9890682b94dee9cd45643c378df78c64e3f7a7160f8f0de73c5360c4b3ecd8",
      "9e1c5239e937026b57b8f931187d6dc4b555892ea200cfe4ab95f0ae94f7cde6",
      "0aa45be01f9e161002f8e22c79467775279949e14530c2505587ad00b6ddf0cb",
      "d2e3dd2bdd2907959ef35a5aeb905682388540a0f77810a8d108cd9026164f3b",
      "33a8e0b809ce2532ae94d561f2e16def904fa2e7b99bd3f1707d95a1148000a1",
      "28c309552092a2ffbd5505c249663ca7055abc5d9be849e5c28d4046313287e8",
      "3cc8ca670a0948d2de2c098e7a9cea777cb894cc55021a280b2b030d9726dac1",
      "b668387b2d03e4a4d0ef642d0ebe9539737f65cd1815b7e4ba80f5b13b0d9143",
      "4d23502c0c8192101631083dad4c1d183b5ca73160820801268a42c2cbdf5c72",
      "d9b7d13ac7149f974e56548505e64a6ba21a641ba4f7bd0df1665b6823fa3d9b"
    ],
    "index": 6265303
  },
  {
    "root": "8a8856a4d0c268a8511438c2f2b4fc5e0479bfc1ce680bb2ac4183d8eda5849d",
    "value": "e620d8cecf0faf77e1da54f45f3b437f5dc931012ff6c25f650eb4d4f08c1239",
    "siblings": [
      "0000000000000000000000000000000000000000000000000000000000000000",
      "c71603f33a1144ca7953db0ab48808f4c4055e3364a246c33c18a9786cb0b359",
      "2196fc41328ae503de8f9ad762a30af28d85581b9901b2cfb61a4ad1aaf14fcc",
      "67703a0cc73ca54246fb94bfe956c05f9a247cc59da2de6461e00af7295ce05a",
      "f522eaa0af88a040167d7cf3bf854d278cc1b30d2e2c09475154921a06462644",
      "d0053597686f6672b77e23f0fc59019786ac9b34bd97d439e9e6b5c8d15b61ae",
      "49561260080d30c3dda8f741c47dfb105a1d2a648eee8f0325225f1a5d49614a",
      "b768e4fc8b0b79f516c9da6ea83aa4b13c9a42c646c4c1f9e979ed3ee20855e3",
      "2bd367124a2989b3d31bd45195f9a9278d72cff3db0a7a5afe6fd7720cfd2916",
      "fcf1da35791ff4452cf0c633ee9d9197954ec02c35af849e3ca2442157c9f14e",
      "c27e8f4600af2a41707c71f51d338df791e919b1e4a3ea53ccf7b63f7b1140c3",
      "218bc75b3bc83675e1c5ac76b0d9d44c0d1baab6f05098e38d6ebaad0ab5d3c3",
      "61618c69e9d26f4c8ee39e4c215804e2fb01846fee718016ed2589168e839d21",
      "ec76a20799cf5dc50841b1fa4588f4f8c975d7aec7a1c669296ff821d8378f7f",
      "f55d5d12107b371efb4650fb6b8880811f7867621b8c1c1a0168a392cc7b542c",
      "6c9890682b94dee9cd45643c378df78c64e3f7a7160f8f0de73c5360c4b3ecd8",
      "9e1c5239e937026b57b8f931187d6dc4b555892ea200cfe4ab95f0ae94f7cde6",
      "0aa45be01f9e161002f8e22c79467775279949e14530c2505587ad00b6ddf0cb",
      "d2e3dd2bdd2907959ef35a5aeb905682388540a0f77810a8d108cd9026164f3b",
      "33a8e0b809ce2532ae94d561f2e16def904fa2e7b99bd3f1707d95a1148000a1",
      "28c309552092a2ffbd5505c249663ca7055abc5d9be849e5c28d4046313287e8",
      "3cc8ca670a0948d2de2c098e7a9cea777cb894cc55021a280b2b030d9726dac1",
      "b668387b2d03e4a4d0ef642d0ebe9539737f65cd1815b7e4ba80f5b13b0d9143",
      "4d23502c0c8192101631083dad4c1d183b5ca73160820801268a42c2cbdf5c72",
      "d9b7d13ac7149f974e56548505e64a6ba21a641ba4f7bd0df1665b6823fa3d9b"
    ],
    "index": 6265303
  },
  {
    "root": "8a8856a4d0c268a8511438c2f2b4fc5e0479bfc1ce680bb2ac4183d8eda5849d",
    "value": "0000000000000000000000000000000000000000000000000000000000000000",
    "siblings": [
      "0000000000000000000000000000000000000000000000000000000000000000",
      "c71603f33a1144ca7953db0ab48808f4c4055e3364a246c33c18a9786cb0b359",
      "2196fc41328ae503de8f9ad762a30af28d85581b9901b2cfb61a4ad1aaf14fcc",
      "67703a0cc73ca54246fb94bfe956c05f9a247cc59da2de6461e00af7295ce05a",
      "f522eaa0af88a040167d7cf3bf854d278cc1b30d2e2c09475154921a06462644",
      "d0053597686f6672b77e23f0fc59019786ac9b34bd97d439e9e6b5c8d15b61ae",
      "49561260080d30c3dda8f741c47dfb105a1d2a648eee8f0325225f1a5d49614a",
      "b768e4fc8b0b79f516c9da6ea83aa4b13c9a42c646c4c1f9e979ed3ee20855e3",
      "2bd367124a2989b3d31bd45195f9a9278d72cff3db0a7a5afe6fd7720cfd2916",
      "fcf1da35791ff4452cf0c633ee9d9197954ec02c35af849e3ca2442157c9f14e",
      "c27e8f4600af2a41707c71f51d338df791e919b1e4a3ea53ccf7b63f7b1140c3",
      "218bc75b3bc83675e1c5ac76b0d9d44c0d1baab6f05098e38d6ebaad0ab5d3c3",
      "61618c69e9d26f4c8ee39e4c215804e2fb01846fee718016ed2589168e839d21",
      "ec76a20799cf5dc50841b1fa4588f4f8c975d7aec7a1c669296ff821d8378f7f",
      "f55d5d12107b371efb4650fb6b8880811f7867621b8c1c1a0168a392cc7b542c",
      "6c9890682b94dee9cd45643c378df78c64e3f7a7160f8f0de73c5360c4b3ecd8",
      "9e1c5239e937026b57b8f931187d6dc4b555892ea200cfe4ab95f0ae94f7cde6",
      "0aa45be01f9e161002f8e22c79467775279949e14530c2505587ad00b6ddf0cb",
      "d2e3dd2bdd2907959ef35a5aeb905682388540a0f77810a8d108cd9026164f3b",
      "7caded180bba5a6f53c1f329fc6495672d5c06014ba3d12d87e0f2aa9341ad01",
      "a80a7535c83bd4e5b62b64eb6a3fc6dffd95fa19865ac4411ec49278f40c9708",
      "3f07be6f7c4b594befaef804ca27f09a1889aea85c071ba00a4a521638645349",
      "c2815eb3673cb2e1d41c1e2ef3c94f13c254c7768f8ca27f440a0ed0b0bbbd1f",
      "8fd0957679d2caaf73f7d4630a11ccb38a0a98ab45f1b7c75dd9afbd6304ef2d",
      "d9b7d13ac7149f974e56548505e64a6ba21a641ba4f7bd0df1665b6823fa3d9b"
    ],
    "index": 14013049
  },
  {
    "root": "5dcda133c568989afdc1635bc1847292632ee6e474ac482d9cec1cdc038afd83",
    "value": "ac68e572b2b637126d020d07b22d13b6da35e108d75d7afcda42b7021f712311",
    "siblings": [
      "0000000000000000000000000000000000000000000000000000000000000000",
      "c71603f33a1144ca7953db0ab48808f4c4055e3364a246c33c18a9786cb0b359",
      "2196fc41328ae503de8f9ad762a30af28d85581b9901b2cfb61a4ad1aaf14fcc",
      "67703a0cc73ca54246fb94bfe956c05f9a247cc59da2de6461e00af7295ce05a",
      "f522eaa0af88a040167d7cf3bf854d278cc1b30d2e2c09475154921a06462644",
      "d0053597686f6672b77e23f0fc59019786ac9b34bd97d439e9e6b5c8d15b61ae",
      "49561260080d30c3dda8f741c47dfb105a1d2a648eee8f0325225f1a5d49614a",
      "b768e4fc8b0b79f516c9da6ea83aa4b13c9a42c646c4c1f9e979ed3ee20855e3",
      "2bd367124a2989b3d31bd45195f9a9278d72cff3db0a7a5afe6fd7720cfd2916",
      "fcf1da35791ff4452cf0c633ee9d9197954ec02c35af849e3ca2442157c9f14e",
      "c27e8f4600af2a41707c71f51d338df791e919b1e4a3ea53ccf7b63f7b1140c3",
      "218bc75b3bc83675e1c5ac76b0d9d44c0d1baab6f05098e38d6ebaad0ab5d3c3",
      "61618c69e9d26f4c8ee39e4c215804e2fb01846fee718016ed2589168e839d21",
      "ec76a20799cf5dc50841b1fa4588f4f8c975d7aec7a1c669296ff821d8378f7f",
      "f55d5d12107b371efb4650fb6b8880811f7867621b8c1c1a0168a392cc7b542c",
      "6c9890682b94dee9cd45643c378df78c64e3f7a7160f8f0de73c5360c4b3ecd8",
      "9e1c5239e937026b57b8f931187d6dc4b555892ea200cfe4ab95f0ae94f7cde6",
      "0aa45be01f9e161002f8e22c79467775279949e14530c2505587ad00b6ddf0cb",
      "d2e3dd2bdd2907959ef35a5aeb905682388540a0f77810a8d108cd9026164f3b",
      "7caded180bba5a6f53c1f329fc6495672d5c06014ba3d12d87e0f2aa9341ad01",
      "a80a7535c83bd4e5b62b64eb6a3fc6dffd95fa19865ac4411ec49278f40c9708",
      "3f07be6f7c4b594befaef804ca27f09a1889aea85c071ba00a4a521638645349",
      "c2815eb3673cb2e1d41c1e2ef3c94f13c254c7768f8ca27f440a0ed0b0bbbd1f",
      "8fd0957679d2caaf73f7d4630a11ccb38a0a98ab45f1b7c75dd9afbd6304ef2d",
      "d9b7d13ac7149f974e56548505e64a6ba21a641ba4f7bd0df1665b6823fa3d9b"
    ],
    "index": 14013049
  },
  {
    "root": "a3e6c50166d80d809d084cd41e13275337b06aa688c4bff3eba796543fd14d68",
    "value": "0000000000000000000000000000000000000000000000000000000000000000",
    "siblings": [
      "0000000000000000000000000000000000000000000000000000000000000000",
      "c71603f33a1144ca7953db0ab48808f4c4055e3364a246c33c18a9786cb0b359",
      "2196fc41328ae503de8f9ad762a30af28d85581b9901b2cfb61a4ad1aaf14fcc",
      "67703a0cc73ca54246fb94bfe956c05f9a247cc59da2de6461e00af7295ce05a",
      "f522eaa0af88a040167d7cf3bf854d278cc1b30d2e2c09475154921a06462644",
      "d0053597686f6672b77e23f0fc59019786ac9b34bd97d439e9e6b5c8d15b61ae",
      "49561260080d30c3dda8f741c47dfb105a1d2a648eee8f0325225f1a5d49614a",
      "b768e4fc8b0b79f516c9da6ea83aa4b13c9a42c646c4c1f9e979ed3ee20855e3",
      "2bd367124a2989b3d31bd45195f9a9278d72cff3db0a7a5afe6fd7720cfd2916",
      "fcf1da35791ff4452cf0c633ee9d9197954ec02c35af849e3ca2442157c9f14e",
      "c27e8f4600af2a41707c71f51d338df791e919b1e4a3ea53ccf7b63f7b1140c3",
      "218bc75b3bc83675e1c5ac76b0d9d44c0d1baab6f05098e38d6ebaad0ab5d3c3",
      "61618c69e9d26f4c8ee39e4c215804e2fb01846fee718016ed2589168e839d21",
      "ec76a20799cf5dc50841b1fa4588f4f8c975d7aec7a1c669296ff821d8378f7f",
      "f55d5d12107b371efb4650fb6b8880811f7867621b8c1c1a0168a392cc7b542c",
      "6c9890682b94dee9cd45643c378df78c64e3f7a7160f8f0de73c5360c4b3ecd8",
      "9e1c5239e937026b57b8f931187d6dc4b555892ea200cfe4ab95f0ae94f7cde6",
      "0aa45be01f9e161002f8e22c79467775279949e14530c2505587ad00b6ddf0cb",
      "d2e3dd2bdd2907959ef35a5aeb905682388540a0f77810a8d108cd9026164f3b",
      "33a8e0b809ce2532ae94d561f2e16def904fa2e7b99bd3f1707d95a1148000a1",
      "7c532cb268b45bb14a652644386a297c15d10f5239240e521eef213a08c1963a",
      "4cd8998b2e482b39b3ec50e7446f162b1bb9ed123f02cdc96f90f30de5382784",
      "a58bd38d4fcb812c0d783175df67c34bb42fa0aca1c57c64b9a91e0f814f0835",
      "573b947295fc96cedc0846e224ccdf739e5ded030b0dae9603378e274781d0a7",
      "2d1278022de326184aeece28ce59228d848b8f00113f37e077ca80f1f023a157"
    ],
    "index": 16175224
  },
  {
    "root": "7c737d2dfa1afb1bf3b13bbaaa44a8727c9c026f2c0d92636b56c9f33170f963",
    "value": "20db5786c4b8e61f1935c822114bfffdd5c9dc6b1af39a070186fb71093d465c",
    "siblings": [
      "0000000000000000000000000000000000000000000000000000000000000000",
      "c71603f33a1144ca7953db0ab48808f4c4055e3364a246c33c18a9786cb0b359",
      "2196fc41328ae503de8f9ad762a30af28d85581b9901b2cfb61a4ad1aaf14fcc",
      "67703a0cc73ca54246fb94bfe956c05f9a247cc59da2de6461e00af7295ce05a",
      "f522eaa0af88a040167d7cf3bf854d278cc1b30d2e2c09475154921a06462644",
      "d0053597686f6672b77e23f0fc59019786ac9b34bd97d439e9e6b5c8d15b61ae",
      "49561260080d30c3dda8f741c47dfb105a1d2a648eee8f0325225f1a5d49614a",
      "b768e4fc8b0b79f516c9da6ea83aa4b13c9a42c646c4c1f9e979ed3ee20855e3",
      "2bd367124a2989b3d31bd45195f9a9278d72cff3db0a7a5afe6fd7720cfd2916",
      "fcf1da35791ff4452cf0c633ee9d9197954ec02c35af849e3ca2442157c9f14e",
      "c27e8f4600af2a41707c71f51d338df791e919b1e4a3ea53ccf7b63f7b1140c3",
      "218bc75b3bc83675e1c5ac76b0d9d44c0d1baab6f05098e38d6ebaad0ab5d3c3",
      "61618c69e9d26f4c8ee39e4c215804e2fb01846fee718016ed2589168e839d21",
      "ec76a20799cf5dc50841b1fa4588f4f8c975d7aec7a1c669296ff821d8378f7f",
      "f55d5d12107b371efb4650fb6b8880811f7867621b8c1c1a0168a392cc7b542c",
      "6c9890682b94dee9cd45643c378df78c64e3f7a7160f8f0de73c5360c4b3ecd8",
      "9e1c5239e937026b57b8f931187d6dc4b555892ea200cfe4ab95f0ae94f7cde6",
      "0aa45be01f9e161002f8e22c79467775279949e14530c2505587ad00b6ddf0cb",
      "d2e3dd2bdd2907959ef35a5aeb905682388540a0f77810a8d108cd9026164f3b",
      "33a8e0b809ce2532ae94d561f2e16def904fa2e7b99bd3f1707d95a1148000a1",
      "7c532cb268b45bb14a652644386a297c15d10f5239240e521eef213a08c1963a",
      "4cd8998b2e482b39b3ec50e7446f162b1bb9ed123f02cdc96f90f30de5382784",
      "a58bd38d4fcb812c0d783175df67c34bb42fa0aca1c57c64b9a91e0f814f0835",
      "573b947295fc96cedc0846e224ccdf739e5ded030b0dae9603378e274781d0a7",
      "2d1278022de326184aeece28ce59228d848b8f00113f37e077ca80f1f023a157"
    ],
    "index": 16175224
  },
  {
    "root": "d79fed6bb3475ad2b6b3ccc19569d7ef10f3468ed0a7313eb762231ff5a21d1e",
    "value": "0000000000000000000000000000000000000000000000000000000000000000",
    "siblings": [
      "0000000000000000000000000000000000000000000000000000000000000000",
      "c71603f33a1144ca7953db0ab48808f4c4055e3364a246c33c18a9786cb0b359",
      "2196fc41328ae503de8f9ad762a30af28d85581b9901b2cfb61a4ad1aaf14fcc",
      "67703a0cc73ca54246fb94bfe956c05f9a247cc59da2de6461e00af7295ce05a",
      "f522eaa0af88a040167d7cf3bf854d278cc1b30d2e2c09475154921a06462644",
      "d0053597686f6672b77e23f0fc59019786ac9b34bd97d439e9e6b5c8d15b61ae",
      "49561260080d30c3dda8f741c47dfb105a1d2a648eee8f0325225f1a5d49614a",
      "b768e4fc8b0b79f516c9da6ea83aa4b13c9a42c646c4c1f9e979ed3ee20855e3",
      "2bd367124a2989b3d31bd45195f9a9278d72cff3db0a7a5afe6fd7720cfd2916",
      "fcf1da35791ff4452cf0c633ee9d9197954ec02c35af849e3ca2442157c9f14e",
      "c27e8f4600af2a41707c71f51d338df791e919b1e4a3ea53ccf7b63f7b1140c3",
      "218bc75b3bc83675e1c5ac76b0d9d44c0d1baab6f05098e38d6ebaad0ab5d3c3",
      "61618c69e9d26f4c8ee39e4c215804e2fb01846fee718016ed2589168e839d21",
      "621bc46a4fefefb93696afe3430dcd0f71734be018c5268fba4dcb4511be1034",
      "bc5055c6e7db90649b33b86d47a38f93361e59bf1f439031e8cace6e328113dd",
      "7ff4f9a4d81ea83b0f046a390c16c0ef634b73b47b532796b662e0c939c2f721",
      "7815dc757596a144fddf0d0f9f270b8e4323d3d226fba7c662e27a8f7f30a538"
    ],
    "index": 42292
  },
  {
    "root": "feee2c06cf4a3fc6cea914f3e2bd5a12f2bd83d8cef9ed307bb24e78684cfaa8",
    "value": "272f84feb724d3b6ad73b8d4bf403e239a9eb242256f58f1f603022a116936db",
    "siblings": [
      "0000000000000000000000000000000000000000000000000000000000000000",
      "c71603f33a1144ca7953db0ab48808f4c4055e3364a246c33c18a9786cb0b359",
      "2196fc41328ae503de8f9ad762a30af28d85581b9901b2cfb61a4ad1aaf14fcc",
      "67703a0cc73ca54246fb94bfe956c05f9a247cc59da2de6461e00af7295ce05a",
      "f522eaa0af88a040167d7cf3bf854d278cc1b30d2e2c09475154921a06462644",
      "d0053597686f6672b77e23f0fc59019786ac9b34bd97d439e9e6b5c8d15b61ae",
      "49561260080d30c3dda8f741c47dfb105a1d2a648eee8f0325225f1a5d49614a",
      "b768e4fc8b0b79f516c9da6ea83aa4b13c9a42c646c4c1f9e979ed3ee20855e3",
      "2bd367124a2989b3d31bd45195f9a9278d72cff3db0a7a5afe6fd7720cfd2916",
      "fcf1da35791ff4452cf0c633ee9d9197954ec02c35af849e3ca2442157c9f14e",
      "c27e8f4600af2a41707c71f51d338df791e919b1e4a3ea53ccf7b63f7b1140c3",
      "218bc75b3bc83675e1c5ac76b0d9d44c0d1baab6f05098e38d6ebaad0ab5d3c3",
      "61618c69e9d26f4c8ee39e4c215804e2fb01846fee718016ed2589168e839d21",
      "621bc46a4fefefb93696afe3430dcd0f71734be018c5268fba4dcb4511be1034",
      "bc5055c6e7db90649b33b86d47a38f93361e59bf1f439031e8cace6e328113dd",
      "7ff4f9a4d81ea83b0f046a390c16c0ef634b73b47b532796b662e0c939c2f721",
      "7815dc757596a144fddf0d0f9f270b8e4323d3d226fba7c662e27a8f7f30a538"
    ],
    "index": 42292
  },
  {
    "root": "e16ab3883fc8d54dafa90c700060c90306cb4767b8cb40ef61b90438a54bc477",
    "value": "0000000000000000000000000000000000000000000000000000000000000000",
    "siblings": [
      "0000000000000000000000000000000000000000000000000000000000000000",
      "c71603f33a1144ca7953db0ab48808f4c4055e3364a246c33c18a9786cb0b359",
      "2196fc41328ae503de8f9ad762a30af28d85581b9901b2cfb61a4ad1aaf14fcc",
      "67703a0cc73ca54246fb94bfe956c05f9a247cc59da2de6461e00af7295ce05a",
      "f522eaa0af88a040167d7cf3bf854d278cc1b30d2e2c09475154921a06462644",
      "d0053597686f6672b77e23f0fc59019786ac9b34bd97d439e9e6b5c8d15b61ae",
      "49561260080d30c3dda8f741c47dfb105a1d2a648eee8f0325225f1a5d49614a",
      "b768e4fc8b0b79f516c9da6ea83aa4b13c9a42c646c4c1f9e979ed3ee20855e3",
      "2bd367124a2989b3d31bd45195f9a9278d72cff3db0a7a5afe6fd7720cfd2916",
      "fcf1da35791ff4452cf0c633ee9d9197954ec02c35af849e3ca2442157c9f14e",
      "c27e8f4600af2a41707c71f51d338df791e919b1e4a3ea53ccf7b63f7b1140c3",
      "019b884ab23fd274137572e92b258d62d6a215fa03b6eba2f14f96a32854a011",
      "61618c69e9d26f4c8ee39e4c215804e2fb01846fee718016ed2589168e839d21",
      "ec76a20799cf5dc50841b1fa4588f4f8c975d7aec7a1c669296ff821d8378f7f",
      "2a5ff15613bc42ec8e935436876eb364b9d8bce6cae7139ff855482d0ca020ec",
      "92c5b7335e6cc2871d92bb7beba262ffcea56f6062c5d1a698480e92b976fb0b",
      "8c0e8a3192de6a9d3d0a9ab284c51fd3d522fd08117d4a1e304f9c748370d52b"
    ],
    "index": 75009
  },
  {
    "root": "409a1fbe53d31b337d39ff7ddacad80ab2cac863b0a1d05744ec98f446ac570b",
    "value": "6324041671e74a1b34c29b2079719f013979f9baee8fc39ffd16687bd095a2f2",
    "siblings": [
      "0000000000000000000000000000000000000000000000000000000000000000",
      "c71603f33a1144ca7953db0ab48808f4c4055e3364a246c33c18a9786cb0b359",
      "2196fc41328ae503de8f9ad762a30af28d85581b9901b2cfb61a4ad1aaf14fcc",
      "67703a0cc73ca54246fb94bfe956c05f9a247cc59da2de6461e00af7295ce05a",
      "f522eaa0af88a040167d7cf3bf854d278cc1b30d2e2c09475154921a06462644",
      "d0053597686f6672b77e23f0fc59019786ac9b34bd97d439e9e6b5c8d15b61ae",
      "49561260080d30c3dda8f741c47dfb105a1d2a648eee8f0325225f1a5d49614a",
      "b768e4fc8b0b79f516c9da6ea83aa4b13c9a42c646c4c1f9e979ed3ee20855e3",
      "2bd367124a2989b3d31bd45195f9a9278d72cff3db0a7a5afe6fd7720cfd2916",
      "fcf1da35791ff4452cf0c633ee9d9197954ec02c35af849e3ca2442157c9f14e",
      "c27e8f4600af2a41707c71f51d338df791e919b1e4a3ea53ccf7b63f7b1140c3",
      "019b884ab23fd274137572e92b258d62d6a215fa03b6eba2f14f96a32854a011",
      "61618c69e9d26f4c8ee39e4c215804e2fb01846fee718016ed2589168e839d21",
      "ec76a20799cf5dc50841b1fa4588f4f8c975d7aec7a1c669296ff821d8378f7f",
      "2a5ff15613bc42ec8e935436876eb364b9d8bce6cae7139ff855482d0ca020ec",
      "92c5b7335e6cc2871d92bb7beba262ffcea56f6062c5d1a698480e92b976fb0b",
      "8c0e8a3192de6a9d3d0a9ab284c51fd3d522fd08117d4a1e304f9c748370d52b"
    ],
    "index": 75009
  }
]   
    "#;

    fn create_mp_circuit_for_proof_a(mp: &MerkleProof<F>) {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let mp_gadget = MerkleProofGadget::add_virtual_to::<PoseidonHash, F, D>(
            &mut builder,
            mp.siblings.len(),
        );

        builder.register_public_inputs(&mp_gadget.root.elements);
        let data = builder.build::<C>();
        let mut pw = PartialWitness::new();
        mp_gadget.set_witness_proof(&mut pw, mp);
        let proof = data.prove(pw).unwrap();
        let pub_inputs = proof.public_inputs.clone();
        assert_eq!(pub_inputs[0..4], mp.root.0.elements);
        assert!(data.verify(proof).is_ok());
    }
    fn create_mp_circuit_for_proof_b(mp: &MerkleProof<F>) {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let root = builder.constant_hash(mp.root.0);
        let index = builder.constant(mp.index);
        let mp_gadget = MerkleProofGadget::add_virtual_to_with_options::<PoseidonHash, F, D>(
            &mut builder,
            mp.siblings.len(),
            OptionalMerkleProofGadget {
                root: Some(root),
                value: None,
                siblings: None,
                index: Some(index),
            },
        );

        builder.register_public_inputs(&mp_gadget.root.elements);
        let data = builder.build::<C>();
        let mut pw = PartialWitness::new();
        mp_gadget.set_witness_proof(&mut pw, mp);
        let proof = data.prove(pw).unwrap();
        let pub_inputs = proof.public_inputs.clone();
        assert_eq!(pub_inputs[0..4], mp.root.0.elements);
        assert!(data.verify(proof).is_ok());
    }

    #[should_panic]
    fn merkle_proof_should_fail_a(mp: &MerkleProof<F>) {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let index = builder.constant(mp.index + F::ONE);
        let root = builder.constant_hash(mp.root.0);
        let mp_gadget = MerkleProofGadget::add_virtual_to_with_options::<PoseidonHash, F, D>(
            &mut builder,
            mp.siblings.len(),
            OptionalMerkleProofGadget {
                root: Some(root),
                value: None,
                siblings: None,
                index: Some(index),
            },
        );

        builder.register_public_inputs(&mp_gadget.root.elements);
        let data = builder.build::<C>();
        let mut pw = PartialWitness::new();
        mp_gadget.set_witness_proof(&mut pw, mp);
        let proof = data.prove(pw).unwrap();
        let pub_inputs = proof.public_inputs.clone();
        assert_eq!(pub_inputs[0..4], mp.root.0.elements);
        assert!(data.verify(proof).is_ok());
    }

    #[should_panic]
    fn merkle_proof_should_fail_b(mp: &MerkleProof<F>) {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let index = builder.constant(mp.index);
        let root = builder.constant_hash(mp.root.0);
        let mp_gadget = MerkleProofGadget::add_virtual_to_with_options::<PoseidonHash, F, D>(
            &mut builder,
            mp.siblings.len(),
            OptionalMerkleProofGadget {
                root: Some(root),
                value: Some(root),
                siblings: None,
                index: Some(index),
            },
        );

        builder.register_public_inputs(&mp_gadget.root.elements);
        let data = builder.build::<C>();
        let mut pw = PartialWitness::new();
        mp_gadget.set_witness_proof(&mut pw, mp);
        let proof = data.prove(pw).unwrap();
        let pub_inputs = proof.public_inputs.clone();
        assert_eq!(pub_inputs[0..4], mp.root.0.elements);
        assert!(data.verify(proof).is_ok());
    }

    #[test]
    fn test_merkle_proof_circuit() {
        let parsed_test_cases =
            serde_json::from_str::<Vec<MerkleProof<F>>>(TEST_CASES_JSON).unwrap();
        for test_case in &parsed_test_cases {
            create_mp_circuit_for_proof_a(test_case);
            create_mp_circuit_for_proof_b(test_case);
        }
    }
    #[test]
    #[should_panic]
    fn test_merkle_proof_circuit_failures() {
        let parsed_test_cases =
            serde_json::from_str::<Vec<MerkleProof<F>>>(TEST_CASES_JSON).unwrap();
        for test_case in &parsed_test_cases {
            merkle_proof_should_fail_a(test_case);
            merkle_proof_should_fail_b(test_case);
        }
    }
}
