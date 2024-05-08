use city_crypto::hash::{
    merkle::core::{DeltaMerkleProof, DeltaMerkleProofBase, DeltaMerkleProofCore},
    qhashout::QHashOut,
    traits::hasher::MerkleZeroHasher,
};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::{target::Target, witness::Witness},
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};
pub const NUM_HASH_OUT_ELEMENTS: usize = 4;
use bitflags::bitflags;

use crate::builder::{
    connect::CircuitBuilderConnectHelpers, hash::core::CircuitBuilderHashCore,
    optional_inputs::CircuitBuilderOptionalInputs,
};

use super::merkle_proof::MerkleProofGadget;

bitflags! {
  #[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
    pub struct DeltaMerkleProofGadgetOptionFlags: u64 {
        const none_value_placeholder = 0;
        const old_root = 0b1;
        const old_value = 0b10;
        const index = 0b100;
        const siblings = 0b1000;
        const new_root = 0b10000;
        const new_value = 0b100000;
    }
}
#[derive(Debug, Clone)]
pub struct DeltaMerkleProofGadget {
    pub old_root: HashOutTarget,
    pub old_value: HashOutTarget,
    pub new_root: HashOutTarget,
    pub new_value: HashOutTarget,
    pub index: Target,
    pub siblings: Vec<HashOutTarget>,
    pub option_flags: DeltaMerkleProofGadgetOptionFlags,
}

#[derive(Debug, Clone)]
pub struct OptionalDeltaMerkleProofGadget {
    pub old_root: Option<HashOutTarget>,
    pub old_value: Option<HashOutTarget>,
    pub new_root: Option<HashOutTarget>,
    pub new_value: Option<HashOutTarget>,
    pub index: Option<Target>,
    pub siblings: Option<Vec<HashOutTarget>>,
}

impl DeltaMerkleProofGadget {
    pub fn add_virtual_to_u8h<
        H: AlgebraicHasher<F>,
        F: RichField + Extendable<D>,
        const D: usize,
    >(
        builder: &mut CircuitBuilder<F, D>,
        height: u8,
    ) -> Self {
        Self::add_virtual_to::<H, F, D>(builder, height as usize)
    }
    pub fn add_virtual_to<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        height: usize,
    ) -> Self {
        let index = builder.add_virtual_target();
        let old_value = builder.add_virtual_hash();
        let new_value = builder.add_virtual_hash();
        let siblings = (0..height)
            .map(|_| builder.add_virtual_hash())
            .collect::<Vec<_>>();
        //builder.range_check(index, height);
        let index_bits = builder.split_le(index, height);

        let old_root = MerkleProofGadget::compute_root_bits::<H, F, D>(
            builder,
            &index_bits,
            old_value,
            &siblings,
        );
        let new_root = MerkleProofGadget::compute_root_bits::<H, F, D>(
            builder,
            &index_bits,
            new_value,
            &siblings,
        );
        Self {
            old_root,
            old_value,
            new_root,
            new_value,
            index,
            siblings,
            option_flags: DeltaMerkleProofGadgetOptionFlags::none_value_placeholder,
        }
    }
    pub fn add_virtual_to_append_only<
        H: MerkleZeroHasher<HashOut<F>> + AlgebraicHasher<F>,
        F: RichField + Extendable<D>,
        const D: usize,
    >(
        builder: &mut CircuitBuilder<F, D>,
        height: usize,
    ) -> Self {
        let index = builder.add_virtual_target();
        let old_value = builder.add_virtual_hash();
        let new_value = builder.add_virtual_hash();
        let siblings = (0..height)
            .map(|_| builder.add_virtual_hash())
            .collect::<Vec<_>>();
        //builder.range_check(index, height);
        let index_bits = builder.split_le(index, height);
        let z_hash_target = builder.constant_hash(HashOut {
            elements: [F::ZERO, F::ZERO, F::ZERO, F::ZERO],
        });
        // ensure that the old value is zero
        builder.connect_hashes(old_value, z_hash_target);

        for i in 0..height {
            let zero_hash_target = builder.constant_hash(H::get_zero_hash(i));
            builder.ensure_hash_not_equal_if(index_bits[i], siblings[i], zero_hash_target);
            builder.connect_hashes_if_false(index_bits[i], siblings[i], zero_hash_target);
        }

        let old_root = MerkleProofGadget::compute_root_bits::<H, F, D>(
            builder,
            &index_bits,
            old_value,
            &siblings,
        );
        let new_root = MerkleProofGadget::compute_root_bits::<H, F, D>(
            builder,
            &index_bits,
            new_value,
            &siblings,
        );
        Self {
            old_root,
            old_value,
            new_root,
            new_value,
            index,
            siblings,
            option_flags: DeltaMerkleProofGadgetOptionFlags::none_value_placeholder,
        }
    }
    pub fn add_virtual_to_push_sparse_list<
        H: MerkleZeroHasher<HashOut<F>> + AlgebraicHasher<F>,
        F: RichField + Extendable<D>,
        const D: usize,
    >(
        builder: &mut CircuitBuilder<F, D>,
        height: usize,
    ) -> Self {
        let index = builder.add_virtual_target();
        let old_value = builder.add_virtual_hash();
        let new_value = builder.add_virtual_hash();
        let siblings = (0..height)
            .map(|_| builder.add_virtual_hash())
            .collect::<Vec<_>>();
        //builder.range_check(index, height);
        let index_bits = builder.split_le(index, height);
        let z_hash_target = builder.constant_hash(HashOut {
            elements: [F::ZERO, F::ZERO, F::ZERO, F::ZERO],
        });
        // ensure that the old value is zero
        builder.connect_hashes(old_value, z_hash_target);

        for i in 0..height {
            let zero_hash_target = builder.constant_hash(H::get_zero_hash(i));
            // we only really need to make sure the the leaves to the right of the tree are 0
            // builder.ensure_hash_not_equal_if(index_bits[i], siblings[i], zero_hash_target);
            builder.connect_hashes_if_false(index_bits[i], siblings[i], zero_hash_target);
        }

        let old_root = MerkleProofGadget::compute_root_bits::<H, F, D>(
            builder,
            &index_bits,
            old_value,
            &siblings,
        );
        let new_root = MerkleProofGadget::compute_root_bits::<H, F, D>(
            builder,
            &index_bits,
            new_value,
            &siblings,
        );
        Self {
            old_root,
            old_value,
            new_root,
            new_value,
            index,
            siblings,
            option_flags: DeltaMerkleProofGadgetOptionFlags::none_value_placeholder,
        }
    }
    pub fn add_virtual_to_pop_right<
        H: MerkleZeroHasher<HashOut<F>> + AlgebraicHasher<F>,
        F: RichField + Extendable<D>,
        const D: usize,
    >(
        builder: &mut CircuitBuilder<F, D>,
        height: usize,
    ) -> Self {
        let index = builder.add_virtual_target();
        let old_value = builder.add_virtual_hash();
        let new_value = builder.add_virtual_hash();
        let siblings = (0..height)
            .map(|_| builder.add_virtual_hash())
            .collect::<Vec<_>>();
        //builder.range_check(index, height);
        let index_bits = builder.split_le(index, height);
        let z_hash_target = builder.constant_hash(HashOut {
            elements: [F::ZERO, F::ZERO, F::ZERO, F::ZERO],
        });

        // ensure that the old value is not a zero
        builder.ensure_hash_not_equal(old_value, z_hash_target);

        // ensure that the new value is zero
        builder.connect_hashes(new_value, z_hash_target);

        for i in 0..height {
            let zero_hash_target = builder.constant_hash(H::get_zero_hash(i));
            builder.ensure_hash_not_equal_if(index_bits[i], siblings[i], zero_hash_target);
            builder.connect_hashes_if_false(index_bits[i], siblings[i], zero_hash_target);
        }

        let old_root = MerkleProofGadget::compute_root_bits::<H, F, D>(
            builder,
            &index_bits,
            old_value,
            &siblings,
        );
        let new_root = MerkleProofGadget::compute_root_bits::<H, F, D>(
            builder,
            &index_bits,
            new_value,
            &siblings,
        );
        Self {
            old_root,
            old_value,
            new_root,
            new_value,
            index,
            siblings,
            option_flags: DeltaMerkleProofGadgetOptionFlags::none_value_placeholder,
        }
    }
    pub fn add_virtual_to_dequeue_left<
        H: MerkleZeroHasher<HashOut<F>> + AlgebraicHasher<F>,
        F: RichField + Extendable<D>,
        const D: usize,
    >(
        builder: &mut CircuitBuilder<F, D>,
        height: usize,
    ) -> Self {
        let index = builder.add_virtual_target();
        let old_value = builder.add_virtual_hash();
        let new_value = builder.add_virtual_hash();
        let siblings = (0..height)
            .map(|_| builder.add_virtual_hash())
            .collect::<Vec<_>>();
        //builder.range_check(index, height);
        let index_bits = builder.split_le(index, height);
        let z_hash_target = builder.constant_hash(HashOut {
            elements: [F::ZERO, F::ZERO, F::ZERO, F::ZERO],
        });

        // ensure that the old value is not a zero
        builder.ensure_hash_not_equal(old_value, z_hash_target);

        // ensure that the new value is zero
        builder.connect_hashes(new_value, z_hash_target);

        for i in 0..height {
            let zero_hash_target = builder.constant_hash(H::get_zero_hash(i));
            // if our path is on the right, then the sibling should be zero
            builder.connect_hashes_if_true(index_bits[i], siblings[i], zero_hash_target);
        }

        let old_root = MerkleProofGadget::compute_root_bits::<H, F, D>(
            builder,
            &index_bits,
            old_value,
            &siblings,
        );
        let new_root = MerkleProofGadget::compute_root_bits::<H, F, D>(
            builder,
            &index_bits,
            new_value,
            &siblings,
        );
        Self {
            old_root,
            old_value,
            new_root,
            new_value,
            index,
            siblings,
            option_flags: DeltaMerkleProofGadgetOptionFlags::none_value_placeholder,
        }
    }
    pub fn add_virtual_to_append_only_skip_left<
        H: MerkleZeroHasher<HashOut<F>> + AlgebraicHasher<F>,
        F: RichField + Extendable<D>,
        const D: usize,
    >(
        builder: &mut CircuitBuilder<F, D>,
        height: usize,
    ) -> Self {
        let index = builder.add_virtual_target();
        let old_value = builder.add_virtual_hash();
        let new_value = builder.add_virtual_hash();
        let siblings = (0..height)
            .map(|_| builder.add_virtual_hash())
            .collect::<Vec<_>>();
        //builder.range_check(index, height);
        let index_bits = builder.split_le(index, height);
        let one = builder.one();
        // only allow updating the right hand node
        builder.connect(index_bits[0].target, one);
        let z_hash_target = builder.constant_hash(HashOut {
            elements: [F::ZERO, F::ZERO, F::ZERO, F::ZERO],
        });
        // ensure that the sibling is zero
        builder.connect_hashes(siblings[0], z_hash_target);
        // ensure that the old value is zero
        builder.connect_hashes(old_value, z_hash_target);

        for i in 1..height {
            let zero_hash_target = builder.constant_hash(H::get_zero_hash(i));
            // if our path is on the right, then the sibling should not be zero
            builder.ensure_hash_not_equal_if(index_bits[i], siblings[i], zero_hash_target);
            // if our path is on the left, then then sibling should be zero
            builder.connect_hashes_if_false(index_bits[i], siblings[i], zero_hash_target);
        }

        let old_root = MerkleProofGadget::compute_root_bits::<H, F, D>(
            builder,
            &index_bits,
            old_value,
            &siblings,
        );
        let new_root = MerkleProofGadget::compute_root_bits::<H, F, D>(
            builder,
            &index_bits,
            new_value,
            &siblings,
        );
        Self {
            old_root,
            old_value,
            new_root,
            new_value,
            index,
            siblings,
            option_flags: DeltaMerkleProofGadgetOptionFlags::none_value_placeholder,
        }
    }
    pub fn add_virtual_to_with_options<
        H: AlgebraicHasher<F>,
        F: RichField + Extendable<D>,
        const D: usize,
    >(
        builder: &mut CircuitBuilder<F, D>,
        height: usize,
        options: OptionalDeltaMerkleProofGadget,
    ) -> Self {
        let mut option_flags: u64 = 0;
        let old_value = builder.add_virtual_hash_if_none_op(
            options.old_value,
            &mut option_flags,
            DeltaMerkleProofGadgetOptionFlags::old_value.bits(),
        );
        let index = builder.add_virtual_target_if_none_op(
            options.index,
            &mut option_flags,
            DeltaMerkleProofGadgetOptionFlags::index.bits(),
        );

        let siblings = builder.add_virtual_hashes_if_none_op(
            options.siblings,
            height,
            &mut option_flags,
            DeltaMerkleProofGadgetOptionFlags::siblings.bits(),
        );
        let new_value = builder.add_virtual_hash_if_none_op(
            options.new_value,
            &mut option_flags,
            DeltaMerkleProofGadgetOptionFlags::new_value.bits(),
        );

        builder.range_check(index, height);
        let index_bits = builder.split_le(index, height);

        let old_root = MerkleProofGadget::compute_root_bits::<H, F, D>(
            builder,
            &index_bits,
            old_value,
            &siblings,
        );
        let new_root = MerkleProofGadget::compute_root_bits::<H, F, D>(
            builder,
            &index_bits,
            new_value,
            &siblings,
        );
        if options.old_root.is_some() {
            builder.connect_hashes(options.old_root.unwrap(), old_root);
        }
        if options.new_root.is_some() {
            builder.connect_hashes(options.new_root.unwrap(), new_root);
        }
        Self {
            old_root,
            old_value,
            new_root,
            new_value,
            index,
            siblings,
            option_flags: DeltaMerkleProofGadgetOptionFlags::from_bits(option_flags).unwrap(),
        }
    }
    pub fn set_witness<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        index: F,
        old_value: QHashOut<F>,
        new_value: QHashOut<F>,
        siblings: &[QHashOut<F>],
    ) {
        if !self
            .option_flags
            .contains(DeltaMerkleProofGadgetOptionFlags::index)
        {
            witness.set_target(self.index, index);
        }
        if !self
            .option_flags
            .contains(DeltaMerkleProofGadgetOptionFlags::old_value)
        {
            witness.set_hash_target(self.old_value, old_value.0);
        }
        if !self
            .option_flags
            .contains(DeltaMerkleProofGadgetOptionFlags::siblings)
        {
            for (i, sibling) in self.siblings.iter().enumerate() {
                witness.set_hash_target(*sibling, siblings[i].0);
            }
        }
        if !self
            .option_flags
            .contains(DeltaMerkleProofGadgetOptionFlags::new_value)
        {
            witness.set_hash_target(self.new_value, new_value.0);
        }
    }

    pub fn set_witness_hash_out<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        index: F,
        old_value: HashOut<F>,
        new_value: HashOut<F>,
        siblings: &[HashOut<F>],
    ) {
        if !self
            .option_flags
            .contains(DeltaMerkleProofGadgetOptionFlags::index)
        {
            witness.set_target(self.index, index);
        }
        if !self
            .option_flags
            .contains(DeltaMerkleProofGadgetOptionFlags::old_value)
        {
            witness.set_hash_target(self.old_value, old_value);
        }
        if !self
            .option_flags
            .contains(DeltaMerkleProofGadgetOptionFlags::siblings)
        {
            for (i, sibling) in self.siblings.iter().enumerate() {
                witness.set_hash_target(*sibling, siblings[i]);
            }
        }
        if !self
            .option_flags
            .contains(DeltaMerkleProofGadgetOptionFlags::new_value)
        {
            witness.set_hash_target(self.new_value, new_value);
        }
    }
    pub fn set_witness_proof<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        input: &DeltaMerkleProof<F>,
    ) {
        self.set_witness(
            witness,
            input.index,
            input.old_value,
            input.new_value,
            &input.siblings,
        );
    }
    pub fn set_witness_base_proof<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        input: &DeltaMerkleProofBase<F>,
    ) {
        self.set_witness(
            witness,
            input.index,
            input.old_value,
            input.new_value,
            &input.siblings,
        );
    }
    pub fn set_witness_core_proof_q<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        input: &DeltaMerkleProofCore<QHashOut<F>>,
    ) {
        self.set_witness(
            witness,
            F::from_noncanonical_u64(input.index),
            input.old_value,
            input.new_value,
            &input.siblings,
        );
    }
    pub fn set_witness_core_proof<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        input: &DeltaMerkleProofCore<HashOut<F>>,
    ) {
        self.set_witness_hash_out(
            witness,
            F::from_noncanonical_u64(input.index),
            input.old_value,
            input.new_value,
            &input.siblings,
        );
    }
}

#[cfg(test)]
mod tests {
    use city_crypto::hash::merkle::core::DeltaMerkleProof;
    use plonky2::field::types::Field;
    use plonky2::hash::poseidon::PoseidonHash;
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

    use crate::hash::merkle::gadgets::delta_merkle_proof::DeltaMerkleProofGadget;

    use super::OptionalDeltaMerkleProofGadget;

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    const TEST_CASES_JSON: &str = r#"
    [
        {
          "index": 0,
          "siblings": [
            "cc68946d68de51deb46b7a38380c329ddcfaaa7b84a8f96b768ec1fe97b9771a",
            "ffcc3ee2bd4e11bd9a31af1d272d4fc100cadb76a3921c1520de2cb0fb70c994"
          ],
          "old_root": "8c371f3671d46ae2d647c5458a37cc48018d743ebc68da578b14fcbf9c159ab6",
          "old_value": "34f349a0300d120380c15b5f94bea19372be9b98b8866b41e53a36091667496b",
          "new_value": "e9e929fab44eb3367b726c3d7ea32b2fa33e86b10921f2c24a9e6b230171ae45",
          "new_root": "872273520f925b8ac0aae1b4fbd9535e350e770c8dbb644468430505df7dd3fc"
        },
        {
          "index": 24,
          "siblings": [
            "c1be0cc0fff0fb610605e81511c417b834b380429818b643d2808cf4d1237d87",
            "c71603f33a1144ca7953db0ab48808f4c4055e3364a246c33c18a9786cb0b359",
            "2196fc41328ae503de8f9ad762a30af28d85581b9901b2cfb61a4ad1aaf14fcc",
            "056b5c6f886d9e0d490f6b804d1a6304512e314fa860b0fbe6c022b6982e5f72",
            "19583a8111f84f54bc1228dae5fb895e1e807fecf0db981468a52396d0a522c3"
          ],
          "old_root": "603973465b060026b18ea03de95851198d55d7a6db27718e0f0fc4b01c02055f",
          "old_value": "1ab447a88032389961ab33ae0f382a389546be195ccd6a4d3e9f450723b6fa5c",
          "new_value": "9e971365b5f6e986fbbc7b8df64ad8a74dba1af278eaa5a4e66e212a99694999",
          "new_root": "ec2ad6c522e3147dbec286a5f554fb98916d5ba4ac13f519d45027c897493a70"
        },
        {
          "index": 5,
          "siblings": [
            "a1003866cf3d629e6202373ae077e375aaa09ea498fe64e783747c00c3ed92f4",
            "c71603f33a1144ca7953db0ab48808f4c4055e3364a246c33c18a9786cb0b359",
            "8d52ba399a7c6c0607f14ea363a86c7ddbb01d51a10e92220efcc0b98e3ae813",
            "b6d9bf395a6ac5a787bdabf9a503404d4774587f24c548fb7add2b4befabcc03",
            "66074a5c274edd66ef7066b8d67785970487096320eb5f1972882af763474b12"
          ],
          "old_root": "ada4a18a8dc4fba44759b482aff560ba07c27120b41bb5cf076a1293fb6c4ec3",
          "old_value": "e754f1baf4a8afe4d00f029fda8998603c3cf5fae8ac88fd8731826246f5512a",
          "new_value": "074486f5dc652eeab1980d4b0c766050c27c9bf961bdc3addf67d50d2548ee41",
          "new_root": "d3d51fb05ec839ed0e196b10b4f938f218326d3fa5253fbb4cbddb6c469d4efb"
        },
        {
          "index": 5,
          "siblings": [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "ccbf796be23810cee16885fde7d7ee35dfc46335739db561ee185f4490c84871",
            "c61e8adc9b80641aa9fb83bd2395208a4db3357489fef545b812b5b28be261e7",
            "abe0d573642c3251818f384b7f72bd88b3088e5191b033f06575a2ee1613fa4a"
          ],
          "old_root": "e7ef71df948d77308a346b736e0575c6013e8e469ab3b2d5d7669f51b922cf70",
          "old_value": "86b9cb185973cec07d9131bd8872f18ba43e7acb1b6a62f4ab61237cb98e954e",
          "new_value": "28c4a86c5a02d68a7f6c13f974b18d16ba868e4232f58d65dd2ea76764c89669",
          "new_root": "bb77149429d164f20b507bdacbce711ec1c81a73bf67867376ce7b2be08abf91"
        },
        {
          "index": 4,
          "siblings": [
            "28c4a86c5a02d68a7f6c13f974b18d16ba868e4232f58d65dd2ea76764c89669",
            "ccbf796be23810cee16885fde7d7ee35dfc46335739db561ee185f4490c84871",
            "b2676cba96d7ccf9c6372d3cdccd592e2959d48b5d7823d0d0575d3d17f76446",
            "2e0aa7bfcf3368a13b39816c86760095fa50f05acb50ad37b53ab25a190c0592"
          ],
          "old_root": "ba0a3d1933494662054b17e44f944cf2a1fc84cfb7ecda34a864899123c9e636",
          "old_value": "0000000000000000000000000000000000000000000000000000000000000000",
          "new_value": "d24d98e8fa73ab9e13e063ee42aae88dcd9468d5ec29c3c45236de300a4510a0",
          "new_root": "197ad572f5dcdfc1a29095691114b512ba644408e71c7a5f1c166a05f4e0bc41"
        },
        {
          "index": 8,
          "siblings": [
            "361ad4684e61adc9f9b5647c74bf1dd50691c6fe1de48c27973e514c9eb667ae",
            "de492a33e2b5f2252b29266c102987ddebd8374268696f9c98bcc0ad29ee5b9f",
            "850501d8cff858fe9fc51dd2decde27b163ed739b235fcf5a21af3887e584f26",
            "5c3677a96d5c21ce08670bd2bda3cef28b8ffb0c3b3d3f8af1deb7c721045cc1"
          ],
          "old_root": "d860ca274d278faf1db95617bd8c1be9356a4d2721bd5011bcaccc05baa8ba6e",
          "old_value": "c4a49a93c9b40b68199c69307f217ec55b046d7ec0ab7fa4886663c2d864bda0",
          "new_value": "5859adba12675a8d1fb9e4078992f54f7c26137e7ae724328843dbf5cc467bef",
          "new_root": "8fb689e858aa2eb5023ea8537ff3e9a99b4dc1b09586ba02b52b293c27c0036a"
        },
        {
          "index": 9,
          "siblings": [
            "5859adba12675a8d1fb9e4078992f54f7c26137e7ae724328843dbf5cc467bef",
            "a174e5d43736335c23fb68a672cb6547fcc0ed891c170b172c2d47e231dea466",
            "ba4bbd3bae48820cab9b4a2373c4b68815c91c1d14a817b530dc90629a0184e3",
            "c64caf2311994fe26807a31669102359dac37267987405a0fe81c37f36a83c0a"
          ],
          "old_root": "8d4be89dc402dcd3ef7063840a59bc76f8162053634dd6f81293d5e607c7d4e7",
          "old_value": "361ad4684e61adc9f9b5647c74bf1dd50691c6fe1de48c27973e514c9eb667ae",
          "new_value": "58415022e6792d2175abc2915036d8fc5e5d220e02a5ae87242ccc9880f1f4b2",
          "new_root": "a3c79f7475cadfea7cc08d9d6df86fe9d5d084356b04924cf445c2fb98cec05b"
        },
      
        {
          "index": 23376084,
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
          "old_root": "136d1e4de0ec40976bbc33f7629585b0d61bd7fc765b146828be4825a134fb10",
          "old_value": "0000000000000000000000000000000000000000000000000000000000000000",
          "new_value": "67ca468ade96685df6f87d07dfe95713c2b0e496d7e132b83432e9e9b27409cc",
          "new_root": "0f2f6f0f022bbf3ca215d3b404c499867ab3494d0130d487949215e0936cbab7"
        },
        {
          "index": 25344999,
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
          "old_root": "6cc6e544755064dc6f1e9a7d3eece2edf1593734671ede912a8089e62b38c766",
          "old_value": "0000000000000000000000000000000000000000000000000000000000000000",
          "new_value": "8b825a485d63a4a22e592c5d76d4f0d4b63469633bfbc0e9cb97308d10df5240",
          "new_root": "d24ff565c461eab65d77fb7e9afd67e168ecfb0a4c2f5ca22e863dd1dee1ba11"
        },
        {
          "index": 1731448120594,
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
            "5793fc6d609c47c365b9470bc3e00cd4f19dece13278be693612ac9d812a8f8c",
            "e0c55886db8e5a00bfa58f8faf71ab1e1f12ae8ff82875c95b3c0f2c8ee070cc",
            "8f3c07c1b1e0b6c9c69aade405671398bf062e3f77dc0b13671c5e28b2f9dc9a",
            "06ff527899c10074411162bf4a7f70b84e6acab68322cba1e9e10aca93469e78",
            "08b8d7b96221d9f59ed49f4906c24becbe646c8d1b68665bf42d09eff74e4b90",
            "e0fd1bfa878b3cd2cc7e2bf5f351da7a2a1963d1913370406b4ae756e5e20763",
            "80faf1e491cd910ae2566bc52d26d7ea099b512bfeff20768a0dd4cf966a4a93",
            "20ca8d0d3b8c55d18b0f02df1c469ca317afad6c010c855f7765a145976afdbc",
            "d65af5933a094e8329332a714327ba72b1e4dac93c0cde8ee479b9bb36c3fc43",
            "8898459110b83c06328274e332fef5dd801222195cdd3607eae16dfae567667f",
            "128e848f6988b2b8335307a5113f75b308990353e58cf52e228985d5d429ba69",
            "c13a45af45b47a5481cf07291ff08e901c5a47cadb1735bb909d85b22b82538b",
            "ac7d82d9ae06ff91d8bde415099dc683356c8a5f50c975fb27c11cf7c22eb6bb",
            "1494c53ff2760f8c3e186f1b3fa11e6180ade1ad5662ca882381c62d9f7d5ab3",
            "86fe2a65d9616c076123e5a9b2b015e152fbbe221dfc41bbd1ff1d3b81d79b3c",
            "7423f98eebf751e64cf3d0793e09cf7c6eb9087fb4cbafb5eb32f839ede65578",
            "254c41ecc66c43443c8f4e9d5f5603b45d684ee21be11bcddf9175d81e0b8629",
            "d591970fb3755a6edd18eb8b916bf380acfa7c2484429da72b9d647d58a164ca"
          ],
          "old_root": "6b212c22c7d28125944145b4bc67e6e8508f1c760f8c975de0874c7c4fe50ed8",
          "old_value": "0000000000000000000000000000000000000000000000000000000000000000",
          "new_value": "7f24ad5cc13a53d928c4a86c5a02d68a7f6c13f974b18d16ba868e4232f58d65",
          "new_root": "d8caa29f7ad1e78cdb0c9ac90111cf895b3033d8ec9d0683dd0b38f3d0886ee4"
        },
        {
          "index": 5398274643086,
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
            "5793fc6d609c47c365b9470bc3e00cd4f19dece13278be693612ac9d812a8f8c",
            "e0c55886db8e5a00bfa58f8faf71ab1e1f12ae8ff82875c95b3c0f2c8ee070cc",
            "8f3c07c1b1e0b6c9c69aade405671398bf062e3f77dc0b13671c5e28b2f9dc9a",
            "06ff527899c10074411162bf4a7f70b84e6acab68322cba1e9e10aca93469e78",
            "08b8d7b96221d9f59ed49f4906c24becbe646c8d1b68665bf42d09eff74e4b90",
            "e0fd1bfa878b3cd2cc7e2bf5f351da7a2a1963d1913370406b4ae756e5e20763",
            "80faf1e491cd910ae2566bc52d26d7ea099b512bfeff20768a0dd4cf966a4a93",
            "20ca8d0d3b8c55d18b0f02df1c469ca317afad6c010c855f7765a145976afdbc",
            "d65af5933a094e8329332a714327ba72b1e4dac93c0cde8ee479b9bb36c3fc43",
            "8898459110b83c06328274e332fef5dd801222195cdd3607eae16dfae567667f",
            "128e848f6988b2b8335307a5113f75b308990353e58cf52e228985d5d429ba69",
            "c13a45af45b47a5481cf07291ff08e901c5a47cadb1735bb909d85b22b82538b",
            "ac7d82d9ae06ff91d8bde415099dc683356c8a5f50c975fb27c11cf7c22eb6bb",
            "1494c53ff2760f8c3e186f1b3fa11e6180ade1ad5662ca882381c62d9f7d5ab3",
            "86fe2a65d9616c076123e5a9b2b015e152fbbe221dfc41bbd1ff1d3b81d79b3c",
            "7423f98eebf751e64cf3d0793e09cf7c6eb9087fb4cbafb5eb32f839ede65578",
            "22955c8cecc2708796d911b0ce33cfaf0f44db86b1078f796610d88e59e8d0a6",
            "813d62114f1cba1f7bc3cfcf06da12bde0c0aa09a4d5bb1055ba56cfd661adb1",
            "402bdf81438b36159d6af206834c2f8c9aa94571dbc3e4d9dbc4c927e2780ece",
            "fef81a6d00dfac60f1fc85da1212d173b8e9ef80da1b4c72d76be8f6293e1805",
            "b7322aa2d521f04bb768e15957712a0b3c496e5841174c236a32a875333b65b8",
            "725a12ed10118157f99069274f87d7b03355a71db3c02ad6082fd7f83a74a108",
            "ef07998b4ce788f05658c905956675ba982397e4f41d2e9ae46d124ee2accef2"
          ],
          "old_root": "b249efc4e65b84d13a97f6593ff93302c2ecbecfd2e3dc6c03badb6e858bf07b",
          "old_value": "0000000000000000000000000000000000000000000000000000000000000000",
          "new_value": "a876752852f7e391fb286a7ce84a474fe2ba6291f1898ad51f5da2c07f264dce",
          "new_root": "3fef128d0c51d4388fe55e10a8a4c18a9ed319aca5c1673760d7cc235b39d29a"
        },
        {
          "index": 14013049,
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
          "old_root": "8a8856a4d0c268a8511438c2f2b4fc5e0479bfc1ce680bb2ac4183d8eda5849d",
          "old_value": "0000000000000000000000000000000000000000000000000000000000000000",
          "new_value": "ac68e572b2b637126d020d07b22d13b6da35e108d75d7afcda42b7021f712311",
          "new_root": "5dcda133c568989afdc1635bc1847292632ee6e474ac482d9cec1cdc038afd83"
        }
      ]      
    "#;

    fn create_dmp_circuit_for_proof_a(dmp: &DeltaMerkleProof<F>) {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let dmp_gadget = DeltaMerkleProofGadget::add_virtual_to::<PoseidonHash, F, D>(
            &mut builder,
            dmp.siblings.len(),
        );
        let old_root = builder.constant_hash(dmp.old_root.0);
        let new_root = builder.constant_hash(dmp.new_root.0);
        builder.connect_hashes(dmp_gadget.old_root, old_root);
        builder.connect_hashes(dmp_gadget.new_root, new_root);

        builder.register_public_inputs(&dmp_gadget.old_root.elements);
        builder.register_public_inputs(&dmp_gadget.new_root.elements);
        let data = builder.build::<C>();
        let mut pw = PartialWitness::new();
        dmp_gadget.set_witness_proof(&mut pw, dmp);
        let proof = data.prove(pw).unwrap();
        let pub_inputs = proof.public_inputs.clone();
        assert_eq!(pub_inputs[0..4], dmp.old_root.0.elements);
        assert_eq!(pub_inputs[4..8], dmp.new_root.0.elements);
        assert!(data.verify(proof).is_ok());
    }
    fn create_dmp_circuit_for_proof_b(dmp: &DeltaMerkleProof<F>) {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let old_root = builder.constant_hash(dmp.old_root.0);
        let new_root = builder.constant_hash(dmp.new_root.0);
        let index = builder.constant(dmp.index);
        let dmp_gadget = DeltaMerkleProofGadget::add_virtual_to_with_options::<PoseidonHash, F, D>(
            &mut builder,
            dmp.siblings.len(),
            OptionalDeltaMerkleProofGadget {
                old_root: Some(old_root),
                new_root: Some(new_root),
                old_value: None,
                new_value: None,
                siblings: None,
                index: Some(index),
            },
        );

        builder.register_public_inputs(&dmp_gadget.old_root.elements);
        builder.register_public_inputs(&dmp_gadget.new_root.elements);
        let data = builder.build::<C>();
        let mut pw = PartialWitness::new();
        dmp_gadget.set_witness_proof(&mut pw, dmp);
        let proof = data.prove(pw).unwrap();
        let pub_inputs = proof.public_inputs.clone();
        assert_eq!(pub_inputs[0..4], dmp.old_root.0.elements);
        assert_eq!(pub_inputs[4..8], dmp.new_root.0.elements);
        assert!(data.verify(proof).is_ok());
    }

    #[should_panic]
    fn delta_merkle_proof_should_fail_a(dmp: &DeltaMerkleProof<F>) {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let old_root = builder.constant_hash(dmp.old_root.0);
        let new_root = builder.constant_hash(dmp.new_root.0);
        let index = builder.constant(dmp.index + F::ONE);
        let dmp_gadget = DeltaMerkleProofGadget::add_virtual_to_with_options::<PoseidonHash, F, D>(
            &mut builder,
            dmp.siblings.len(),
            OptionalDeltaMerkleProofGadget {
                old_root: Some(old_root),
                new_root: Some(new_root),
                old_value: None,
                new_value: None,
                siblings: None,
                index: Some(index),
            },
        );

        builder.register_public_inputs(&dmp_gadget.old_root.elements);
        builder.register_public_inputs(&dmp_gadget.new_root.elements);
        let data = builder.build::<C>();
        let mut pw = PartialWitness::new();
        dmp_gadget.set_witness_proof(&mut pw, dmp);

        data.prove(pw).unwrap();
    }

    #[should_panic]
    fn delta_merkle_proof_should_fail_b(dmp: &DeltaMerkleProof<F>) {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let old_root = builder.constant_hash(dmp.siblings[1].0);
        let new_root = builder.constant_hash(dmp.new_root.0);
        let index = builder.constant(dmp.index);
        let dmp_gadget = DeltaMerkleProofGadget::add_virtual_to_with_options::<PoseidonHash, F, D>(
            &mut builder,
            dmp.siblings.len(),
            OptionalDeltaMerkleProofGadget {
                old_root: Some(old_root),
                new_root: Some(new_root),
                old_value: None,
                new_value: None,
                siblings: None,
                index: Some(index),
            },
        );

        builder.register_public_inputs(&dmp_gadget.old_root.elements);
        builder.register_public_inputs(&dmp_gadget.new_root.elements);
        let data = builder.build::<C>();
        let mut pw = PartialWitness::new();
        dmp_gadget.set_witness_proof(&mut pw, dmp);
        data.prove(pw).unwrap();
    }

    #[test]
    fn test_delta_merkle_proof_circuit() {
        let parsed_test_cases =
            serde_json::from_str::<Vec<DeltaMerkleProof<F>>>(TEST_CASES_JSON).unwrap();
        for test_case in &parsed_test_cases {
            create_dmp_circuit_for_proof_a(test_case);
            create_dmp_circuit_for_proof_b(test_case);
        }
    }
    #[test]
    #[should_panic]
    fn test_delta_merkle_proof_circuit_failures() {
        let parsed_test_cases =
            serde_json::from_str::<Vec<DeltaMerkleProof<F>>>(TEST_CASES_JSON).unwrap();
        for test_case in &parsed_test_cases {
            delta_merkle_proof_should_fail_a(test_case);
            delta_merkle_proof_should_fail_b(test_case);
        }
    }
}
