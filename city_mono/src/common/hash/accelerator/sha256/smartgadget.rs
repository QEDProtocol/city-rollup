use itertools::Itertools;
use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{target::Target, witness::Witness},
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
    timed,
    util::{log2_ceil, timing::TimingTree},
};
use serde::{Deserialize, Serialize};
use starkyx::{
    chip::uint::operations::instruction::{UintInstruction, UintInstructions},
    machine::hash::{sha::sha256::SHA256, HashPureInteger},
};
use starkyx::{
    chip::{
        register::{array::ArrayRegister, bit::BitRegister, element::ElementRegister},
        trace::writer::{data::AirWriterData, AirWriter},
        AirParameters, Chip,
    },
    machine::{
        builder::Builder,
        bytes::{builder::BytesBuilder, proof::ByteStarkProofTarget, stark::ByteStark},
        hash::{
            sha::{algorithm::SHAir, builder::SHABuilder},
            HashInteger,
        },
    },
    math::extension::CubicParameters,
    plonky2::{stark::config::GenericCombinedConfig, Plonky2Air},
};

use core::fmt::Debug;
use starkyx::math::goldilocks::cubic::GoldilocksCubicParameters;

use crate::common::{
    builder::{
        connect::CircuitBuilderConnectHelpers,
        hash::hash256bytes::{
            read_hash256_bytes_target_from_array, CircuitBuilderHash256Bytes, Hash256BytesTarget,
        },
    },
    field_traits::CubicExtendable,
    hash::{accelerator::sha256::utils::get_pad_length_sha256_u32, core::sha256::CoreSha256Hasher},
};
use plonky2::field::goldilocks_field::GoldilocksField;

use super::{
    super::config::HashAcceleratorConfig,
    utils::{
        pad_preimage_virtual_targets_sha256, reconstruct_preimages_sha256_constrain_padding_length,
    },
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Sha256AirParametersGoldilocks;

impl AirParameters for Sha256AirParametersGoldilocks {
    type Field = GoldilocksField;
    type CubicParams = GoldilocksCubicParameters;

    type Instruction = UintInstruction;

    const NUM_FREE_COLUMNS: usize = 418;
    const EXTENDED_COLUMNS: usize = 912;
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct Sha256AirParametersWithCubicStandard<F: RichField, P: CubicParameters<F>>(
    std::marker::PhantomData<(F, P)>,
);

impl<F: RichField, P: CubicParameters<F>> AirParameters
    for Sha256AirParametersWithCubicStandard<F, P>
{
    type Field = F;
    type CubicParams = P;

    type Instruction = UintInstruction;

    const NUM_FREE_COLUMNS: usize = 418;
    const EXTENDED_COLUMNS: usize = 912;
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct Sha256AirParametersStandard<F: RichField + CubicExtendable>(std::marker::PhantomData<F>);

impl<F: RichField + CubicExtendable> AirParameters for Sha256AirParametersStandard<F> {
    type Field = F;
    type CubicParams = F::CubicParams;

    type Instruction = UintInstruction;

    const NUM_FREE_COLUMNS: usize = 418;
    const EXTENDED_COLUMNS: usize = 912;
}

fn swap_endian_u32_bytes_array<T: Copy + Sized>(src: &[T]) -> Vec<T> {
    let mut dst = Vec::with_capacity(src.len());
    for i in (0..src.len()).step_by(4) {
        dst.push(src[i + 3]);
        dst.push(src[i + 2]);
        dst.push(src[i + 1]);
        dst.push(src[i]);
    }
    dst
}

fn swap_endian_u32_bytes_sized_array<T: Copy + Sized + Default + Clone, const S: usize>(
    src: &[T; S],
) -> [T; S] {
    let mut result = src.clone();
    for i in (0..src.len()).step_by(4) {
        result[i] = src[i + 3];
        result[i + 1] = src[i + 2];
        result[i + 2] = src[i + 1];
        result[i + 3] = src[i];
    }
    result
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlannedHash256BytesTarget {
    pub preimage: Vec<Target>,
    pub digest: Hash256BytesTarget,
}

const SHA256_EXTRA_DATA: [u64; 357] = [
    103, 230, 9, 106, 133, 174, 103, 187, 114, 243, 110, 60, 58, 245, 79, 165, 127, 82, 14, 81,
    140, 104, 5, 155, 171, 217, 131, 31, 25, 205, 224, 91, 152, 47, 138, 66, 145, 68, 55, 113, 207,
    251, 192, 181, 165, 219, 181, 233, 91, 194, 86, 57, 241, 17, 241, 89, 164, 130, 63, 146, 213,
    94, 28, 171, 152, 170, 7, 216, 1, 91, 131, 18, 190, 133, 49, 36, 195, 125, 12, 85, 116, 93,
    190, 114, 254, 177, 222, 128, 167, 6, 220, 155, 116, 241, 155, 193, 193, 105, 155, 228, 134,
    71, 190, 239, 198, 157, 193, 15, 204, 161, 12, 36, 111, 44, 233, 45, 170, 132, 116, 74, 220,
    169, 176, 92, 218, 136, 249, 118, 82, 81, 62, 152, 109, 198, 49, 168, 200, 39, 3, 176, 199,
    127, 89, 191, 243, 11, 224, 198, 71, 145, 167, 213, 81, 99, 202, 6, 103, 41, 41, 20, 133, 10,
    183, 39, 56, 33, 27, 46, 252, 109, 44, 77, 19, 13, 56, 83, 84, 115, 10, 101, 187, 10, 106, 118,
    46, 201, 194, 129, 133, 44, 114, 146, 161, 232, 191, 162, 75, 102, 26, 168, 112, 139, 75, 194,
    163, 81, 108, 199, 25, 232, 146, 209, 36, 6, 153, 214, 133, 53, 14, 244, 112, 160, 106, 16, 22,
    193, 164, 25, 8, 108, 55, 30, 76, 119, 72, 39, 181, 188, 176, 52, 179, 12, 28, 57, 74, 170,
    216, 78, 79, 202, 156, 91, 243, 111, 46, 104, 238, 130, 143, 116, 111, 99, 165, 120, 20, 120,
    200, 132, 8, 2, 199, 140, 250, 255, 190, 144, 235, 108, 80, 164, 247, 163, 249, 190, 242, 120,
    113, 198, 1, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1,
    1, 1, 0, 0, 0, 0, 0, 0, 2147483647,
];
#[derive(Clone, Debug)]
pub struct SimpleSha256AcceleratorPlannerGadget {
    pub planned_hashes: Vec<PlannedHash256BytesTarget>,
}
/*
<
        S: SHAir<BytesBuilder<L>, CYCLE_LENGTH>,
        L: AirParameters<Field = C::F>,
        C: 'static + GenericConfig<D>,
        const D: usize,
        const CYCLE_LENGTH: usize,
    > SimpleSha256AcceleratorPlannerGadget<S, L, C, D, CYCLE_LENGTH>
where
    L::Instruction: UintInstructions,
    L::CubicParams: CubicParameters<C::F>,
    Chip<L>: Plonky2Air<C::F, D>,
    S::Integer: PartialEq + Eq + Debug,
    C::Hasher: AlgebraicHasher<C::F>
     */
impl SimpleSha256AcceleratorPlannerGadget {
    pub fn new() -> Self {
        Self {
            planned_hashes: Vec::new(),
        }
    }

    pub fn add_sha256_input<F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        preimage_length: usize,
    ) -> (&[Target], Hash256BytesTarget) {
        let preimage = builder.add_virtual_targets(preimage_length);
        let digest = builder.add_virtual_hash256_bytes_target();

        self.planned_hashes
            .push(PlannedHash256BytesTarget { preimage, digest });

        (&self.planned_hashes.last().unwrap().preimage, digest)
    }

    pub fn sha256<F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        preimage: &[Target],
    ) -> Hash256BytesTarget {
        let (preimage_internal, digest) = self.add_sha256_input(builder, preimage.len());
        builder.connect_vec(preimage, preimage_internal);
        digest
    }
    pub fn finalize<P: CubicParameters<C::F>, C: 'static + GenericConfig<D>, const D: usize>(
        self,
        builder: &mut CircuitBuilder<C::F, D>,
    ) -> SmartSha256AcceleratorGadget<SHA256, Sha256AirParametersWithCubicStandard<C::F, P>, C, D, 64>
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<<C as GenericConfig<D>>::F>,
    {
        SmartSha256AcceleratorGadget::<
            SHA256,
            Sha256AirParametersWithCubicStandard<C::F, P>,
            C,
            D,
            64,
        >::finalize_planner(builder, &self.planned_hashes)
    }
}

impl Default for SimpleSha256AcceleratorPlannerGadget {
    fn default() -> Self {
        Self::new()
    }
}
#[derive(Clone, Debug)]
pub struct SmartSha256AcceleratorGadget<
    S: SHAir<BytesBuilder<L>, CYCLE_LENGTH>,
    L: AirParameters<Field = C::F>,
    C: 'static + GenericConfig<D>,
    const D: usize,
    const CYCLE_LENGTH: usize,
> where
    L::Instruction: UintInstructions,
    L::CubicParams: CubicParameters<C::F>,
    Chip<L>: Plonky2Air<C::F, D>,
    S::Integer: PartialEq + Eq + Debug,
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub acc_config: HashAcceleratorConfig,
    pub digest_targets: Vec<Hash256BytesTarget>,
    pub preimage_targets: Vec<Vec<Target>>,
    padded_chunks_array_registers:
        Vec<ArrayRegister<<S as HashInteger<BytesBuilder<L>>>::IntRegister>>,
    end_bits_array_register: ArrayRegister<BitRegister>,
    digest_indexes: ArrayRegister<ElementRegister>,
    hash_state: Vec<<S as SHAir<BytesBuilder<L>, CYCLE_LENGTH>>::StateVariable>,
    stark: ByteStark<L, GenericCombinedConfig<D, C>, D>,
    stark_proof_target: ByteStarkProofTarget<D>,
    stark_public_inputs: Vec<Target>,
}

impl<
        S: SHAir<BytesBuilder<L>, CYCLE_LENGTH>,
        L: AirParameters<Field = C::F>,
        C: 'static + GenericConfig<D>,
        const D: usize,
        const CYCLE_LENGTH: usize,
    > SmartSha256AcceleratorGadget<S, L, C, D, CYCLE_LENGTH>
where
    L::Instruction: UintInstructions,
    L::CubicParams: CubicParameters<C::F>,
    Chip<L>: Plonky2Air<C::F, D>,
    S::Integer: PartialEq + Eq + Debug,
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub fn finalize_planner(
        builder: &mut CircuitBuilder<C::F, D>,
        planned_hashes: &[PlannedHash256BytesTarget],
    ) -> Self {
        let acc_config = HashAcceleratorConfig::from_preimage_lengths(
            &planned_hashes
                .iter()
                .map(|x| x.preimage.len())
                .collect::<Vec<usize>>(),
        );
        Self::add_virtual_to_internal(builder, acc_config, Some(planned_hashes))
    }
    fn add_virtual_to_internal(
        builder: &mut CircuitBuilder<C::F, D>,
        acc_config: HashAcceleratorConfig,
        planned_hashes: Option<&[PlannedHash256BytesTarget]>,
    ) -> Self {
        let num_messages = acc_config.preimage_lengths.len();

        let padded_lengths = acc_config
            .preimage_lengths
            .iter()
            .map(|preimage_length: &usize| get_pad_length_sha256_u32(*preimage_length))
            .collect::<Vec<usize>>();

        let mut computed_end_bits_targets: Vec<Target> = Vec::new();
        let mut digest_ind_targets: Vec<Target> = Vec::new();

        let num_rounds = padded_lengths
            .iter()
            .map(|x: &usize| {
                let num_chunks = (*x) / 16;
                (0..(num_chunks - 1)).for_each(|_| computed_end_bits_targets.push(builder.zero()));
                digest_ind_targets.push(builder.constant(C::F::from_noncanonical_u64(
                    computed_end_bits_targets.len() as u64,
                )));
                computed_end_bits_targets.push(builder.one());
                num_chunks
            })
            .sum::<usize>();

        let mut bytes_builder = BytesBuilder::<L>::new();

        let padded_chunks = (0..num_rounds)
            .map(|_| bytes_builder.alloc_array_public::<S::IntRegister>(16))
            .collect::<Vec<_>>();
        let end_bits = bytes_builder.alloc_array_public::<BitRegister>(num_rounds);
        let digest_indexes = bytes_builder.alloc_array_public(num_messages);
        let hash_state = bytes_builder.sha::<S, CYCLE_LENGTH>(
            &padded_chunks,
            &end_bits,
            &end_bits,
            digest_indexes,
        );

        let num_rows_degree = log2_ceil(CYCLE_LENGTH * num_rounds);
        let num_rows = 1 << num_rows_degree;
        let stark = bytes_builder.build::<GenericCombinedConfig<D, C>, D>(num_rows);

        let (stark_proof_target, stark_public_inputs) = if planned_hashes.is_some() {
            let planned_hashes = planned_hashes.unwrap();
            let stark_proof_target = stark.add_virtual_proof_target(builder);
            //let public_inputs_test = builder.add_virtual_targets(stark.num_public_inputs());

            let padded_preimage_targets = planned_hashes
                .iter()
                .flat_map(|x| {
                    swap_endian_u32_bytes_array(&pad_preimage_virtual_targets_sha256(
                        builder,
                        &x.preimage,
                    ))
                })
                .collect::<Vec<Target>>();
            let flattened_digest_targets = planned_hashes
                .iter()
                .flat_map(|x| swap_endian_u32_bytes_sized_array::<Target, 32>(&x.digest))
                .collect::<Vec<Target>>();
            let alt_public_inputs_count = stark.num_public_inputs()
                - (padded_preimage_targets.len() + flattened_digest_targets.len());
            let other_stark_proof_public_inputs =
                builder.add_virtual_targets(alt_public_inputs_count);
            let stark_public_inputs = [
                padded_preimage_targets,
                other_stark_proof_public_inputs,
                flattened_digest_targets,
            ]
            .concat();

            //builder.register_public_inputs(&public_inputs_test);
            //let marker = builder.constant(C::F::from_canonical_u32(1337420));
            //builder.register_public_input(marker);
            //builder.register_public_inputs(&stark_public_inputs);

            (stark_proof_target, stark_public_inputs)
        } else {
            stark.add_virtual_proof_with_pis_target(builder)
        };
        //builder.register_public_inputs(&stark_public_inputs);

        stark.verify_circuit(builder, &stark_proof_target, &stark_public_inputs);

        let start_offset = stark_public_inputs.len() - (32 * num_messages);

        let digest_targets: Vec<Hash256BytesTarget> = (0..num_messages)
            .map(|m| {
                swap_endian_u32_bytes_sized_array::<Target, 32>(
                    &read_hash256_bytes_target_from_array(
                        &stark_public_inputs,
                        start_offset + m * 32,
                    ),
                )
            })
            .collect();

        let (preimage_targets, end_bits_start_pos) =
            reconstruct_preimages_sha256_constrain_padding_length(
                builder,
                &stark_public_inputs,
                &acc_config.preimage_lengths,
            );

        (0..computed_end_bits_targets.len()).for_each(|i| {
            builder.connect(
                stark_public_inputs[end_bits_start_pos + i],
                computed_end_bits_targets[i],
            )
        });

        let mut cur_pos = end_bits_start_pos + computed_end_bits_targets.len();
        digest_ind_targets.iter().for_each(|target| {
            builder.connect(stark_public_inputs[cur_pos], *target);
            cur_pos += 1;
        });
        let num_rounds_next_pow_2 = 1u64 << log2_ceil(num_rounds) as u64;
        let num_rounds_next_pow_2_target =
            builder.constant(C::F::from_noncanonical_u64(num_rounds_next_pow_2));
        let num_rounds_next_pow_2_target_plus_1 =
            builder.constant(C::F::from_noncanonical_u64(num_rounds_next_pow_2 + 1));
        builder.connect(
            stark_public_inputs[cur_pos],
            num_rounds_next_pow_2_target_plus_1,
        );
        builder.connect(
            stark_public_inputs[cur_pos + 1],
            num_rounds_next_pow_2_target,
        );
        cur_pos += 2;
        SHA256_EXTRA_DATA.iter().enumerate().for_each(|(i, x)| {
            let constant = builder.constant(C::F::from_noncanonical_u64(*x));
            builder.connect(stark_public_inputs[cur_pos + i], constant);
        });
        cur_pos += SHA256_EXTRA_DATA.len();

        // not sure what the next byte does, seems to be related to the number/size of messages?
        cur_pos += 1;
        let zero = builder.zero();
        let one = builder.one();
        let const_64 = builder.constant(C::F::from_canonical_u32(64));
        builder.connect(stark_public_inputs[cur_pos], one);
        builder.connect(stark_public_inputs[cur_pos + 1], zero);
        builder.connect(stark_public_inputs[cur_pos + 2], const_64);
        builder.connect(stark_public_inputs[cur_pos + 3], zero);
        builder.connect(stark_public_inputs[cur_pos + 4], zero);
        // cur_pos += 5;

        // cur_pos => now at the digests!
        /*
                let extra_data =
                    stark_public_inputs[cur_pos..(stark_public_inputs.len() - 32 * num_messages)].to_vec();
                builder.register_public_inputs(&extra_data);
        */
        Self {
            acc_config,
            padded_chunks_array_registers: padded_chunks,
            end_bits_array_register: end_bits,
            digest_indexes,
            hash_state,
            stark,
            stark_proof_target,
            stark_public_inputs,
            digest_targets,
            preimage_targets,
        }
    }
    pub fn add_virtual_to(
        builder: &mut CircuitBuilder<C::F, D>,
        acc_config: HashAcceleratorConfig,
    ) -> Self {
        Self::add_virtual_to_internal(builder, acc_config, None)
    }
    fn set_witness_prepared<W: Witness<C::F>>(
        &self,
        witness: &mut W,
        expected_digests: Vec<String>,
        padded_chunks_values: Vec<<S as HashPureInteger>::Integer>,
        end_bits_values: Vec<C::F>,
        num_messages: usize,
    ) {
        let mut timing = TimingTree::new("sha256_accelerator", log::Level::Debug);
        assert_eq!(end_bits_values.len() * 16, padded_chunks_values.len());
        let num_rounds = end_bits_values.len();
        assert_eq!(self.end_bits_array_register.len(), num_rounds);
        assert_eq!(self.digest_indexes.len(), num_messages);

        let num_rows_degree = log2_ceil(CYCLE_LENGTH * num_rounds);
        let num_rows = 1 << num_rows_degree;
        // Write trace.
        let mut writer_data = AirWriterData::new(&self.stark.air_data, num_rows);
        let mut writer = writer_data.public_writer();

        let mut current_state = S::INITIAL_HASH;
        let mut hash_iter = self.hash_state.iter();
        let mut digest_indexes_iter = self.digest_indexes.iter();
        for (i, (((message, register), end_bit), end_bit_value)) in padded_chunks_values
            .chunks_exact(16)
            .zip_eq(self.padded_chunks_array_registers.iter())
            .zip_eq(self.end_bits_array_register.iter())
            .zip_eq(end_bits_values.iter())
            .enumerate()
        {
            writer.write_array(register, message.iter().map(|x| S::int_to_field_value(*x)));

            let pre_processed = S::pre_process(message);
            current_state = S::process(current_state, &pre_processed);
            let state = current_state.map(S::int_to_field_value);
            if *end_bit_value == C::F::ONE {
                writer.write(
                    &digest_indexes_iter.next().unwrap(),
                    &C::F::from_canonical_usize(i),
                );
                let h: S::StateVariable = *hash_iter.next().unwrap();
                let array: ArrayRegister<_> = h.into();
                writer.write_array(&array, &state);
                current_state = S::INITIAL_HASH;
            }

            writer.write(&end_bit, end_bit_value);
        }

        timed!(timing, "write input", {
            self.stark.air_data.write_global_instructions(&mut writer);

            for mut chunk in writer_data.chunks(num_rows) {
                for i in 0..num_rows {
                    let mut writer = chunk.window_writer(i);
                    self.stark.air_data.write_trace_instructions(&mut writer);
                }
            }
        });

        // Compare expected digests with the trace values.
        let writer = writer_data.public_writer();
        for (digest, expected) in self.hash_state.iter().zip_eq(expected_digests) {
            let array: ArrayRegister<S::IntRegister> = (*digest).into();
            let digest = writer
                .read_array::<_, 8>(&array)
                .map(|x| S::field_value_to_int(&x));
            let expected_digest = S::decode(expected.as_str());
            assert_eq!(digest, expected_digest);
        }

        let (trace, public) = (writer_data.trace, writer_data.public);

        let proof = timed!(
            timing,
            "generate stark proof",
            self.stark.prove(&trace, &public, &mut timing).unwrap()
        );

        self.stark.verify(proof.clone(), &public).unwrap();
        timing.print();

        witness.set_target_arr(&self.stark_public_inputs, &public);
        self.stark
            .set_proof_target(witness, &self.stark_proof_target, proof);
    }
    pub fn set_witness_preimage_refs<W: Witness<C::F>>(
        &self,
        witness: &mut W,
        preimages: &[&[u8]],
    ) {
        let expected_digests = preimages
            .iter()
            .map(|preimage| CoreSha256Hasher::hash_bytes(*preimage).to_hex_string())
            .collect::<Vec<String>>();
        let mut end_bits_values = Vec::new();
        let mut num_messages = 0;
        let padded_chunks_values = preimages
            .iter()
            .flat_map(|msg| {
                num_messages += 1;
                let padded_msg = S::pad(*msg);
                let num_chunks = padded_msg.len() / 16;
                end_bits_values.extend_from_slice(&vec![C::F::ZERO; num_chunks - 1]);
                end_bits_values.push(C::F::ONE);
                padded_msg
            })
            .collect::<Vec<_>>();
        self.set_witness_prepared(
            witness,
            expected_digests,
            padded_chunks_values,
            end_bits_values,
            num_messages,
        )
    }
    pub fn set_witness<W: Witness<C::F>>(&self, witness: &mut W, preimages: &[Vec<u8>]) {
        let expected_digests = preimages
            .iter()
            .map(|preimage| CoreSha256Hasher::hash_bytes(preimage).to_hex_string())
            .collect::<Vec<String>>();
        let mut end_bits_values = Vec::new();
        let mut num_messages = 0;
        let padded_chunks_values = preimages
            .iter()
            .flat_map(|msg| {
                num_messages += 1;
                let padded_msg = S::pad(msg);
                let num_chunks = padded_msg.len() / 16;
                end_bits_values.extend_from_slice(&vec![C::F::ZERO; num_chunks - 1]);
                end_bits_values.push(C::F::ONE);
                padded_msg
            })
            .collect::<Vec<_>>();
        self.set_witness_prepared(
            witness,
            expected_digests,
            padded_chunks_values,
            end_bits_values,
            num_messages,
        )
    }
}

#[cfg(test)]
mod tests {

    use plonky2::field::types::Field;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    use starkyx::machine::hash::sha::sha256::SHA256;
    use starkyx::math::goldilocks::cubic::GoldilocksCubicParameters;

    use crate::common::builder::connect::CircuitBuilderConnectHelpers;
    use crate::common::builder::hash::hash256bytes::{CircuitBuilderHash256Bytes, WitnessHash256};
    use crate::common::hash::accelerator::config::HashAcceleratorConfig;
    use crate::common::hash::accelerator::sha256::smartgadget::{
        Sha256AirParametersGoldilocks, SimpleSha256AcceleratorPlannerGadget,
        SmartSha256AcceleratorGadget,
    };
    use crate::common::hash::core::sha256::CoreSha256Hasher;
    use plonky2::field::goldilocks_field::GoldilocksField;

    #[test]
    fn test_sha256_planner() {
        env_logger::try_init().unwrap_or_default();
        let preimages = vec![
            hex_literal::hex!("b5339960f9f828391779d69a23c745eceebdce2737c1394a6ec486b50dab56cfedf6db502951337b6e9d9b8ef46bc87790b9471657eed623598db2268948833b2a98b2e59f43ff1c5adc5b6c006f0ab805b233bbf35c737cb88136b041eeb69eeb8e000822278725b3cb376e9a186ef5dca75ed3e30007ccc46f6c91301456ba75fadf9955c21a71b2fb6638cc852eccffb2a45c738b1270ca48b96afa16f8adc216754febb2cdca1dc9f875e92aa8e3b41bef272ff25432cd0e31215edc0b247943bdb1720c18efbbb662c0bcd25ef64a4073ed23cf71c77245d56545436b").to_vec(),
            hex_literal::hex!("ce5269e8d28f30c402124388e876ee0241850f5c4979e919fc8c54b2fa3ad6eded559fd24dca9ffebc9ad0cde86355a1c8d0ca54de0bebcae63b0a38efa6834c9deec874224faae4d941715b60cd1c1026a992a315f1ee76a6ff63999a7980ae1a8f5ca3cc0e790fbb93b93dd7638fd5f614031d1ba6fb5d762361c63b22c60827e42aac5908ab67ec63031969f0c99c09247b105faf237466c2ab4bedb3764f75a601d7a7b3c517bd455fe2cbdadb561f7b90dbe0acedb4de8dcf356952d0f84746cb4281c421644d28956aa097432ed57779cdafd67b8a1d12260741865f5f1d1d29e480df0a27492a033c96679e829a6dbd5ded853f151103625d51709ab7d51ae4f1a1a6fb168ac2230fb6b8e86d7edde7a1721b2102ec4d83076f7290bac5fe62c16e3ed9f76dbb7d2d64651410b84c0ee66b64274f1004108af7d6b6ee41665a166f405c713bf3db1873286110ac86b8fa84ffa280a35200ce0aee38261584bc8233268baf4e3ff56b55ef8dc283d7edd5aae86d0164ecc168a1548db9e80f97af256c8bca9768ca63f4cafafc8a97e56a0d7625ba5fb7d2170cbba185bd27b9ba96281617f8bc3523317ea83dfe1bf424efeeacd7d9530512c0c145e8e5f4700ebd3de999d7a30332794291f4b5787dc2c5bcde4d27d58a10f0ff4d3db89ff70259202aac4a7ad8130cad216a54cf5e5710965c88f745cb904dd7afaa901c8cfbd4a7fe19a970a2aebfac75d3e69c228708444306d612fb8ab47e04b6b2856bc0ee9afa1f845ca4202ea3fa0f175f18677df273b290c04711f5a1456f15fa03046d726b5c3489e5575ba3e4c9807990792590dbc90ba9d41b47c0555d9916b80a9dcee3848a6928bd324deac31527a7c2beac3cf794bd68947937f76edae32edd0699447f853cd9dcfd8bc49b3ad7ffe83f88865a0b0c7a174b8663b2cecc7ca3c60ac06617db0e7a9c10762a3cc25b9383231209b29440fae2a955b91a105026ea6e203237a2cb14cb5ceffd7622db580d96dae28a4cbbbbde3011c05cb5040210b89ebe9ea08b87a77a4b3df2e2374288de20d83088afa94cfd015b2c7e1852847ad5fec7c8c632ae1acfd87099daf59615281c043619bdfe2d0c02fb4c11d069769c06f99d0c475ac24fcad96edbda40257fac45f4832896cb206c359311659e86dca4589ed8c150e4960de211daf424f9defb52c673081083858ffbcd0c236f0a9c25613aa3980844622b39c4f3c79a61a8070f8f47c8d82fd777d7a08eb642f23c4cd038fbd331651821f0f1fe6114cd44150c071a83c85a3e478b1b0dac811328e0dc202252b283fa567e0d960b936054ffa9e8bcd5d7920bb8a16b3f32df54e2c2d5a446b613f384a1eed15129167831adffb10c5fe62a590ab85720d7c15f1f910a93857cfe97254f23d602a636836fb4e417214ae715972b851085bc8ea5ca2847e4beaf55d15776b679f7088e31a575ad92c8c962783bf785ecc2d978aab065d73057e7b278be4ef82d43c431a733c7ae2e075d646ce7e70332833586c54e292340c84df2999449da70a556e3af7179a66ef2303977768afc2121912c3250cbf0523fae4625ed76553e1168b674f95f7912db095c6c018f98eb6c1a3d01e9dd7c427e856ad8146390ef0b5c4369106498a2401d48430c6ffc9e98ffb57504af2bbc8d10edd26ee7a6ff791a61a419da1e6650b7b54acc5df45affb2f9a505fc64ed770e01f79f761d46279948fbaf66a5dd9054e732cc8624362288a1b7e003795a4bffaf13fdcdcfbcffbcae1c6f8918db9c06647b06f1c70b4bf466d705739a2aa9").to_vec(),
            hex_literal::hex!("7552425b88e993188a35d52ae8d9137be5755f400159fb8689bfdd628171982067feac4f697ec36410ea0a7d63b4775ffd768f441d16bcacaf1e70d1209d40a5f9d028e26eaaa643d161db42304edddfb26f9a1221b92379223d48acbdc24c2514ec8c9d8641bf9b84cf1cca285cccd7bc9c78ae767f0eacf762c653bcc38b19a1e0fe2279d14fcdb8159ce076269c400542f160e7508223308cb5cf2764696f05bdcb012430192dc03482ff852e1fb5ea6b9413d96509a56bf5207268e922684bdc7cc765e1872e378667b4dbd3bbdbcc965c3066dfda9806d86c1b1b55fc9f98a5775e3b8ce6af09dde2be3418c6b4a16cde41864c5248a13dc4fce3f38a92a10eb3d2b140ccb38fff9d2186ede5c4bba8c782f12400c72f8dfe768c747402fdc2b57d2be9054c9ad00b6b2833a76235f2cb45c4a8699fe91a1c1eaa84628a39241efef2ead4ee1fababee2b5ee9c8782b50e6410851ad1ee9ad5f7491122f0525bd5becea90987d5457d1dd3bbbe035c1b8c76478a0ff0084cc27cfcf9bc8b283ad327f37fb1b3a3566d20f68e4da8deebdc09880d488a3aae2d8de2b507085165a5b70ff4ac6ca6f2c9d10686299f0e5a4ae5ad24d53228be556734b0555a4d2d3defe5fe02e9393972485b04e46d6b537840653f7b5f4a34e2cd2f0a479317bf8bb838f74efe505ddd9bea49da651c6053f24ce8c01bc906849c916fa8663184ba92f92079330869c989d5684e1c4bde042d07ba07b77fa11503f2042b76f6a229e565de10326a9559dd388a18a90277b8d1315766c4383633b172e0b42b116f60a5e8cc7ef221e7af20897dd011334f61723d5de8f7a8802aa4e376c3edb091465f3ad0fdebee66f3835eb72ea8b1023fe69654a2264bf6b519b83b58294d41707b16993d44fd80c2c7f874b28eac1afda7f1f9a0cf001cd08f75f3849da21418829506e2a4dafca60210517ba06d6e9fdfbbd962dd7a9a95430ebdc8175a2acb3f5b8035a7701a693a2d08134c5f7cf25ca4b2c61e476c626df69a44ee6d23d3940648acfa73e82ed628f84db0bc6f3829c78c84218de523ffd047e87fdc55ec261f0e5503882bb9bb5edc99e3ca0fc4dce5dd2f428c93969685234ccc0cf8c527b76ea628e8c60001d83bc933e1b63864d3182ce418a53c63081812d963fe8349d0631e0f4b27561a9723dc94ed490f814129716c314b211665bd2061b30e72acfbbf85fb836fbf0f366b453325c2d4664b92cffec7e505b6edd71c950d512cc7bacf09ccb9dd79fbe2eadfbb87596335faf62bee787239a167235f5081b4f7b437c3bc2a5de7a85d8c6d2a5c5fbf5a114f329726f157c6c5afe8ac03d74de730daa24973b05998675d12d6050af46ea92f08495ed6ec78d05525bd8e916282d45e8392927b179f3a2c6ec1cf4e5e6e5e2ff1db8513af5adea4158258d93db58b09048c330b1ae9dc72985df161199ad0d8573a1552b6fbeb8e0154d025d771fcdd177eae2f598cfbdcaf2ae76a28dd699672a0c34b7ae3e8fc43a9f564669a598").to_vec(),
            hex_literal::hex!("433deae804377044cf23396191e3005cf3234a122420c73f8868ef402beb793d50da0450c0f1daa618c1530a57caae7e474ca05d8b6e4513e955e363adf5bf3adf3100bf0bbd206425a77be23edba6d436b12782eaa16708e683b5239e3cd76f69a2172ff0f2bc7d9f4f004fc8dc0d6421c73af13677f0103fdfb68e54e7a8822623aee304e9735fea66e7e791dccfaafd4d3ce3076686376b97e0e3f8456fad60c76671ffc72a1de922234335d8a9791fd62cc5d532d7ee79840ee110e232a81ee73f2de6b3a4631f683af8c5f847c248bdb2613216f7efea2f870e970f1c3e368d564bfa42bd7cf30e70b1f8e4795953c1377efffa1ecdea993f6f7b7c489b1d80d89231515f0794b078c1462fef2c77c61797d571ed798a3f765e7789f4e332beb9e9bc13d7a10b7321961984b1bd09322765e73e392d094b47682ab90fc0920afd50a36ef0793ac544c6125f279216a9e481681134eb8783bf11037d94bbc8bba863581cf80feeb5c370cf31fafd087fb99cf653a9f94541552dd4f5e1fa553998ef06512d58da3c18161ec85e8707761cf7b2668073832b235d1f6053069db020184dc1c08bea4ecd084226afbce04444bd37f04e450fc322425d766d22a30ce28af01e5fb08c6e19590da52a2a9d00a869850bacd9b7d40d5cfd84c38c3e5c99f1b567bf09ae5638562d57823414f3ca1136a5ac89b5f93f9d4b1a38c6b11b6914c72fd4b7fe1ea8c342537b4717a1f7be1a1cf1e5250a22d09613aeefc4f156546bae9721c90f57f220525e5821c30260c55ec82406b32852a4ce44b56be1493b2f024fe10f399d28ae32b4ea9fdb0d9fee931054d26664abb93e1c3fc99d261b2755091b279eb4439d34b47f2a10bdfb7b22f92d7025ec091815ab4fb3c82a157603c781df26f40d94c321695c546730e02f918c30ddad805c62c7feebc90e245a25c60b9f184a07c873cc855cc2494c95043bbc3b1772119bd2021b323e1d9c00cbcc8e5354e87c5f4d0942c66fa5ef9ff273bb45eaee14401ce00b4761850776fd0409713bb918bf24a61560042831f7f031536da011cf96c40eaef8b8dea849fdf4751f7375420868f3fc0560789a2f4bf2b466bc6d075445162d306de37790070a01a93c3225a410aa988c3f1531d00c7747df04022a8e6540458b578f00c17a88a505e40ca1eb3ebd0d22301043de2e79724e0afb85ef6c61ef4bbd6220d81cb50102ea5ffd4651b6e8ed53cc08c1498ea6b80e983996a1c841609335b07235c2ed92c2fd2b260e4f7edb71d5b774548bd1739ad0b64a84dbcefbf7e1ae8d4f6f199bcb1e436977951e3d34050f564a262c4810a1cec4d3782b8bc9035b6be5fc1bc6cb9d548b411e17ec852e4f6011d1bee3df39a6ac").to_vec(),
            hex_literal::hex!("c02485c08dbe45a463335222faefc5b439792ebf4748ba2c41e6e3eefe0d4b7be8e4245ccf806dc3e187963b465241889998cc978b627ac711c2914feab3b1491c56ec1d15736ea71a01362884666c1e1714814852b1b8db5f6e1e7adb6cc1f7b11a9d42ca9ae726ed22b8e9df9d4cae0061f6ef483eeb87103fdc9365dbcbed8cf2ef4a223b91b4aeef2ac2970545a734777021c305429282e71a8c28a7ba4c574599ea4d07c34a696e116d3706a48bcdec6afd5aa02a89836d64f8d95a1314f83aea9732258f76367909b9e9cc56068b92ddb1138a91dd7200b62a5ed0164748eb4eb2fa96d7a9ef1a58f1bfa5225a393fcbe4cb43be201e8f4b4e925e02aeb3689eabbe8110d5f1d71fbb0dbc74572c30b500f00007f1e8cb7ea1d1408dc22e5f542a19f251809afc2b55aad968e7b4f9834aab031670dc02371e9d22d19dd92f1d2a8748872f47a1f004e0ddbc0ee4bf4495e0296fc5490014eab42b270cbecebbf9af84cd9471bd11289bb5e676c2a6c9073eb797ef1b25759feee03dc45d518bf8c5a1a67e40dd236fcaf9d7ec7c2b72ad1f31e70b93f5fa577415e7e00b83c52ea75a62b083c33879a339204f04bcb90073a4aa83b02f2cd1d2804448793440b7f3522b32ff8a0a1a6c102612d7154689c0eca5c663a34315258d3c13df1b87284e198fff78eb0394adeaee5f36be039aef438f33481ea93608ecc25331fb9f97a0c6aee86ce4f8bb807d8296702d01f1f75f54246cc8c6caf062d349ab001f6c6a8c3cecbeed646c6941cb277cf5363128a2b82de3e97204dff80ecab05e44f1be4e01d3d20353e52a48e7cb5962415db1a6311f2d69da97465448629bb581eecce9722df3529b70fc5c9fb307c0e0a5ea8c4eb247ee83e29bc5c5e32661d357de921c65fbf876b7ec735d246d55c31c3fdb9d70c971d10ccc7e70febecdb631693c374da113395084aaec067d5b498cc088aa259448c00a7c30275258db7a90c4f96de27b1e497d8e97aeaca6845ecd4432a60fc56e271c1161bd9c96d13fb104bef7fd5c3e36713d5783d39dd87e3fc377b0c2272be7d755e32165b85c5eaf7d54b8282d8cc42111eedb4ee17005ad1aeb8ea7b4e3fab0ef7f1b2f56a66626082d50644070aeb8b19a60dfa4e05d6cd874da9d3b26e09ae3be7d0e97489f0e71b8677992dba8b9cd85da942090e3e869ac921416f3a8445874f3b664d1372d428d09b3611e20da09ea7ebe5782952ac9b4eacac6c9f6959745723e041f9beb9e1e64109d3816556f766ed71a99f9e3c5156517b10efffccfae9565b818b0d0c912f2d8de8e93a8a703a4c280461af35c0c95a0d13902e3a7f1b577e264a2644274645cd2e903a10ce172c22d23c749735eae2ee82fb3f1d8ffc3951e015777ef3a03d213eccc9022e11fbd14430e2fa9eb854a2f6cfca4bb82cbb137f41de6629a2d2b28f4a53c177c458f2e44ec035342585425f90533920191b728aabe5f797bea3129b3bb5d902772340583c79a3f80912a12fcb114f1a293680ff7d4f631a7fa507d35b978310694084d7c04856050bb689e7d329d6075df3f5f626dc4758b25f164dc7c6d7d90ed1fef68a1c779276b657c58a9de694d5bfee4af2615171ce510b5aa24dd26230eff6d936fce82780d3d64904912adf8b11588720a37af8bd08990d1ceae751db04d64089be201f471d6f3c5fa2ea5704d0fe6924215a559729aac4a6390177769c8e751477cd01849aab9ab998f1b3e6f028b26363299db4df4f72fe40ad2d4873ece39ab2e2cad6b5ab9b4c896ec3846657551f070f0d6d40c48cd536d3092c4d10284b7e70d1589bbad4e823ebaad8fca4956bf1ca913891de808a7fcc212279148bb0a81753d29072b746ee63f903cc815807c91b0064d5878be35d52d04f02eb467d392243f2fd053d7b79956400afc983eb54a435e2820e2a1b1f3c92f8d5d4b41110252eb1b0ecca102723e3acbc0c035f76b3f4cc69605577ade3bacaf0c041ee93024e894e9cf7452f3602e998bb65c71b9056c43fb5f3ef6bc71c05d12762d6ed3").to_vec(),
        ];

        let expected_digests = preimages
            .iter()
            .map(|p| CoreSha256Hasher::hash_bytes(p))
            .collect::<Vec<_>>();

        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = GoldilocksField;
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let mut sha256_planner_gadget = SimpleSha256AcceleratorPlannerGadget::new();
        let expected_preimage_targets = preimages
            .iter()
            .map(|p| builder.add_virtual_targets(p.len()))
            .collect::<Vec<_>>();

        let expected_digest_targets = (0..expected_digests.len())
            .map(|_| builder.add_virtual_hash256_bytes_target())
            .collect::<Vec<_>>();
        //builder.register_public_inputs(&expected_preimage_targets.concat());

        //let marker = builder.constant(F::from_canonical_u32(1337420));
        //builder.register_public_input(marker);
        preimages.iter().enumerate().for_each(|(i, p)| {
            let (preimage, digest) = sha256_planner_gadget.add_sha256_input(&mut builder, p.len());
            //builder.register_public_inputs(preimage);
            builder.connect_vec(&expected_preimage_targets[i], preimage);
            builder.connect_hash256_bytes(expected_digest_targets[i], digest);
        });

        let sha256_acc_gadget =
            sha256_planner_gadget.finalize::<GoldilocksCubicParameters, C, D>(&mut builder);
        expected_preimage_targets
            .iter()
            .enumerate()
            .for_each(|(i, expected)| {
                builder.connect_vec(expected, &sha256_acc_gadget.preimage_targets[i])
            });

        expected_digest_targets
            .iter()
            .enumerate()
            .for_each(|(i, expected)| {
                builder.connect_hash256_bytes(*expected, sha256_acc_gadget.digest_targets[i])
            });
        //let num_gates = builder.num_gates();
        let data = builder.build::<C>();

        let start_time = std::time::Instant::now();
        let mut pw = PartialWitness::new();
        expected_digests
            .iter()
            .zip(expected_digest_targets.iter())
            .for_each(|(d, t)| {
                pw.set_hash256_bytes_target(t, &d.0);
            });
        expected_preimage_targets
            .iter()
            .zip(preimages.iter())
            .for_each(|(t, p)| {
                pw.set_target_arr(
                    t,
                    &p.iter()
                        .map(|v| F::from_canonical_u8(*v))
                        .collect::<Vec<F>>(),
                );
            });
        sha256_acc_gadget.set_witness(&mut pw, &preimages);

        let proof = data.prove(pw).unwrap();
        let duration_ms = start_time.elapsed().as_millis();
        println!("public_inputs: {:?}", proof.public_inputs);
        println!("sha256 proved in {}ms", duration_ms);
        assert!(data.verify(proof).is_ok());
    }

    #[test]
    fn test_sha256_acc_gadget_long() {
        env_logger::try_init().unwrap_or_default();
        let preimages = vec![
            hex_literal::hex!("b5339960f9f828391779d69a23c745eceebdce2737c1394a6ec486b50dab56cfedf6db502951337b6e9d9b8ef46bc87790b9471657eed623598db2268948833b2a98b2e59f43ff1c5adc5b6c006f0ab805b233bbf35c737cb88136b041eeb69eeb8e000822278725b3cb376e9a186ef5dca75ed3e30007ccc46f6c91301456ba75fadf9955c21a71b2fb6638cc852eccffb2a45c738b1270ca48b96afa16f8adc216754febb2cdca1dc9f875e92aa8e3b41bef272ff25432cd0e31215edc0b247943bdb1720c18efbbb662c0bcd25ef64a4073ed23cf71c77245d56545436b").to_vec(),
            hex_literal::hex!("ce5269e8d28f30c402124388e876ee0241850f5c4979e919fc8c54b2fa3ad6eded559fd24dca9ffebc9ad0cde86355a1c8d0ca54de0bebcae63b0a38efa6834c9deec874224faae4d941715b60cd1c1026a992a315f1ee76a6ff63999a7980ae1a8f5ca3cc0e790fbb93b93dd7638fd5f614031d1ba6fb5d762361c63b22c60827e42aac5908ab67ec63031969f0c99c09247b105faf237466c2ab4bedb3764f75a601d7a7b3c517bd455fe2cbdadb561f7b90dbe0acedb4de8dcf356952d0f84746cb4281c421644d28956aa097432ed57779cdafd67b8a1d12260741865f5f1d1d29e480df0a27492a033c96679e829a6dbd5ded853f151103625d51709ab7d51ae4f1a1a6fb168ac2230fb6b8e86d7edde7a1721b2102ec4d83076f7290bac5fe62c16e3ed9f76dbb7d2d64651410b84c0ee66b64274f1004108af7d6b6ee41665a166f405c713bf3db1873286110ac86b8fa84ffa280a35200ce0aee38261584bc8233268baf4e3ff56b55ef8dc283d7edd5aae86d0164ecc168a1548db9e80f97af256c8bca9768ca63f4cafafc8a97e56a0d7625ba5fb7d2170cbba185bd27b9ba96281617f8bc3523317ea83dfe1bf424efeeacd7d9530512c0c145e8e5f4700ebd3de999d7a30332794291f4b5787dc2c5bcde4d27d58a10f0ff4d3db89ff70259202aac4a7ad8130cad216a54cf5e5710965c88f745cb904dd7afaa901c8cfbd4a7fe19a970a2aebfac75d3e69c228708444306d612fb8ab47e04b6b2856bc0ee9afa1f845ca4202ea3fa0f175f18677df273b290c04711f5a1456f15fa03046d726b5c3489e5575ba3e4c9807990792590dbc90ba9d41b47c0555d9916b80a9dcee3848a6928bd324deac31527a7c2beac3cf794bd68947937f76edae32edd0699447f853cd9dcfd8bc49b3ad7ffe83f88865a0b0c7a174b8663b2cecc7ca3c60ac06617db0e7a9c10762a3cc25b9383231209b29440fae2a955b91a105026ea6e203237a2cb14cb5ceffd7622db580d96dae28a4cbbbbde3011c05cb5040210b89ebe9ea08b87a77a4b3df2e2374288de20d83088afa94cfd015b2c7e1852847ad5fec7c8c632ae1acfd87099daf59615281c043619bdfe2d0c02fb4c11d069769c06f99d0c475ac24fcad96edbda40257fac45f4832896cb206c359311659e86dca4589ed8c150e4960de211daf424f9defb52c673081083858ffbcd0c236f0a9c25613aa3980844622b39c4f3c79a61a8070f8f47c8d82fd777d7a08eb642f23c4cd038fbd331651821f0f1fe6114cd44150c071a83c85a3e478b1b0dac811328e0dc202252b283fa567e0d960b936054ffa9e8bcd5d7920bb8a16b3f32df54e2c2d5a446b613f384a1eed15129167831adffb10c5fe62a590ab85720d7c15f1f910a93857cfe97254f23d602a636836fb4e417214ae715972b851085bc8ea5ca2847e4beaf55d15776b679f7088e31a575ad92c8c962783bf785ecc2d978aab065d73057e7b278be4ef82d43c431a733c7ae2e075d646ce7e70332833586c54e292340c84df2999449da70a556e3af7179a66ef2303977768afc2121912c3250cbf0523fae4625ed76553e1168b674f95f7912db095c6c018f98eb6c1a3d01e9dd7c427e856ad8146390ef0b5c4369106498a2401d48430c6ffc9e98ffb57504af2bbc8d10edd26ee7a6ff791a61a419da1e6650b7b54acc5df45affb2f9a505fc64ed770e01f79f761d46279948fbaf66a5dd9054e732cc8624362288a1b7e003795a4bffaf13fdcdcfbcffbcae1c6f8918db9c06647b06f1c70b4bf466d705739a2aa9").to_vec(),
            hex_literal::hex!("7552425b88e993188a35d52ae8d9137be5755f400159fb8689bfdd628171982067feac4f697ec36410ea0a7d63b4775ffd768f441d16bcacaf1e70d1209d40a5f9d028e26eaaa643d161db42304edddfb26f9a1221b92379223d48acbdc24c2514ec8c9d8641bf9b84cf1cca285cccd7bc9c78ae767f0eacf762c653bcc38b19a1e0fe2279d14fcdb8159ce076269c400542f160e7508223308cb5cf2764696f05bdcb012430192dc03482ff852e1fb5ea6b9413d96509a56bf5207268e922684bdc7cc765e1872e378667b4dbd3bbdbcc965c3066dfda9806d86c1b1b55fc9f98a5775e3b8ce6af09dde2be3418c6b4a16cde41864c5248a13dc4fce3f38a92a10eb3d2b140ccb38fff9d2186ede5c4bba8c782f12400c72f8dfe768c747402fdc2b57d2be9054c9ad00b6b2833a76235f2cb45c4a8699fe91a1c1eaa84628a39241efef2ead4ee1fababee2b5ee9c8782b50e6410851ad1ee9ad5f7491122f0525bd5becea90987d5457d1dd3bbbe035c1b8c76478a0ff0084cc27cfcf9bc8b283ad327f37fb1b3a3566d20f68e4da8deebdc09880d488a3aae2d8de2b507085165a5b70ff4ac6ca6f2c9d10686299f0e5a4ae5ad24d53228be556734b0555a4d2d3defe5fe02e9393972485b04e46d6b537840653f7b5f4a34e2cd2f0a479317bf8bb838f74efe505ddd9bea49da651c6053f24ce8c01bc906849c916fa8663184ba92f92079330869c989d5684e1c4bde042d07ba07b77fa11503f2042b76f6a229e565de10326a9559dd388a18a90277b8d1315766c4383633b172e0b42b116f60a5e8cc7ef221e7af20897dd011334f61723d5de8f7a8802aa4e376c3edb091465f3ad0fdebee66f3835eb72ea8b1023fe69654a2264bf6b519b83b58294d41707b16993d44fd80c2c7f874b28eac1afda7f1f9a0cf001cd08f75f3849da21418829506e2a4dafca60210517ba06d6e9fdfbbd962dd7a9a95430ebdc8175a2acb3f5b8035a7701a693a2d08134c5f7cf25ca4b2c61e476c626df69a44ee6d23d3940648acfa73e82ed628f84db0bc6f3829c78c84218de523ffd047e87fdc55ec261f0e5503882bb9bb5edc99e3ca0fc4dce5dd2f428c93969685234ccc0cf8c527b76ea628e8c60001d83bc933e1b63864d3182ce418a53c63081812d963fe8349d0631e0f4b27561a9723dc94ed490f814129716c314b211665bd2061b30e72acfbbf85fb836fbf0f366b453325c2d4664b92cffec7e505b6edd71c950d512cc7bacf09ccb9dd79fbe2eadfbb87596335faf62bee787239a167235f5081b4f7b437c3bc2a5de7a85d8c6d2a5c5fbf5a114f329726f157c6c5afe8ac03d74de730daa24973b05998675d12d6050af46ea92f08495ed6ec78d05525bd8e916282d45e8392927b179f3a2c6ec1cf4e5e6e5e2ff1db8513af5adea4158258d93db58b09048c330b1ae9dc72985df161199ad0d8573a1552b6fbeb8e0154d025d771fcdd177eae2f598cfbdcaf2ae76a28dd699672a0c34b7ae3e8fc43a9f564669a598").to_vec(),
            hex_literal::hex!("433deae804377044cf23396191e3005cf3234a122420c73f8868ef402beb793d50da0450c0f1daa618c1530a57caae7e474ca05d8b6e4513e955e363adf5bf3adf3100bf0bbd206425a77be23edba6d436b12782eaa16708e683b5239e3cd76f69a2172ff0f2bc7d9f4f004fc8dc0d6421c73af13677f0103fdfb68e54e7a8822623aee304e9735fea66e7e791dccfaafd4d3ce3076686376b97e0e3f8456fad60c76671ffc72a1de922234335d8a9791fd62cc5d532d7ee79840ee110e232a81ee73f2de6b3a4631f683af8c5f847c248bdb2613216f7efea2f870e970f1c3e368d564bfa42bd7cf30e70b1f8e4795953c1377efffa1ecdea993f6f7b7c489b1d80d89231515f0794b078c1462fef2c77c61797d571ed798a3f765e7789f4e332beb9e9bc13d7a10b7321961984b1bd09322765e73e392d094b47682ab90fc0920afd50a36ef0793ac544c6125f279216a9e481681134eb8783bf11037d94bbc8bba863581cf80feeb5c370cf31fafd087fb99cf653a9f94541552dd4f5e1fa553998ef06512d58da3c18161ec85e8707761cf7b2668073832b235d1f6053069db020184dc1c08bea4ecd084226afbce04444bd37f04e450fc322425d766d22a30ce28af01e5fb08c6e19590da52a2a9d00a869850bacd9b7d40d5cfd84c38c3e5c99f1b567bf09ae5638562d57823414f3ca1136a5ac89b5f93f9d4b1a38c6b11b6914c72fd4b7fe1ea8c342537b4717a1f7be1a1cf1e5250a22d09613aeefc4f156546bae9721c90f57f220525e5821c30260c55ec82406b32852a4ce44b56be1493b2f024fe10f399d28ae32b4ea9fdb0d9fee931054d26664abb93e1c3fc99d261b2755091b279eb4439d34b47f2a10bdfb7b22f92d7025ec091815ab4fb3c82a157603c781df26f40d94c321695c546730e02f918c30ddad805c62c7feebc90e245a25c60b9f184a07c873cc855cc2494c95043bbc3b1772119bd2021b323e1d9c00cbcc8e5354e87c5f4d0942c66fa5ef9ff273bb45eaee14401ce00b4761850776fd0409713bb918bf24a61560042831f7f031536da011cf96c40eaef8b8dea849fdf4751f7375420868f3fc0560789a2f4bf2b466bc6d075445162d306de37790070a01a93c3225a410aa988c3f1531d00c7747df04022a8e6540458b578f00c17a88a505e40ca1eb3ebd0d22301043de2e79724e0afb85ef6c61ef4bbd6220d81cb50102ea5ffd4651b6e8ed53cc08c1498ea6b80e983996a1c841609335b07235c2ed92c2fd2b260e4f7edb71d5b774548bd1739ad0b64a84dbcefbf7e1ae8d4f6f199bcb1e436977951e3d34050f564a262c4810a1cec4d3782b8bc9035b6be5fc1bc6cb9d548b411e17ec852e4f6011d1bee3df39a6ac").to_vec(),
            hex_literal::hex!("c02485c08dbe45a463335222faefc5b439792ebf4748ba2c41e6e3eefe0d4b7be8e4245ccf806dc3e187963b465241889998cc978b627ac711c2914feab3b1491c56ec1d15736ea71a01362884666c1e1714814852b1b8db5f6e1e7adb6cc1f7b11a9d42ca9ae726ed22b8e9df9d4cae0061f6ef483eeb87103fdc9365dbcbed8cf2ef4a223b91b4aeef2ac2970545a734777021c305429282e71a8c28a7ba4c574599ea4d07c34a696e116d3706a48bcdec6afd5aa02a89836d64f8d95a1314f83aea9732258f76367909b9e9cc56068b92ddb1138a91dd7200b62a5ed0164748eb4eb2fa96d7a9ef1a58f1bfa5225a393fcbe4cb43be201e8f4b4e925e02aeb3689eabbe8110d5f1d71fbb0dbc74572c30b500f00007f1e8cb7ea1d1408dc22e5f542a19f251809afc2b55aad968e7b4f9834aab031670dc02371e9d22d19dd92f1d2a8748872f47a1f004e0ddbc0ee4bf4495e0296fc5490014eab42b270cbecebbf9af84cd9471bd11289bb5e676c2a6c9073eb797ef1b25759feee03dc45d518bf8c5a1a67e40dd236fcaf9d7ec7c2b72ad1f31e70b93f5fa577415e7e00b83c52ea75a62b083c33879a339204f04bcb90073a4aa83b02f2cd1d2804448793440b7f3522b32ff8a0a1a6c102612d7154689c0eca5c663a34315258d3c13df1b87284e198fff78eb0394adeaee5f36be039aef438f33481ea93608ecc25331fb9f97a0c6aee86ce4f8bb807d8296702d01f1f75f54246cc8c6caf062d349ab001f6c6a8c3cecbeed646c6941cb277cf5363128a2b82de3e97204dff80ecab05e44f1be4e01d3d20353e52a48e7cb5962415db1a6311f2d69da97465448629bb581eecce9722df3529b70fc5c9fb307c0e0a5ea8c4eb247ee83e29bc5c5e32661d357de921c65fbf876b7ec735d246d55c31c3fdb9d70c971d10ccc7e70febecdb631693c374da113395084aaec067d5b498cc088aa259448c00a7c30275258db7a90c4f96de27b1e497d8e97aeaca6845ecd4432a60fc56e271c1161bd9c96d13fb104bef7fd5c3e36713d5783d39dd87e3fc377b0c2272be7d755e32165b85c5eaf7d54b8282d8cc42111eedb4ee17005ad1aeb8ea7b4e3fab0ef7f1b2f56a66626082d50644070aeb8b19a60dfa4e05d6cd874da9d3b26e09ae3be7d0e97489f0e71b8677992dba8b9cd85da942090e3e869ac921416f3a8445874f3b664d1372d428d09b3611e20da09ea7ebe5782952ac9b4eacac6c9f6959745723e041f9beb9e1e64109d3816556f766ed71a99f9e3c5156517b10efffccfae9565b818b0d0c912f2d8de8e93a8a703a4c280461af35c0c95a0d13902e3a7f1b577e264a2644274645cd2e903a10ce172c22d23c749735eae2ee82fb3f1d8ffc3951e015777ef3a03d213eccc9022e11fbd14430e2fa9eb854a2f6cfca4bb82cbb137f41de6629a2d2b28f4a53c177c458f2e44ec035342585425f90533920191b728aabe5f797bea3129b3bb5d902772340583c79a3f80912a12fcb114f1a293680ff7d4f631a7fa507d35b978310694084d7c04856050bb689e7d329d6075df3f5f626dc4758b25f164dc7c6d7d90ed1fef68a1c779276b657c58a9de694d5bfee4af2615171ce510b5aa24dd26230eff6d936fce82780d3d64904912adf8b11588720a37af8bd08990d1ceae751db04d64089be201f471d6f3c5fa2ea5704d0fe6924215a559729aac4a6390177769c8e751477cd01849aab9ab998f1b3e6f028b26363299db4df4f72fe40ad2d4873ece39ab2e2cad6b5ab9b4c896ec3846657551f070f0d6d40c48cd536d3092c4d10284b7e70d1589bbad4e823ebaad8fca4956bf1ca913891de808a7fcc212279148bb0a81753d29072b746ee63f903cc815807c91b0064d5878be35d52d04f02eb467d392243f2fd053d7b79956400afc983eb54a435e2820e2a1b1f3c92f8d5d4b41110252eb1b0ecca102723e3acbc0c035f76b3f4cc69605577ade3bacaf0c041ee93024e894e9cf7452f3602e998bb65c71b9056c43fb5f3ef6bc71c05d12762d6ed3").to_vec(),
        ];
        let hash_acc_config = HashAcceleratorConfig::from_preimage_lengths(
            &preimages.iter().map(|p| p.len()).collect::<Vec<usize>>(),
        );

        let expected_digests = preimages
            .iter()
            .map(|p| CoreSha256Hasher::hash_bytes(p))
            .collect::<Vec<_>>();

        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = GoldilocksField;
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let expected_preimage_targets = preimages
            .iter()
            .map(|p| builder.add_virtual_targets(p.len()))
            .collect::<Vec<_>>();

        let expected_digest_targets = (0..expected_digests.len())
            .map(|_| builder.add_virtual_hash256_bytes_target())
            .collect::<Vec<_>>();

        let sha256_acc_gadget = SmartSha256AcceleratorGadget::<
            SHA256,
            Sha256AirParametersGoldilocks,
            C,
            D,
            64,
        >::add_virtual_to(&mut builder, hash_acc_config);
        expected_preimage_targets
            .iter()
            .enumerate()
            .for_each(|(i, expected)| {
                builder.connect_vec(expected, &sha256_acc_gadget.preimage_targets[i])
            });

        expected_digest_targets
            .iter()
            .enumerate()
            .for_each(|(i, expected)| {
                builder.connect_hash256_bytes(*expected, sha256_acc_gadget.digest_targets[i])
            });
        //let num_gates = builder.num_gates();
        let data = builder.build::<C>();

        let start_time = std::time::Instant::now();
        let mut pw = PartialWitness::new();
        expected_digests
            .iter()
            .zip(expected_digest_targets.iter())
            .for_each(|(d, t)| {
                pw.set_hash256_bytes_target(t, &d.0);
            });
        expected_preimage_targets
            .iter()
            .zip(preimages.iter())
            .for_each(|(t, p)| {
                pw.set_target_arr(
                    t,
                    &p.iter()
                        .map(|v| F::from_canonical_u8(*v))
                        .collect::<Vec<F>>(),
                );
            });
        sha256_acc_gadget.set_witness(&mut pw, &preimages);

        let proof = data.prove(pw).unwrap();
        let duration_ms = start_time.elapsed().as_millis();
        println!("public_inputs: {:?}", proof.public_inputs);
        println!("sha256 proved in {}ms", duration_ms);
        assert!(data.verify(proof).is_ok());
    }
}
