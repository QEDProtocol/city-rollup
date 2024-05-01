use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::target::{BoolTarget, Target},
    plonk::circuit_builder::CircuitBuilder,
};

use crate::common::builder::{
    core::CircuitBuilderHelpersCore,
    hash_ops::{
        add_arr_2, add_arr_2_const, add_arr_3, and_arr, bool_vec_to_arr_s, not_arr, or_arr,
        rol_arr, split_le_no_drain, xor2_arr, xor3_arr,
    },
};

use super::{
    hash160bytes::{CircuitBuilderHash160Bytes, Hash160BytesTarget},
    hash256bytes::{CircuitBuilderHash256Bytes, Hash256BytesTarget},
};

pub trait CircuitBuilderHashRipemd160<F: RichField + Extendable<D>, const D: usize> {
    fn hash_ripemd160_hash256_bytes(&mut self, value: Hash256BytesTarget) -> Hash160BytesTarget;
}
impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderHashRipemd160<F, D>
    for CircuitBuilder<F, D>
{
    fn hash_ripemd160_hash256_bytes(&mut self, value: Hash256BytesTarget) -> Hash160BytesTarget {
        let bit_decomposed = self.hash256_bytes_to_u32_bits(value);
        let bits = ripemd160_hash_pad_u32_bits(self, &bit_decomposed);
        self.hash160_bytes_from_u32_bits(&bits)
    }
}

pub fn ripemd160_op_f_arr<F: RichField + Extendable<D>, const D: usize, const S: usize>(
    input_t: usize,
    x: [BoolTarget; S],
    y: [BoolTarget; S],
    z: [BoolTarget; S],
    builder: &mut CircuitBuilder<F, D>,
) -> [BoolTarget; S] {
    let t = if input_t < 80 {
        input_t
    } else {
        80 - (input_t % 80) - 1
    };

    if t < 16 {
        xor3_arr(x, y, z, builder)
    } else if t < 32 {
        let a = and_arr(x, y, builder);
        let not_x = not_arr(x, builder);
        let b = and_arr(not_x, z, builder);
        or_arr(a, b, builder)
    } else if t < 48 {
        let not_y = not_arr(y, builder);
        let x_or_not_y = or_arr(x, not_y, builder);
        xor2_arr(x_or_not_y, z, builder)
    } else if t < 64 {
        let x_and_z = and_arr(x, z, builder);
        let not_z = not_arr(z, builder);
        let y_and_not_z = and_arr(y, not_z, builder);
        or_arr(x_and_z, y_and_not_z, builder)
    } else if t < 80 {
        let not_z = not_arr(z, builder);
        let y_or_not_z = or_arr(y, not_z, builder);
        xor2_arr(x, y_or_not_z, builder)
    } else {
        panic!("should not reach here")
    }
}

pub fn ripemd160_const_k(t: usize) -> usize {
    if t < 16 {
        0x00000000
    } else if t < 32 {
        0x5a827999
    } else if t < 48 {
        0x6ed9eba1
    } else if t < 64 {
        0x8f1bbcdc
    } else if t < 80 {
        0xa953fd4e
    } else if t < 96 {
        0x50a28be6
    } else if t < 112 {
        0x5c4dd124
    } else if t < 128 {
        0x6d703ef3
    } else if t < 144 {
        0x7a6d76e9
    } else {
        0
    }
}

#[rustfmt::skip]
pub const RIPEMD160_CONST_BASE_HASH: [u64; 5] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];

#[rustfmt::skip]
pub const RIPEMD160_CONST_S: [u64; 160] = [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12, 11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12, 9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6, 8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11, 9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8, 8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11];

#[rustfmt::skip]
pub const RIPEMD160_CONST_X: [u64; 160] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8, 3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2, 4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13, 5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2, 15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14, 12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11];

pub fn ripemd160_op_c_arr<F: RichField + Extendable<D>, const D: usize, const S: usize>(
    input_t: usize,
    a: [BoolTarget; S],
    b: [BoolTarget; S],
    c: [BoolTarget; S],
    d: [BoolTarget; S],
    e: [BoolTarget; S],
    x: [BoolTarget; S],
    builder: &mut CircuitBuilder<F, D>,
) -> [BoolTarget; S] {
    let f_result = ripemd160_op_f_arr(input_t, b, c, d, builder);
    let a_plus_f_result = add_arr_2(a, f_result, builder);
    let x_plus_k_t = add_arr_2_const(x, ripemd160_const_k(input_t as usize) as u64, builder);
    let a_plus_f_result_plus_x_plus_k_t = add_arr_2(a_plus_f_result, x_plus_k_t, builder);
    let a_plus_f_result_plus_x_plus_k_t_rol_s = rol_arr(
        a_plus_f_result_plus_x_plus_k_t,
        RIPEMD160_CONST_S[input_t] as usize,
        builder,
    );
    let a_plus_f_result_plus_x_plus_k_t_rol_e_plus_e =
        add_arr_2(a_plus_f_result_plus_x_plus_k_t_rol_s, e, builder);

    a_plus_f_result_plus_x_plus_k_t_rol_e_plus_e
}
pub fn ripemd160_round<F: RichField + Extendable<D>, const D: usize, const S: usize>(
    i: usize,
    builder: &mut CircuitBuilder<F, D>,
    round_initial_hash_targets_input: [Target; 5],
    payload_target: [Target; 16],
) -> [Target; 5] {
    let mut round_hash_targets = round_initial_hash_targets_input
        .map(|t| bool_vec_to_arr_s::<S>(&split_le_no_drain::<F, D>(builder, t, 32)));
    let x =
        payload_target.map(|t| bool_vec_to_arr_s::<S>(&split_le_no_drain::<F, D>(builder, t, 32)));
    let mut aa = round_hash_targets[0];
    let mut aaa = round_hash_targets[0];

    let mut bb = round_hash_targets[1];
    let mut bbb = round_hash_targets[1];

    let mut cc = round_hash_targets[2];
    let mut ccc = round_hash_targets[2];

    let mut dd = round_hash_targets[3];
    let mut ddd = round_hash_targets[3];

    let mut ee = round_hash_targets[4];
    let mut eee = round_hash_targets[4];
    for t in 0..80 {
        aa = ripemd160_op_c_arr::<F, D, S>(
            t,
            aa,
            bb,
            cc,
            dd,
            ee,
            x[i + RIPEMD160_CONST_X[t] as usize],
            builder,
        );
        let tmp = ee;
        ee = dd;
        dd = rol_arr(cc, 10, builder);
        cc = bb;
        bb = aa;
        aa = tmp;
    }

    for t in 80..160 {
        aaa = ripemd160_op_c_arr::<F, D, S>(
            t,
            aaa,
            bbb,
            ccc,
            ddd,
            eee,
            x[i + RIPEMD160_CONST_X[t] as usize],
            builder,
        );
        let tmp = eee;
        eee = ddd;
        ddd = rol_arr(ccc, 10, builder);
        ccc = bbb;
        bbb = aaa;
        aaa = tmp;
    }

    ddd = add_arr_3(round_hash_targets[1], cc, ddd, builder);
    round_hash_targets[1] = add_arr_3(round_hash_targets[2], dd, eee, builder);
    round_hash_targets[2] = add_arr_3(round_hash_targets[3], ee, aaa, builder);
    round_hash_targets[3] = add_arr_3(round_hash_targets[4], aa, bbb, builder);
    round_hash_targets[4] = add_arr_3(round_hash_targets[0], bb, ccc, builder);
    round_hash_targets[0] = ddd;

    round_hash_targets.map(|rht| builder.le_sum(rht.iter()))
}

pub fn ripemd160_rounds<F: RichField + Extendable<D>, const D: usize, const S: usize>(
    builder: &mut CircuitBuilder<F, D>,

    payload_targets: Vec<[Target; 16]>,
) -> [Target; 5] {
    let mut round_hash_targets = RIPEMD160_CONST_BASE_HASH
        .map(|z| builder.constant(F::from_noncanonical_u64(z)))
        .map(|t| bool_vec_to_arr_s::<S>(&split_le_no_drain::<F, D>(builder, t, 32)));

    for i in 0..payload_targets.len() {
        let x = payload_targets[i]
            .map(|t| bool_vec_to_arr_s::<S>(&split_le_no_drain::<F, D>(builder, t, 32)));
        let mut aa = round_hash_targets[0];
        let mut aaa = round_hash_targets[0];

        let mut bb = round_hash_targets[1];
        let mut bbb = round_hash_targets[1];

        let mut cc = round_hash_targets[2];
        let mut ccc = round_hash_targets[2];

        let mut dd = round_hash_targets[3];
        let mut ddd = round_hash_targets[3];

        let mut ee = round_hash_targets[4];
        let mut eee = round_hash_targets[4];
        for t in 0..80 {
            aa = ripemd160_op_c_arr::<F, D, S>(
                t,
                aa,
                bb,
                cc,
                dd,
                ee,
                x[i * 16 + RIPEMD160_CONST_X[t] as usize],
                builder,
            );
            let tmp = ee;
            ee = dd;
            dd = rol_arr(cc, 10, builder);
            cc = bb;
            bb = aa;
            aa = tmp;
        }

        for t in 80..160 {
            aaa = ripemd160_op_c_arr::<F, D, S>(
                t,
                aaa,
                bbb,
                ccc,
                ddd,
                eee,
                x[i * 16 + RIPEMD160_CONST_X[t] as usize],
                builder,
            );
            let tmp = eee;
            eee = ddd;
            ddd = rol_arr(ccc, 10, builder);
            ccc = bbb;
            bbb = aaa;
            aaa = tmp;
        }

        ddd = add_arr_3(round_hash_targets[1], cc, ddd, builder);
        round_hash_targets[1] = add_arr_3(round_hash_targets[2], dd, eee, builder);
        round_hash_targets[2] = add_arr_3(round_hash_targets[3], ee, aaa, builder);
        round_hash_targets[3] = add_arr_3(round_hash_targets[4], aa, bbb, builder);
        round_hash_targets[4] = add_arr_3(round_hash_targets[0], bb, ccc, builder);
        round_hash_targets[0] = ddd;
    }
    round_hash_targets.map(|rht| builder.le_sum(rht.iter()))
}

pub fn ripemd160_rounds_no_16<F: RichField + Extendable<D>, const D: usize, const S: usize>(
    builder: &mut CircuitBuilder<F, D>,

    payload_targets: &[Target],
) -> [Target; 5] {
    let mut round_hash_targets = RIPEMD160_CONST_BASE_HASH
        .map(|z| builder.constant(F::from_noncanonical_u64(z)))
        .map(|t| bool_vec_to_arr_s::<S>(&split_le_no_drain::<F, D>(builder, t, 32)));

    let x = payload_targets
        .iter()
        .map(|t| bool_vec_to_arr_s::<S>(&split_le_no_drain::<F, D>(builder, *t, 32)))
        .collect::<Vec<_>>();
    for ctr in 0..(x.len() / 16) {
        let i = ctr * 16;

        let mut aa = round_hash_targets[0];
        let mut aaa = round_hash_targets[0];

        let mut bb = round_hash_targets[1];
        let mut bbb = round_hash_targets[1];

        let mut cc = round_hash_targets[2];
        let mut ccc = round_hash_targets[2];

        let mut dd = round_hash_targets[3];
        let mut ddd = round_hash_targets[3];

        let mut ee = round_hash_targets[4];
        let mut eee = round_hash_targets[4];
        for t in 0..80 {
            aa = ripemd160_op_c_arr::<F, D, S>(
                t,
                aa,
                bb,
                cc,
                dd,
                ee,
                x[i + RIPEMD160_CONST_X[t] as usize],
                builder,
            );
            let tmp = ee;
            ee = dd;
            dd = rol_arr(cc, 10, builder);
            cc = bb;
            bb = aa;
            aa = tmp;
        }

        for t in 80..160 {
            aaa = ripemd160_op_c_arr::<F, D, S>(
                t,
                aaa,
                bbb,
                ccc,
                ddd,
                eee,
                x[i + RIPEMD160_CONST_X[t] as usize],
                builder,
            );
            let tmp = eee;
            eee = ddd;
            ddd = rol_arr(ccc, 10, builder);
            ccc = bbb;
            bbb = aaa;
            aaa = tmp;
        }

        ddd = add_arr_3(round_hash_targets[1], cc, ddd, builder);
        round_hash_targets[1] = add_arr_3(round_hash_targets[2], dd, eee, builder);
        round_hash_targets[2] = add_arr_3(round_hash_targets[3], ee, aaa, builder);
        round_hash_targets[3] = add_arr_3(round_hash_targets[4], aa, bbb, builder);
        round_hash_targets[4] = add_arr_3(round_hash_targets[0], bb, ccc, builder);
        round_hash_targets[0] = ddd;
    }
    round_hash_targets.map(|rht| builder.le_sum(rht.iter()))
}

pub fn ripemd160_rounds_no_16_bits<F: RichField + Extendable<D>, const D: usize, const S: usize>(
    builder: &mut CircuitBuilder<F, D>,
    payload_targets: &[[BoolTarget; S]],
) -> [[BoolTarget; S]; 5] {
    let mut round_hash_targets = RIPEMD160_CONST_BASE_HASH
        .map(|z| builder.constant(F::from_noncanonical_u64(z)))
        .map(|t| bool_vec_to_arr_s::<S>(&split_le_no_drain::<F, D>(builder, t, 32)));

    let x = payload_targets;
    for ctr in 0..(x.len() / 16) {
        let i = ctr * 16;

        let mut aa = round_hash_targets[0];
        let mut aaa = round_hash_targets[0];

        let mut bb = round_hash_targets[1];
        let mut bbb = round_hash_targets[1];

        let mut cc = round_hash_targets[2];
        let mut ccc = round_hash_targets[2];

        let mut dd = round_hash_targets[3];
        let mut ddd = round_hash_targets[3];

        let mut ee = round_hash_targets[4];
        let mut eee = round_hash_targets[4];
        for t in 0..80 {
            aa = ripemd160_op_c_arr::<F, D, S>(
                t,
                aa,
                bb,
                cc,
                dd,
                ee,
                x[i + RIPEMD160_CONST_X[t] as usize],
                builder,
            );
            let tmp = ee;
            ee = dd;
            dd = rol_arr(cc, 10, builder);
            cc = bb;
            bb = aa;
            aa = tmp;
        }

        for t in 80..160 {
            aaa = ripemd160_op_c_arr::<F, D, S>(
                t,
                aaa,
                bbb,
                ccc,
                ddd,
                eee,
                x[i + RIPEMD160_CONST_X[t] as usize],
                builder,
            );
            let tmp = eee;
            eee = ddd;
            ddd = rol_arr(ccc, 10, builder);
            ccc = bbb;
            bbb = aaa;
            aaa = tmp;
        }

        ddd = add_arr_3(round_hash_targets[1], cc, ddd, builder);
        round_hash_targets[1] = add_arr_3(round_hash_targets[2], dd, eee, builder);
        round_hash_targets[2] = add_arr_3(round_hash_targets[3], ee, aaa, builder);
        round_hash_targets[3] = add_arr_3(round_hash_targets[4], aa, bbb, builder);
        round_hash_targets[4] = add_arr_3(round_hash_targets[0], bb, ccc, builder);
        round_hash_targets[0] = ddd;
    }
    round_hash_targets
}

pub fn ripemd160_hash_pad_u32<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    u32_inputs: &[Target],
) -> [Target; 5] {
    let length = u32_inputs.len() * 4;
    let bit_length = length * 8;
    let pad_length = (if length % 64 < 56 { 56 } else { 120 }) - (length % 64);
    let u32_pad_length = pad_length / 4;
    let zero = builder.zero();
    let pad_targets = (0..u32_pad_length)
        .map(|ind| {
            if ind == 0 {
                builder.constant(F::from_canonical_u32(0x80 as u32))
            } else {
                zero
            }
        })
        .collect::<Vec<_>>();

    let bit_length_target = builder.constant(F::from_canonical_u32(bit_length as u32));
    let count_target = builder.constant(F::from_canonical_u32(
        ((bit_length as u64) / (4294967296u64)) as u32,
    ));

    let payload_targets = vec![
        u32_inputs.to_vec(),
        pad_targets,
        vec![bit_length_target, count_target],
    ]
    .concat();
    ripemd160_rounds_no_16::<F, D, 32>(builder, &payload_targets)
}

pub fn ripemd160_hash_pad_u32_bits<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    u32_inputs: &[[BoolTarget; 32]],
) -> [[BoolTarget; 32]; 5] {
    let length = u32_inputs.len() * 4;
    let bit_length = length * 8;
    let pad_length = (if length % 64 < 56 { 56 } else { 120 }) - (length % 64);
    let u32_pad_length = pad_length / 4;
    //let zero = builder.zero();
    let pad_targets = (0..u32_pad_length)
        .map(|ind| {
            if ind == 0 {
                builder.constant_u32_bits(0x80)
            } else {
                builder.constant_u32_bits(0)
            }
        })
        .collect::<Vec<_>>();

    let bit_length_target = builder.constant_u32_bits(bit_length as u32);
    let count_target = builder.constant_u32_bits(((bit_length as u64) / (4294967296u64)) as u32);

    let payload_targets = vec![
        u32_inputs.to_vec(),
        pad_targets,
        vec![bit_length_target, count_target],
    ]
    .concat();
    ripemd160_rounds_no_16_bits::<F, D, 32>(builder, &payload_targets)
}
