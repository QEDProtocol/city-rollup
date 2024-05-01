use plonky2::{
    field::extension::Extendable,
    gates::base_sum::BaseSumGate,
    hash::hash_types::RichField,
    iop::{
        generator::{GeneratedValues, SimpleGenerator},
        target::{BoolTarget, Target},
        witness::{PartitionWitness, Witness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
    util::serialization::{Read, Write},
};

use crate::common::{math::ceil_div_usize, u32::arithmetic_u32::U32Target};

pub fn _right_rotate<const S: usize>(n: [BoolTarget; S], bits: usize) -> [BoolTarget; S] {
    let mut res = [None; S];
    for i in 0..S {
        res[i] = Some(n[((S - bits) + i) % S])
    }
    res.map(|x| x.unwrap())
}

pub fn _shr<F: RichField + Extendable<D>, const D: usize, const S: usize>(
    n: [BoolTarget; S],
    bits: i64,
    builder: &mut CircuitBuilder<F, D>,
) -> [BoolTarget; S] {
    let mut res = [None; S];
    for i in 0..S {
        if (i as i64) < bits {
            res[i] = Some(BoolTarget::new_unsafe(builder.constant(F::ZERO)));
        } else {
            res[i] = Some(n[(i as i64 - bits) as usize]);
        }
    }
    res.map(|x| x.unwrap())
}

pub fn uint64_to_bits<F: RichField + Extendable<D>, const D: usize>(
    value: u64,
    builder: &mut CircuitBuilder<F, D>,
) -> [BoolTarget; 64] {
    let mut bits = [None; 64];
    (0..64).for_each(|i| {
        if value & (1 << (63 - i)) != 0 {
            bits[i] = Some(BoolTarget::new_unsafe(builder.constant(F::ONE)));
        } else {
            bits[i] = Some(BoolTarget::new_unsafe(builder.constant(F::ZERO)));
        }
    });
    bits.map(|x| x.unwrap())
}

pub fn uint32_to_bits<F: RichField + Extendable<D>, const D: usize>(
    value: u32,
    builder: &mut CircuitBuilder<F, D>,
) -> [BoolTarget; 32] {
    let mut bits = [None; 32];
    (0..32).for_each(|i| {
        if value & (1 << (31 - i)) != 0 {
            bits[i] = Some(BoolTarget::new_unsafe(builder.constant(F::ONE)));
        } else {
            bits[i] = Some(BoolTarget::new_unsafe(builder.constant(F::ZERO)));
        }
    });
    bits.map(|x| x.unwrap())
}

pub fn byte_to_u32_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    bits_target: Vec<BoolTarget>,
) -> U32Target {
    let bit_len = bits_target.len();
    assert_eq!(bit_len, 8);

    U32Target(builder.le_sum(bits_target.iter().rev()))
}

pub fn split_le_no_drain<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    integer: Target,
    num_bits: usize,
) -> Vec<BoolTarget> {
    if num_bits == 0 {
        return Vec::new();
    }
    let gate_type = BaseSumGate::<2>::new_from_config::<F>(&builder.config);
    let k = ceil_div_usize(num_bits, gate_type.num_limbs);
    let gates = (0..k)
        .map(|_| builder.add_gate(gate_type, vec![]))
        .collect::<Vec<_>>();

    let mut bits = Vec::with_capacity(num_bits);
    for &gate in &gates {
        // for limb_column in gate_type.limbs() {
        let limbs_range = 1..1 + gate_type.num_limbs;
        for limb_column in limbs_range {
            // `new_unsafe` is safe here because BaseSumGate::<2> forces it to be in `{0, 1}`.
            bits.push(BoolTarget::new_unsafe(Target::wire(gate, limb_column)));
        }
    }
    /*
    for b in bits.drain(num_bits..) {
        self.assert_zero(b.target);
    }
    */

    let zero = builder.zero();
    let base = F::TWO.exp_u64(gate_type.num_limbs as u64);
    let mut acc = zero;
    for &gate in gates.iter().rev() {
        // BaseSumGate::<2>::WIRE_SUM == 0
        let sum = Target::wire(gate, 0);
        acc = builder.mul_const_add(base, acc, sum);
    }
    builder.connect(acc, integer);

    builder.add_simple_generator(WireSplitGenerator {
        integer,
        gates,
        num_limbs: gate_type.num_limbs,
    });

    bits
}

#[derive(Debug)]
struct WireSplitGenerator {
    integer: Target,
    gates: Vec<usize>,
    num_limbs: usize,
}

impl<F: RichField + Extendable<D>, const D: usize> SimpleGenerator<F, D> for WireSplitGenerator {
    fn dependencies(&self) -> Vec<Target> {
        vec![self.integer]
    }

    fn run_once(&self, witness: &PartitionWitness<F>, out_buffer: &mut GeneratedValues<F>) {
        let mut integer_value = witness.get_target(self.integer).to_canonical_u64();

        for &gate in &self.gates {
            //BaseSumGate::<2>::WIRE_SUM = 0
            let sum = Target::wire(gate, 0);

            // If num_limbs >= 64, we don't need to truncate since `integer_value` is already
            // limited to 64 bits, and trying to do so would cause overflow. Hence the conditional.
            let mut truncated_value = integer_value;
            if self.num_limbs < 64 {
                truncated_value = integer_value & ((1 << self.num_limbs) - 1);
                integer_value >>= self.num_limbs;
            } else {
                integer_value = 0;
            };

            out_buffer.set_target(sum, F::from_canonical_u64(truncated_value));
        }

        debug_assert_eq!(
            integer_value,
            0,
            "Integer too large to fit in {} many `BaseSumGate`s",
            self.gates.len()
        );
    }

    fn id(&self) -> String {
        "WireSplitGenerator".to_string()
    }
    fn serialize(
        &self,
        dst: &mut Vec<u8>,
        _common_data: &plonky2::plonk::circuit_data::CommonCircuitData<F, D>,
    ) -> plonky2::util::serialization::IoResult<()> {
        dst.write_target(self.integer)?;
        dst.write_usize_vec(&self.gates)?;
        dst.write_usize(self.num_limbs)
    }

    fn deserialize(
        src: &mut plonky2::util::serialization::Buffer,
        _common_data: &plonky2::plonk::circuit_data::CommonCircuitData<F, D>,
    ) -> plonky2::util::serialization::IoResult<Self>
    where
        Self: Sized,
    {
        let integer = src.read_target()?;
        let gates = src.read_usize_vec()?;
        let num_limbs = src.read_usize()?;
        Ok(Self {
            integer,
            gates,
            num_limbs,
        })
    }
}

pub fn reg_dbg_input<F: RichField + Extendable<D>, const D: usize, const S: usize>(
    x: [BoolTarget; S],
    builder: &mut CircuitBuilder<F, D>,
) {
    let p = builder.le_sum(x.iter());
    builder.register_public_input(p);
}

/*
a ^ b ^ c = a+b+c - 2*a*b - 2*a*c - 2*b*c + 4*a*b*c
        = a*( 1 - 2*b - 2*c + 4*b*c ) + b + c - 2*b*c
        = a*( 1 - 2*b -2*c + 4*m ) + b + c - 2*m
where m = b*c
*/
pub fn xor3<F: RichField + Extendable<D>, const D: usize>(
    a: BoolTarget,
    b: BoolTarget,
    c: BoolTarget,
    builder: &mut CircuitBuilder<F, D>,
) -> BoolTarget {
    let m = builder.mul(b.target, c.target);
    let two_b = builder.add(b.target, b.target);
    let two_c = builder.add(c.target, c.target);
    let two_m = builder.add(m, m);
    let four_m = builder.add(two_m, two_m);
    let one = builder.one();
    let one_sub_two_b = builder.sub(one, two_b);
    let one_sub_two_b_sub_two_c = builder.sub(one_sub_two_b, two_c);
    let one_sub_two_b_sub_two_c_add_four_m = builder.add(one_sub_two_b_sub_two_c, four_m);
    let mut res = builder.mul(a.target, one_sub_two_b_sub_two_c_add_four_m);
    res = builder.add(res, b.target);
    res = builder.add(res, c.target);

    BoolTarget::new_unsafe(builder.sub(res, two_m))
}

pub fn xor3_arr<F: RichField + Extendable<D>, const D: usize, const S: usize>(
    a: [BoolTarget; S],
    b: [BoolTarget; S],
    c: [BoolTarget; S],
    builder: &mut CircuitBuilder<F, D>,
) -> [BoolTarget; S] {
    let mut res = [None; S];
    for i in 0..S {
        res[i] = Some(xor3(a[i], b[i], c[i], builder));
    }
    res.map(|x| x.unwrap())
}

pub fn xor2_arr<F: RichField + Extendable<D>, const D: usize, const S: usize>(
    a: [BoolTarget; S],
    b: [BoolTarget; S],
    builder: &mut CircuitBuilder<F, D>,
) -> [BoolTarget; S] {
    let mut res = [None; S];
    for i in 0..S {
        let a_b = builder.mul(a[i].target, b[i].target);
        let two_a_b = builder.mul_const(F::ONE + F::ONE, a_b);
        let a_plus_b = builder.add(a[i].target, b[i].target);
        res[i] = Some(BoolTarget::new_unsafe(builder.sub(a_plus_b, two_a_b)));
    }
    res.map(|x| x.unwrap())
}

pub fn and_arr<F: RichField + Extendable<D>, const D: usize, const S: usize>(
    a: [BoolTarget; S],
    b: [BoolTarget; S],
    builder: &mut CircuitBuilder<F, D>,
) -> [BoolTarget; S] {
    let mut res = [None; S];
    for i in 0..S {
        res[i] = Some(builder.and(a[i], b[i]));
    }
    res.map(|x| x.unwrap())
}

pub fn not_arr<F: RichField + Extendable<D>, const D: usize, const S: usize>(
    a: [BoolTarget; S],
    builder: &mut CircuitBuilder<F, D>,
) -> [BoolTarget; S] {
    let mut res = [None; S];
    for i in 0..S {
        res[i] = Some(builder.not(a[i]));
    }
    res.map(|x| x.unwrap())
}

pub fn add_arr_2<F: RichField + Extendable<D>, const D: usize, const S: usize>(
    a: [BoolTarget; S],
    b: [BoolTarget; S],
    builder: &mut CircuitBuilder<F, D>,
) -> [BoolTarget; S] {
    // First convert a, b into biguint with limbs of 32 bits each
    let a_number = builder.le_sum(a.iter());
    let b_number = builder.le_sum(b.iter());
    let c = builder.add(a_number, b_number);
    bool_vec_to_arr_s::<S>(&split_le_no_drain(builder, c, 32))
}

pub fn add_arr_3<F: RichField + Extendable<D>, const D: usize, const S: usize>(
    a: [BoolTarget; S],
    b: [BoolTarget; S],
    c: [BoolTarget; S],
    builder: &mut CircuitBuilder<F, D>,
) -> [BoolTarget; S] {
    // First convert a, b into biguint with limbs of 32 bits each
    let x = add_arr_2(a, b, builder);
    add_arr_2(x, c, builder)
}

pub fn add_arr_2_const<F: RichField + Extendable<D>, const D: usize, const S: usize>(
    a: [BoolTarget; S],
    b: u64,
    builder: &mut CircuitBuilder<F, D>,
) -> [BoolTarget; S] {
    // First convert a, b into biguint with limbs of 32 bits each
    let a_number = builder.le_sum(a.iter());
    let b_number = builder.constant(F::from_noncanonical_u64(b));
    let c = builder.add(a_number, b_number);
    bool_vec_to_arr_s::<S>(&split_le_no_drain(builder, c, 32))
}

pub fn or_arr<F: RichField + Extendable<D>, const D: usize, const S: usize>(
    a: [BoolTarget; S],
    b: [BoolTarget; S],
    builder: &mut CircuitBuilder<F, D>,
) -> [BoolTarget; S] {
    //XOR(XOR(a,b),AND(a,b))
    let x = xor2_arr(a, b, builder);
    let y = and_arr(a, b, builder);
    xor2_arr(x, y, builder)
}

pub fn bool_vec_to_arr_s<const S: usize>(arr: &[BoolTarget]) -> [BoolTarget; S] {
    let mut out_arr: [Option<BoolTarget>; S] = [None; S];
    for i in 0..S {
        out_arr[i] = Some(arr[i]);
    }
    out_arr.map(|f| f.unwrap())
}

pub fn rol_arr<F: RichField + Extendable<D>, const D: usize, const S: usize>(
    a: [BoolTarget; S],
    shift_amount: usize,
    _builder: &mut CircuitBuilder<F, D>,
) -> [BoolTarget; S] {
    let n = S - (shift_amount % 32);
    let p = vec![a[n..S].to_vec(), a[0..n].to_vec()].concat();
    bool_vec_to_arr_s(&p)
}
