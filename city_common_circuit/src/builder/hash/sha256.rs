use city_crypto::field::qfield::QRichField;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::BoolTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::hash::base_types::hash256::{CircuitBuilderHash, Hash256Target};
use crate::traits::GenericCircuitMerkleHasher;
use crate::u32::arithmetic_u32::{CircuitBuilderU32, U32Target};
use crate::u32::interleaved_u32::CircuitBuilderB32;

pub trait CircuitBuilderHashSha256<F: RichField + Extendable<D>, const D: usize> {
    fn hash_sha256_u32(&mut self, data: &[U32Target]) -> Hash256Target;
    fn hash_sha256_u32_bytes(&mut self, data: &[U32Target], length_bytes: usize) -> Hash256Target;
    fn two_to_one_sha256(&mut self, left: Hash256Target, right: Hash256Target) -> Hash256Target;
}

/// Initial state for SHA-256.
#[rustfmt::skip]
pub const H256_256: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Constants necessary for SHA-256 family of digests.
#[rustfmt::skip]
pub const K32: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

// (a rrot r1) xor (a rrot r2) xor (a rsh s3)
pub fn sigma<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: U32Target,
    r1: u8,
    r2: u8,
    s3: u8,
) -> U32Target {
    let x = builder.rrot_u32(a, r1);
    let y = builder.rrot_u32(a, r2);
    let z = builder.rsh_u32(a, s3);

    builder.unsafe_xor_many_u32(&[x, y, z])
}

// (a rrot r1) xor (a rrot r2) xor (a rrot r3)
pub fn big_sigma<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: U32Target,
    r1: u8,
    r2: u8,
    r3: u8,
) -> U32Target {
    let x = builder.rrot_u32(a, r1);
    let y = builder.rrot_u32(a, r2);
    let z = builder.rrot_u32(a, r3);

    builder.unsafe_xor_many_u32(&[x, y, z])
}

// (e and f) xor ((not e) and g)
pub fn ch<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    e: U32Target,
    f: U32Target,
    g: U32Target,
) -> U32Target {
    let not_e = builder.not_u32(e);

    let ef = builder.and_xor_u32(e, f).0;
    let eg = builder.and_xor_u32(not_e, g).0;

    builder.and_xor_b32_to_u32(ef, eg).1
}

// (a and b) xor (a and c) xor (b and c)
// = (a and (b xor c)) xor (b and c)
// we can calculate (b xor c), (b and c) in a single op
pub fn maj<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: U32Target,
    b: U32Target,
    c: U32Target,
) -> U32Target {
    let (b_and_c, b_xor_c) = builder.and_xor_u32(b, c);

    let a = builder.interleave_u32(a);
    let abc = builder.and_xor_b32(a, b_xor_c).0;

    builder.and_xor_b32_to_u32(abc, b_and_c).1
}

pub fn sha256_start_state<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> [U32Target; 8] {
    [
        builder.constant_u32(H256_256[0]),
        builder.constant_u32(H256_256[1]),
        builder.constant_u32(H256_256[2]),
        builder.constant_u32(H256_256[3]),
        builder.constant_u32(H256_256[4]),
        builder.constant_u32(H256_256[5]),
        builder.constant_u32(H256_256[6]),
        builder.constant_u32(H256_256[7]),
    ]
}

pub fn sha256_round_constants<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> [U32Target; 64] {
    core::array::from_fn(|i| builder.constant_u32(K32[i]))
}

pub fn sha256_digest_block<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    state: &mut [U32Target],
    block_data: &[U32Target],
    k256: &[U32Target],
) {
    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];

    let mut w = [
        block_data[0],
        block_data[1],
        block_data[2],
        block_data[3],
        block_data[4],
        block_data[5],
        block_data[6],
        block_data[7],
        block_data[8],
        block_data[9],
        block_data[10],
        block_data[11],
        block_data[12],
        block_data[13],
        block_data[14],
        block_data[15],
    ];

    for i in 0..64 {
        // Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array
        if i >= 16 {
            let s0 = sigma(builder, w[(i + 1) & 0xf], 7, 18, 3);
            let s1 = sigma(builder, w[(i + 14) & 0xf], 17, 19, 10);
            w[i & 0xf] = builder
                .add_many_u32(&[s0, s1, w[(i + 9) & 0xf], w[i & 0xf]])
                .0;
        }

        // Compression function main loop
        let big_s1_e = big_sigma(builder, e, 6, 11, 25);
        let ch_efg = ch(builder, e, f, g);
        let temp1 = builder
            .add_many_u32(&[h, big_s1_e, ch_efg, k256[i], w[i & 0xf]])
            .0;

        let big_s0_a = big_sigma(builder, a, 2, 13, 22);
        let maj_abc = maj(builder, a, b, c);
        let temp2 = builder.add_u32_lo(big_s0_a, maj_abc);

        h = g;
        g = f;
        f = e;
        e = builder.add_u32_lo(d, temp1);
        d = c;
        c = b;
        b = a;
        a = builder.add_u32_lo(temp1, temp2); // add_many_u32 of 3 elements is the same
    }

    // Add the compressed chunk to the current hash value
    state[0] = builder.add_u32_lo(state[0], a);
    state[1] = builder.add_u32_lo(state[1], b);
    state[2] = builder.add_u32_lo(state[2], c);
    state[3] = builder.add_u32_lo(state[3], d);
    state[4] = builder.add_u32_lo(state[4], e);
    state[5] = builder.add_u32_lo(state[5], f);
    state[6] = builder.add_u32_lo(state[6], g);
    state[7] = builder.add_u32_lo(state[7], h);
}

fn sha256_digest_u32_array_with_length<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    data: &[U32Target],
    length_bits: usize,
) -> Hash256Target {
    let mut state = sha256_start_state(builder);
    let round_constants = sha256_round_constants(builder);
    let standard_rounds = data.len() / 16;
    for i in 0..standard_rounds {
        sha256_digest_block(
            builder,
            &mut state,
            &data[i * 16..i * 16 + 16],
            &round_constants,
        );
    }
    let remaining = data.len() - standard_rounds * 16;
    let zero = builder.zero_u32();
    if remaining <= 13 {
        let mut block_data = [zero; 16];
        for i in 0..remaining {
            block_data[i] = data[standard_rounds * 16 + i];
        }
        block_data[remaining] = builder.constant_u32(0x80000000);
        block_data[14] = builder.constant_u32((length_bits >> 32) as u32);
        block_data[15] = builder.constant_u32((length_bits & 0xffffffff) as u32);

        sha256_digest_block(builder, &mut state, &block_data, &round_constants);
    } else {
        let mut block_data = [zero; 32];
        for i in 0..remaining {
            block_data[i] = data[standard_rounds * 16 + i];
        }
        block_data[remaining] = builder.constant_u32(0x80000000);
        block_data[30] = builder.constant_u32((length_bits as u64 >> 32u64) as u32);
        block_data[31] = builder.constant_u32(((length_bits as u64) & 0xffffffffu64) as u32);
        sha256_digest_block(builder, &mut state, &block_data[0..16], &round_constants);
        sha256_digest_block(builder, &mut state, &block_data[16..32], &round_constants);
    }
    state
}

fn mask_add_u32<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    mask: u32,
    x: U32Target,
    y: u32,
) -> U32Target {
    let mask_target = builder.constant_u32(mask);
    let masked_x = builder.and_u32(x, mask_target);
    let y_target = builder.constant(F::from_canonical_u32(y));
    U32Target(builder.add(masked_x.0, y_target))
}

fn sha256_digest_u32_array_with_byte_length<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    data: &[U32Target],
    length_bytes: usize,
) -> Hash256Target {
    let length_bits = (length_bytes * 8) as u64;
    let mut state = sha256_start_state(builder);
    let round_constants = sha256_round_constants(builder);
    let standard_rounds = data.len() / 16;
    for i in 0..standard_rounds {
        sha256_digest_block(
            builder,
            &mut state,
            &data[i * 16..i * 16 + 16],
            &round_constants,
        );
    }
    let remaining = data.len() - standard_rounds * 16;
    let rem_bytes = length_bytes % 4;
    println!("length_bytes: {}, rem_bytes: {}", length_bytes, rem_bytes);
    let zero = builder.zero_u32();
    println!("remaining: {}", remaining);
    if remaining <= 14 {
        let mut block_data = [zero; 16];
        for i in 0..remaining {
            block_data[i] = data[standard_rounds * 16 + i];
        }

        if rem_bytes == 3 {
            block_data[remaining - 1] =
                mask_add_u32(builder, 0xffffff00, block_data[remaining - 1], 0x80);
        } else if rem_bytes == 2 {
            block_data[remaining - 1] =
                mask_add_u32(builder, 0xffff0000, block_data[remaining - 1], 0x8000);
        } else if rem_bytes == 1 {
            block_data[remaining - 1] =
                mask_add_u32(builder, 0xff000000, block_data[remaining - 1], 0x800000);
        } else {
            block_data[remaining] = builder.constant_u32(0x80000000);
        }

        block_data[14] = builder.constant_u32((length_bits >> 32) as u32);
        block_data[15] = builder.constant_u32((length_bits & 0xffffffff) as u32);

        sha256_digest_block(builder, &mut state, &block_data, &round_constants);
    } else {
        let mut block_data = [zero; 32];
        for i in 0..remaining {
            block_data[i] = data[standard_rounds * 16 + i];
        }
        if rem_bytes == 3 {
            block_data[remaining - 1] =
                mask_add_u32(builder, 0xffffff00, block_data[remaining - 1], 0x80);
        } else if rem_bytes == 2 {
            block_data[remaining - 1] =
                mask_add_u32(builder, 0xffff0000, block_data[remaining - 1], 0x8000);
        } else if rem_bytes == 1 {
            block_data[remaining - 1] =
                mask_add_u32(builder, 0xff000000, block_data[remaining - 1], 0x800000);
        } else {
            block_data[remaining] = builder.constant_u32(0x80000000);
        }
        block_data[30] = builder.constant_u32((length_bits as u64 >> 32u64) as u32);
        block_data[31] = builder.constant_u32(((length_bits as u64) & 0xffffffffu64) as u32);

        //builder.register_public_inputs(&block_data.iter().map(|o|o.0).collect_vec());
        sha256_digest_block(builder, &mut state, &block_data[0..16], &round_constants);
        sha256_digest_block(builder, &mut state, &block_data[16..32], &round_constants);
    }
    state
}

fn sha256_digest_u32_array<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    data: &[U32Target],
) -> Hash256Target {
    sha256_digest_u32_array_with_length(builder, data, data.len() * 32)
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderHashSha256<F, D>
    for CircuitBuilder<F, D>
{
    fn hash_sha256_u32(&mut self, data: &[U32Target]) -> Hash256Target {
        sha256_digest_u32_array(self, data)
    }

    // https://en.wikipedia.org/wiki/SHA-2#Pseudocode
    fn two_to_one_sha256(&mut self, left: Hash256Target, right: Hash256Target) -> Hash256Target {
        let mut state: Hash256Target = [
            self.constant_u32(H256_256[0]),
            self.constant_u32(H256_256[1]),
            self.constant_u32(H256_256[2]),
            self.constant_u32(H256_256[3]),
            self.constant_u32(H256_256[4]),
            self.constant_u32(H256_256[5]),
            self.constant_u32(H256_256[6]),
            self.constant_u32(H256_256[7]),
        ];

        // Initialize array of round constants:
        // (first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311)
        let k256 = sha256_round_constants(self);

        // Pre-processing (Padding)
        // Padding is done by the Witness when setting the input value to the target

        // block 1 data (left and right)
        let w: [U32Target; 16] = [
            left[0], left[1], left[2], left[3], left[4], left[5], left[6], left[7], right[0],
            right[1], right[2], right[3], right[4], right[5], right[6], right[7],
        ];
        // digest block 1
        sha256_digest_block(self, &mut state, &w, &k256);

        let zero = self.constant_u32(0);
        let cx80 = self.constant_u32(0x80000000);
        let c512 = self.constant_u32(512);

        // block 2 (padding/length in bits)
        let w: [U32Target; 16] = [
            cx80, zero, zero, zero, zero, zero, zero, zero, zero, zero, zero, zero, zero, zero,
            zero, c512,
        ];

        // digest block 2
        sha256_digest_block(self, &mut state, &w, &k256);
        state
    }

    fn hash_sha256_u32_bytes(&mut self, data: &[U32Target], length_bytes: usize) -> Hash256Target {
        sha256_digest_u32_array_with_byte_length(self, data, length_bytes)
    }
}

pub struct Sha256Hasher;
impl GenericCircuitMerkleHasher<Hash256Target> for Sha256Hasher {
    fn gc_two_to_one<F: QRichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        left: Hash256Target,
        right: Hash256Target,
    ) -> Hash256Target {
        builder.two_to_one_sha256(left, right)
    }

    fn two_to_one_swapped<F: QRichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        left: Hash256Target,
        right: Hash256Target,
        swap: BoolTarget,
    ) -> Hash256Target {
        let x = builder.select_hash256(swap, left, right);
        let y = builder.select_hash256(swap, right, left);
        Self::gc_two_to_one(builder, x, y)
    }

    fn two_to_one_swapped_marked_leaf<F: QRichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        left: Hash256Target,
        right: Hash256Target,
        swap: BoolTarget,
    ) -> Hash256Target {
        let x = builder.select_hash256(swap, left, right);
        let y = builder.select_hash256(swap, right, left);
        let preimage = [
            x[0],
            x[1],
            x[2],
            x[3],
            x[4],
            x[5],
            x[6],
            x[7],
            y[0],
            y[1],
            y[2],
            y[3],
            y[4],
            y[5],
            y[6],
            y[7],
            builder.one_u32(),
        ];
        builder.hash_sha256_u32(&preimage)
    }
}
#[cfg(test)]
mod tests {
    use std::time::Instant;

    use crate::builder::hash::sha256::sha256_digest_u32_array_with_byte_length;
    use crate::hash::base_types::hash256::{CircuitBuilderHash, WitnessHash256};
    use crate::u32::arithmetic_u32::CircuitBuilderU32;
    use crate::u32::witness::WitnessU32;

    use super::CircuitBuilderHashSha256;
    use city_common::binaryhelpers::bytes::{bytes_to_u32_vec_be, u32_vec_to_bytes_be};
    use city_crypto::hash::base_types::hash256::Hash256;
    use city_crypto::hash::core::sha256::CoreSha256Hasher;
    use city_crypto::hash::qhashout::QHashOut;
    use hex;
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::field::types::{Field, PrimeField64};
    use plonky2::hash::poseidon::PoseidonHash;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, Hasher, PoseidonGoldilocksConfig};

    #[test]
    fn test_sha256_two_to_one() {
        let tests = [
            [
                "44205ea3a71ee1cbd02eef7b084a409450c21d11a3b41769f02bb3e2dd89d5e2",
                "8ecf785b86dd1715d4c193f280a118b82200742f102bf1e59a4a65194a126f03",
                "a452e23aab1e4baae2e3da7c66da43954038e6505dc5b1cb24c8b5d95cf7634c",
            ],
            [
                "42f584ee07afb6754770ea07fc7f498cb7200ba89eb67361a7f2564612040cd3",
                "09e0ed078a0113619c033eec41b65e3168394dc377998bc13481b5f1942f7119",
                "2096622ca7f5aeda8d4c9a9cd4523e1bb9ea09e661f092f515c0c2cbaadcc2c6",
            ],
            [
                "8560e7d4c6e014b01b70bf5e1e2ffaa1e4115c9d21eb685b796b172872b71150",
                "3d38f5e8fc6c4612f27932b009bea0fd41a99c30af7a14a1e5316d9bbd5a4df6",
                "eab6fce22d0679c304d7419cf0746552921b31245d715171a5ec7c9caf81f084",
            ],
            [
                "7c909a4734e36fd67e11cd97a9a4222795672690f3eb081a2dd43a413ba6490c",
                "39a08a837c5bfef00ebb6e3b72f7fc5a8275f13fb5d5a86f03541ebf5ee8edec",
                "f537f1e2ac17a2af3524b7e3fc81ca88adcee65906236dab22250e071924e527",
            ],
            [
                "130151db7ac8036300c80c58a37de8119719ce60600b6e009d09df3a71d5f741",
                "a6bf923dbbcaae29701d82e0a1492ffe388aa14bd3e6ffbfa834aa9b23ad154a",
                "e70822e27d35acff57fc210d451aba171285025ac2fa77911e893427a8430b25",
            ],
            [
                "9992ff1b7ff438d5132b2b5ddd875c10ca62bcb46f681ef228548abdcd6db5c1",
                "4080eca86a5ea164518fc7426dc793ce5c9f95831bc8a97b2f06bc53722c78bb",
                "1bdbe0e67971989362b44c66f7ff26eea7d6c7f5f791d91e96bfa46a6934b97b",
            ],
            [
                "2a6f3577676eb6493d62268cf402f39f432490f8ca64d2323eab7ffb8fa5e239",
                "a004b81f69f9b6694fad09f0193e9120789d4e870681f436a97a2eef9089a3e2",
                "3dd8900540834a3fe28407796f128a21dd4c947b6b991ed14d6167ae4fc29cc3",
            ],
            [
                "7b4e5361bddc8029f76c3fead78e0a0a49e02dd40666cdff03ea40609de3c8d9",
                "bf7b76a80a3a70151640263f13bb62f72d66f0075f03b64e51aaec781b36d8c9",
                "809cf278ede0e210b29e7ce57b12a058d5d1f78be62a16df0c301995be7e7a5d",
            ],
            [
                "a52ae0c843df054f6a9489a743f293a74b7fe21f14bff5d35e9c9ec4fe336522",
                "e3e6379804432520b7eba2a7b46d0b016a4025f32da7cb8aa0003aaf57dab15c",
                "f56647e8f500efaafe8aaaf9a90b142685896cba145a06a6bc9853d9765079b8",
            ],
            [
                "386d9d8e6851f030ac2f510b6a8ebcc2f00e16a9cc7b7707d7d65f8a95ae82f3",
                "bb2b56422cd46210f5ab0c53527e8bf7ef71ad723a77a2cba0d990da15c9bde8",
                "d4d029cc7fbc6eba897d5659bb4d0298f9d3609c383526de67ab15b26fa95ad2",
            ],
            [
                "6e326b458d8bbef8b5a592e939d8bfa2dffb769a5f616034fb0cbf1267d4a600",
                "d5b60f7116771c9033a32bd2ccd22912d97bd3cf30d526fdcaff9f1bc9453397",
                "6c915b5095aca9df36491281c04a4f127b9fd81b4362742f07314d945b44582a",
            ],
            [
                "4af3eaf1108b48e0df66988876570f2044db09a0cad061da7d2448871fc52cb6",
                "cf5c4c57391fa60fbd613b2bdd5ddb5da9435239d073f2cdd265d0788e0b9cec",
                "54a342f852b7d41a5aab4a6a73cfc9adbc3b5fc42303627dbd604eede98e334f",
            ],
        ];

        // build circuit once
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let left_target = builder.add_virtual_hash256_target();
        let right_target = builder.add_virtual_hash256_target();
        let expected_output_target = builder.add_virtual_hash256_target();
        let output_target = builder.two_to_one_sha256(left_target, right_target);
        builder.connect_hash256(output_target, expected_output_target);

        let num_gates = builder.num_gates();
        // let copy_constraints = builder.copy_constraints.len();
        let copy_constraints = "<private>";
        let data = builder.build::<C>();
        println!(
            "two_to_one_sha256 num_gates={}, copy_constraints={}, quotient_degree_factor={}",
            num_gates, copy_constraints, data.common.quotient_degree_factor
        );

        for t in tests {
            let left = Hash256::from_hex_string(t[0]).unwrap();
            let right = Hash256::from_hex_string(t[1]).unwrap();
            let expected_output = Hash256::from_hex_string(t[2]).unwrap();

            // test circuit
            let mut pw = PartialWitness::new();
            pw.set_hash256_target(&left_target, &left.0);
            pw.set_hash256_target(&right_target, &right.0);
            pw.set_hash256_target(&expected_output_target, &expected_output.0);

            let start = Instant::now();
            let proof = data.prove(pw).unwrap();
            let end = start.elapsed();
            println!("two_to_one_sha256 proved in {}ms", end.as_millis());
            assert!(data.verify(proof).is_ok());
        }
    }

    #[test]
    fn test_sha256_long_arbitrary_length() {
        let tests = [
            [
                "600D54000000000000000000000000000000000000000000000000000000000077F1040000000000000000000000000000000000000000000000000000000000",
                "9E05820FB000642E0F36AD7696F92D95C965CB27A8DC093D81A0D37B260A0F8E",
            ],
        ];
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let input = hex::decode(tests[0][0]).unwrap();
        let output = hex::decode(tests[0][1]).unwrap();
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        println!("input len: {} (len/4 = {})", input.len(), input.len() / 4);

        let preimage_target = builder.add_virtual_u32_targets(input.len() / 4);
        println!("preimage target len {}", preimage_target.len());

        let expected_output_target = builder.add_virtual_hash256_target();

        let hash_output = builder.hash_sha256_u32(&preimage_target);
        builder.connect_hash256(hash_output, expected_output_target);

        let num_gates = builder.num_gates();
        let data = builder.build::<C>();
        println!(
            "sha256 ({} bytes) num_gates={}, quotient_degree_factor={}",
            input.len(),
            num_gates,
            data.common.quotient_degree_factor
        );
        let mut pw = PartialWitness::new();
        pw.set_u32_targets(&preimage_target, &bytes_to_u32_vec_be(&input));
        pw.set_hash256_target(&expected_output_target, &output);

        let start_time = std::time::Instant::now();
        let proof = data.prove(pw).unwrap();
        let duration_ms = start_time.elapsed().as_millis();
        println!("sha256 ({} bytes) proved in {}ms", input.len(), duration_ms);

        assert!(data.verify(proof).is_ok());
    }

    #[test]
    fn test_sha256_arbitrary_length() {
        let tests = [
            [
                "600D54000000000000000000000000000000000000000000000000000000000077F1040000000000000000000000000000000000000000000000000000000000",
                "9E05820FB000642E0F36AD7696F92D95C965CB27A8DC093D81A0D37B260A0F8E",
            ],
            [
                "3718CEB4122437AE80D343DFB857F4D016CA3072A05797AC24AE59918EA63C68CF97BD867F78455176EEE0709A9A59EF768E0C6D8A22BCD57ADBB3FB74A0A331F66D7E55CA3786E7C2AB91951F9A1C617CA32B34D395C745E8C15A90766735116E20A45ACA7E4BD37B7F46660E345415C758712EB9493B98C62CAD9B325B1927F7248B773E18D4E4B1D40675B3EFE7528914AD4BEDDB3BADBE05568AE539A6A308D4D2C453C726B34E84E5A6DDC5EED70026BDF5828B7A556342EFC1D8187A4BC7228D0654CB57BB",
                "E1B79FB8A21D1C1438C85BBC81250C112C3126E1935E1C8EF7B8880046B7604B",
            ],
            [
                "ea7f0fe7ed8b30b742b11a0052cd9a54aff18bd42598880371e19f080969270015cb21bc3e8fd66c50eac2d486e271a61313e60d8978caab7a1305725b8b8b20cec40ebef2ecec84efb3b034445f77e78a0630e62e90974a167ef05aead7bdf0cd1c82e34c3a0056befdffa8b75851a4ba7386ef5402ba5fbadace5026d9a0efc977b2f56d2a9f14573dae54f803895cd77571ad178c7aa0868bcf36704f2b5591b82f1ee5579872238930f3c0db7473484d416df0f800eb399bc73792bcab82273c8eb88d466972df36362839df6fe259bc07e1f7fe396fecf9b5a293edfe83211bb2904e629e9e9a01826a09512831abfeedca43e90e6662bbae159433781da39e4f57354c05d57d1ac8bf30cc53ca41bf518491c539fc848c41c7b6c0283468e9e091a190545d519fab7356b749e6b375b47d8dc8e2b1950ecc8139567e1681a6b8226c915de59669555e08c84adc6d292dd5f191f55496ea114c7e7a03ed1a0ca987cb65788613b21be8aa42556e9fbd2567f9a34f6dcff9546e427a91cfb81c2b7cc9ffd1dfc33829336882c4044b0599f0b1cca0cabe26775d37afa787ff1909aa4e78fe0f0b038a42ed5169e5baa44ea9ce0b45aeebea122d850c5d233f10d29ec1c93945e2683c3e9f7eb9054b1f276a0f876f8945c6ebcb714fd8f1a9f3ebe497032e3fa80d2ac9e7e7d7058b705c8889295d084f6108438334deeae670c71d0b57a90cc3e58dc03183f5b9864c5f804a16a91138670360c21391cddc9ac722c6afc3a0f58e59d97ebe8f09a2a68fc265e785bff8aa2bb175a3f4d027a10ee517576f4d4d573eb4f21c8a2d722e1e26780574ed971358a4f1909337b425aef68b3ccd8babf9b7df0bd0759aff72a92462954ee533e9c81cf44e6924cda97a5ce99712c5c1a269a9b5782df41322411f9bbc0ac2e09be861f5b2f1dedfda3082f85202d322814961a29d823a69fc2d539d1fda42559a9e800de3a58432be2c863687febbf4f76f2be30953a72ca02e02eb210feb633dfd6c80cee0638e9de2e8fc02bcc7b341e0964fa76db41de5329a68d29f26ab438ebbd2affb94b462da35653c3bff571e9356208d6c046eb2941623c61788e3e0ab75660bcc72d6d6b7f68aaead8832f81d8e4dd260f1f6ee6f6f6a0985cd2d83c6f97bfe9f9a548c542f8a2b33e48e6c15ff51563167640129eac1013836d6524bfb8c28e18a7201396458256135677cd25b4e0507d61687617126f2baaf3fe36e55d1de27fd9b07a8e90220eebf511978f962c2eb17112f108e958c36c1969b66fff85b5d8c77fc2f6f2d9e0cead09db62cd94a1aff9f9b3438a934dbb99d6f2b4b4bc0bdd50b2cc0ddb88e65e1b21cabe4b7ea3ff4620ba40dc7d5656a7c412fff72326cf666d0555d6470f6de",
                "D1FD0A9EA4D65D43C584C3845A90078EA0CDE6566459756DCDE50F9875E7A95A"
            ]
        ];
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        for t in tests {
            // build circuit for each test
            let input = hex::decode(t[0]).unwrap();
            let output = hex::decode(t[1]).unwrap();
            let config = CircuitConfig::standard_recursion_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);
            let preimage_target = builder.add_virtual_u32_targets(input.len() / 4);
            let expected_output_target = builder.add_virtual_hash256_target();

            let hash_output = builder.hash_sha256_u32(&preimage_target);
            builder.connect_hash256(hash_output, expected_output_target);

            let num_gates = builder.num_gates();
            let data = builder.build::<C>();
            println!(
                "sha256 ({} bytes) num_gates={}, quotient_degree_factor={}",
                input.len(),
                num_gates,
                data.common.quotient_degree_factor
            );
            let mut pw = PartialWitness::new();
            pw.set_u32_targets(&preimage_target, &bytes_to_u32_vec_be(&input));
            pw.set_hash256_target(&expected_output_target, &output);

            let start_time = std::time::Instant::now();
            let proof = data.prove(pw).unwrap();
            let duration_ms = start_time.elapsed().as_millis();
            println!("sha256 ({} bytes) proved in {}ms", input.len(), duration_ms);

            assert!(data.verify(proof).is_ok());
        }
    }

    fn pad_bytes_u32(data: &[u8]) -> Vec<u8> {
        if data.len() % 4 == 0 {
            return data.to_vec();
        } else {
            let mut padded = data.to_vec();
            let padding = 4 - data.len() % 4;
            for _ in 0..padding {
                padded.push(0);
            }
            return padded;
        }
    }

    fn check_sha_hash(input: &[u8]) {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        // build circuit for each test
        let padded_input = pad_bytes_u32(input);
        let expected_result = CoreSha256Hasher::hash_bytes(input);
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let preimage_target = builder.add_virtual_u32_targets(padded_input.len() / 4);
        let expected_output_target = builder.add_virtual_hash256_target();

        let hash_output =
            sha256_digest_u32_array_with_byte_length(&mut builder, &preimage_target, input.len());
        builder.connect_hash256(hash_output, expected_output_target);
        builder.register_public_inputs(&hash_output.iter().map(|o| o.0).collect::<Vec<_>>());

        //let num_gates = builder.num_gates();
        let data = builder.build::<C>();
        /*println!(
            "sha256 ({} bytes) num_gates={}, quotient_degree_factor={}",
            input.len(),
            num_gates,
            data.common.quotient_degree_factor
        );*/
        let mut pw = PartialWitness::new();
        pw.set_u32_targets(&preimage_target, &bytes_to_u32_vec_be(&padded_input));
        pw.set_hash256_target(&expected_output_target, &expected_result.0);

        let start_time = std::time::Instant::now();
        let proof = data.prove(pw).unwrap();
        let duration_ms = start_time.elapsed().as_millis();
        //println!("sha256 ({} bytes) proved in {}ms", input.len(), duration_ms);
        let result_hash = u32_vec_to_bytes_be(
            &proof
                .public_inputs
                .iter()
                .map(|f| f.to_canonical_u64() as u32)
                .collect::<Vec<_>>(),
        );
        assert_eq!(result_hash, expected_result.0.to_vec());
        println!(
            "[sha256 {} bytes, proved in {}ms] sha256({}) = {} ",
            input.len(),
            duration_ms,
            hex::encode(input),
            hex::encode(result_hash)
        );
        assert!(data.verify(proof).is_ok());
    }

    fn check_pos_hash(input: &[u8]) {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = GoldilocksField;
        // build circuit for each test
        let padded_input = pad_bytes_u32(input);

        let preimage_felt = bytes_to_u32_vec_be(&padded_input)
            .iter()
            .map(|x| GoldilocksField::from_canonical_u64(*x as u64))
            .collect::<Vec<_>>();
        let expected_result = PoseidonHash::hash_no_pad(&preimage_felt);
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let preimage_target = builder.add_virtual_u32_targets(padded_input.len() / 4);
        let expected_output_target = builder.add_virtual_hash();

        let hash_output = builder.hash_n_to_hash_no_pad::<PoseidonHash>(
            preimage_target.iter().map(|x| x.0).collect::<Vec<_>>(),
        );
        builder.connect_hashes(hash_output, expected_output_target);
        builder.register_public_inputs(&hash_output.elements);

        //let num_gates = builder.num_gates();
        let data = builder.build::<C>();
        /*println!(
            "sha256 ({} bytes) num_gates={}, quotient_degree_factor={}",
            input.len(),
            num_gates,
            data.common.quotient_degree_factor
        );*/
        let mut pw = PartialWitness::new();
        pw.set_u32_targets(&preimage_target, &bytes_to_u32_vec_be(&padded_input));
        pw.set_hash_target(expected_output_target, expected_result);

        let start_time = std::time::Instant::now();
        let proof = data.prove(pw).unwrap();
        let duration_ms = start_time.elapsed().as_millis();
        //println!("sha256 ({} bytes) proved in {}ms", input.len(), duration_ms);
        assert_eq!(
            proof.public_inputs.to_vec(),
            expected_result.elements.to_vec()
        );
        println!(
            "[poseidon {} bytes, proved in {}ms] poseidon({}) = {} ",
            input.len(),
            duration_ms,
            hex::encode(input),
            QHashOut(expected_result).to_string()
        );
        assert!(data.verify(proof).is_ok());
    }

    /*

    fn check_sha_hash_dbg(input: &[u8]) {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        // build circuit for each test
        let padded_input = pad_bytes_u32(input);
        let expected_result = CoreSha256Hasher::hash_bytes(input);
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let preimage_target = builder.add_virtual_u32_targets(padded_input.len() / 4);
        let expected_output_target = builder.add_virtual_hash256_target();

        let hash_output =
            sha256_digest_u32_array_with_byte_length(&mut builder, &preimage_target, input.len());
        //builder.connect_hash256(hash_output, expected_output_target);
        builder.register_public_inputs(&hash_output.iter().map(|o| o.0).collect_vec());

        let data = builder.build::<C>();
        /*println!(
            "sha256 ({} bytes) num_gates={}, quotient_degree_factor={}",
            input.len(),
            num_gates,
            data.common.quotient_degree_factor
        );*/
        let mut pw = PartialWitness::new();
        pw.set_u32_targets(&preimage_target, &bytes_to_u32_vec_be(&padded_input));
        pw.set_hash256_target(&expected_output_target, &expected_result.0);

        let start_time = std::time::Instant::now();
        let proof = data.prove(pw).unwrap();
        let duration_ms = start_time.elapsed().as_millis();
        let block_data: Vec<u32> = proof.public_inputs[0..(proof.public_inputs.len() - 8)]
            .to_vec()
            .iter()
            .map(|x| x.to_canonical_u64() as u32)
            .collect();
        let hash_result: Vec<u32> = proof.public_inputs[(proof.public_inputs.len() - 8)..]
            .to_vec()
            .iter()
            .map(|x| x.to_canonical_u64() as u32)
            .collect();
        println!("block_data: {:?}", block_data);
        println!("hash_result: {:?}", hash_result);

        //println!("sha256 ({} bytes) proved in {}ms", input.len(), duration_ms);
        let result_hash = u32_vec_to_bytes_be(
            &proof
                .public_inputs
                .iter()
                .map(|f| f.to_canonical_u64() as u32)
                .collect_vec(),
        );
        //assert_eq!(result_hash, expected_result.0.to_vec());
        println!(
            "[sha256 {} bytes, proved in {}ms] sha256({}) = {} ",
            input.len(),
            duration_ms,
            hex::encode(input),
            hex::encode(result_hash)
        );
        assert!(data.verify(proof).is_ok());
    }
    */

    #[test]
    fn test_sha256_alt_length_hashes() {
        check_sha_hash(&hex::decode("112233445566778899aabbccddeeff").unwrap());
        check_sha_hash(&hex::decode("e215b964d86f7b0991b94b8c25f55d285746ad969d").unwrap());
        check_sha_hash(&hex::decode("33cd9afd9b6d7fd578560cfaf3a9c1f5b25ed1b2103af272c08eb6f1d59ede43b080ae4376be70410b4e705c2dbcc49d93213fa774d2847905453f5200bbaaea36376084f7973f2c6b1d7c437b78aac7e2b2677895c2458b839f0ab36fad7f70637097f145d0136c1d84200887ba42d7d7a5f8c37c5007f74e5a4ee8b79356e68014ce74d60d2cd83c2a5223200df10c86f6769080f7f27c12e4e66bf6cdbeab77df631cf8293fb18b066ec2bb9d99a2").unwrap());
        check_sha_hash(&hex::decode("3133793ab909c2971eb33d5fe0a9aa064cc1ddc79feee4e303bc8c6962365bbf17be47362004346cb57d24799f63a634f0682455b95634b1d541c29210e82f9fbd4519f583afb3f9531c1853fcc49b4440094b87e1e71dc04bd13f1c9259d5d2582f6f74a83e3ff4892e2b56").unwrap());
        check_sha_hash(&hex::decode("969215958dbdd66b3cce8c895170b72a72659eebfee4625e2b275049ebd0b0f007f50f1ca845fa11b5f112bad5b2c7879a21e85c7a0be2e8c814f2c026e55cc137").unwrap());
        check_sha_hash(&hex::decode("8aa202ada9ea5cab2a0c223b9f5a3cbd1cc4b6092ae5ee867b43c8d8af02b33ea23c732a7c75dcf3631c86bd391a085e52a696b4fce90cf062de9f15b1be656362a1e565efabbcfbcd0e3103035ec86d03c056f1a94cce09847268869892a31481a00d323d439c21cf0a5aecd5abfc4369bd154f034f4c9e2a3200b5a867e074249861285b740c5d2bca11a1989ac97742e57358580b9e030fb1758193ab91307bfcfc55905f733e518722490c61b8880a8c3bcb7685d2a84af97b88a5d3090580ae49c80e0dc176585e382eed0f6fb8acfbfb7e2711d8cb3a355ba59c2e137cf4b389042d50e7720c99d2962a1ecde99517c9").unwrap());
        check_sha_hash(&hex::decode("e78d5dfd8d6229c04c727ba6369e41e2ae28b00962bffce0933cb5e06067c96efbe19493a877933f039012684f87fef66af3479afe5271b903a9d5b3aaa486cc683613d898f4f3607e4c8ec06a6733867af8939abd971831977c162001").unwrap());
        check_sha_hash(&hex::decode("7a12f3d7a585f3a7f183b27bdea0552f285eec83f95d8273243f885c9637e591b1b472d1d28bc09160ea148c30352f0b6de764f56ce68862ae89").unwrap());
        check_sha_hash(&hex::decode("1732c9641c3ad37b869e16261e5f8505ff932af565e7f7965bcb2499fa8bf5255984c6d0921da4b3841e09e1e7ef8a783481f7a12da43d098822b12cc148f9248d8e18f1baf3e48a1f9b74832146e223b8320b8de0c8afbed3799e30dca917358913e9fe074c918fa2f6119e2037e22bf5c173743f029cf16a83d010469ea21ea362865d243e643b2fe61b282330940dc115c1b9e7f50f8ae5fed5c01bbc830bca5967e088624f6fcaa117bb62f9c2ad2efb1d9dbce32eaf840f801322713e7a2a39ce1ffae4dca445bf0a7a93aed7d79b84dd6c8a16d521a9c0d399221e559bc00601666d5d2f74920afc6e3658bdc6bc677f66e54862a67d62ad13f735ca287b79007d3acb6ceaf3cf45aeea50c13e474e719d2d03d64314e4b8f475355d8099b2ce7c2fb76ed1f8a647def3c7fb0df402afbe2f").unwrap());
        check_sha_hash(&hex::decode("8049fd72f7f3de2b3bc0a3dacc6f9d7652999c681caaa65f019f79f217f8bc9bef22e835f61987e78e13103c8ea92d1069cb5f592d56377321e4249f338d760ce3c9af6058cb5ef1898af97bb25b4ebf1a130ccf39d67109d31057ea9bbe653726a135c30ac1a157224cea20d9eaddbe40419ea94503ec1170d1b5991f1b1cc33b2ce952c6b7469025c0835da6da18da7af10efa57ce40ffcc0b02cb318716f0930e8ececabd8233ba10ef34a0bb32804801f5e025acc1964fbbde37cda1076b53fd7e3e94db80f4568c66f5ff8a2e5ddd676fbfce5b137f4160a674c356a9a8c9c590f3a2ba1bac7c87d27129b9915b138930915dadba9ac87f55e35a954e49f7fc17df29e44cb4c5ac10cd2a6c42fa62169b").unwrap());
        check_sha_hash(&hex::decode("3d65f1dda3fca05665d80a3e13d00e62fc33d50129b1053b7457c2b8f21d93bc19b288dc7906335fd6b48212cce883ce8923416c4d6f638b669ebc4d3a4425b05b09364be22201b9c481f535dbbe150841068912d5c4225ce919a5cb2537960e3b6b3590a768fa872ffd6e28e847efdec462d1227ff63093d5897b6d8b22691da979860c65b284a109d12e13c1630fbbed08c4b12462f284c501368b35ac8c58b7b22e36bf4c828e1fa5ceda6a61f5e888ee6680ce390ca41f4a5473b4cad6ecf114b5b1846d5bbf75173a8c62081afd14911df6e91f69681a2685cc86e1daa8ccef710036327c7bacff0100250239fc88").unwrap());
        check_sha_hash(&hex::decode("cc63283d11823485fcc3652d7ddc6d02d12716fa2aa5796449f6fd5ed7164ec9369e5513bb9ceaf8b1cf880164c4e321efef51edd0153dff32e8e765946c739d6e1fe5fb16fa88f9d62e3b7fd719013e8589d541a5f1812bb4debafcdb6ab58f9dee8b54c2043f0d729685bc61012b10a2647e04454c9b751aa0d337e6c6c445ce345159eda1ef2519bea1759991e4638a03c6e824e74d5dcd83eba5bd661ad0a4bd1128005a9f9967341c05fde394495518aff11177bbe595da03077a68305a20c38077492bb18348eebe31bd36f3fecfa99ab82c08db0d47950e130dcd77cc82").unwrap());
        check_sha_hash(&hex::decode("bc97b1d90e512a4bce09f959ddc5185ba60c3da5713104e0ca0bba173f7c6874ed935b9431743251d663344924c8fd8701ac261710869a51cbbd3c6fa61b3b445df6d29bed5284be45c7b5ec743fd6a5acad5e4bec9d33e1479942af051e977fe9fbf75306f2b40ce48f53bb928e271191bd7ae7b3e546cfb5218d8d3b2b48a05ea478e87148454703ccab94ba6a01605af4e41dec518e82b75fbf272fd289d82c3a5efd448002c639cd6c626cd854f9742b5e9799b927ed7902d30c36893a67b43c74c8").unwrap());
        check_sha_hash(&hex::decode("6618c44c83bc202d35e605b8396aa1ea75ac19").unwrap());
        check_sha_hash(&hex::decode("23e1f85bfc6ca3d6fa455a9f291637921c09c8b4f4aaac5d1fc6d425ca6908da3fc79c88ca811424173c76c07ba203739063dc8eba389b31553f5a62f1d6c3446456eb081f3b0bcb098564ffe58e66277abf8218a8a75efe47df07e50d3941559cbf2a9298a9932b5b84d487b330386b5f39aa0673e9fba104b7b5a32bca76be24db698cc114b3e8a0d4aee6780abb03b11c740cb1096dc582fde3ed5134cce5a8f385f47849bb9c6518dba069b8601cad176e0ce4854044d4f0f3028ad9c86015c4d7e5191a70b3e3943a49883bd5b3706d5438d406aaa21976ec704099007a513ccdbb631c2150b7c9aa16b8f9ebc7f4e02fb75ec8dd49333e156caff27c22a0a5bcbefb2828d5edf0c1352cb357fbd6d8b893").unwrap());
        check_sha_hash(&hex::decode("502220c397c8268432251e768d23c59555be2e5e1b27bba40799d4bac3d4f368bb398a652f22da827610d6dcc9fd7a02169999c5a076e94d2735ffd26575966aa7efa2a487a816a16e36fab6295952aa30dc58a59f52012fd357007ec4c598d1444ff9ed5e1c4d31aef39374a068af67be615afd5dbf71e8734a2f5ab578ab864c1b37d83629cea24c155ccf36408e89942e5a07d10da7b2f0b01896501c9ce870f7fd231240d9144236a1651ca5f2e658502e077c5c5331434d6825a97d02d9ef81d7e3295ee7303eb6b3967ff0b2de2351ebd16b4c1eb4b1c1df63").unwrap());
        check_sha_hash(&hex::decode("02181df5ce6eeabf3728793afef0bb748b6806003b799ff2991b09c970bf0b0080dd15f127df85e02189e0f3f1e2aca4047c8268bc9aabe61445cdde15220d644851a94808903187d6876b33f072aecd747dc423b1da541f3effd585ffffaabb").unwrap());
        check_sha_hash(&hex::decode("1732c9641c3ad37b869e16261e5f8505ff932af565e7f7965bcb2499fa8bf5255984c6d0921da4b3841e09e1e7ef8a783481f7a12da43d098822b12cc148f9248d8e18f1baf3e48a1f9b74832146e223b8320b8de0c8afbed3799e30dca917358913e9fe074c918fa2f6119e2037e22bf5c173743f029cf16a83d010469ea21ea362865d243e643b2fe61b282330940dc115c1b9e7f50f8ae5fed5c01bbc830bca5967e088624f6fcaa117bb62f9c2ad2efb1d9dbce32eaf840f801322713e7a2a39ce1ffae4dca445bf0a7a93aed7d79b84dd6c8a16d521a9c0d399221e559bc00601666d5d2f74920afc6e3658bdc6bc677f66e54862a67d62ad13f735ca287b79007d3acb6ceaf3cf45aeea50c13e474e719d2d03d64314e4b8f475355d8099b2ce7c2fb76ed1f8a647def3c7fb0df402afbe2faabbccdd").unwrap());
        check_sha_hash(&hex::decode("bed8c54bf955c8d2b928b04f3b71fb48602a946c5adbeaf91491e1fdda594319901e06e39e8554ddbd941fbae2f32e2f81e3d33176de2892b72e9ecfd98336a0d9b186be5051e6c7078ce6306ccd852b7c6d644936d8c16d5bb7da658c1e6cc85748d8e828d24ecde3f4907d170e3851c716291edcbb8d479a115087bb4e0feef172894603213bac041a40c438a4550f02c152747c65ebdfd449c6e13f457f24b8f1b72d398ea8c91fc18f3e8a28c4a20a255e93badc8084591108db772a33ad49bfed389174580663a54bfd5884cb4c4a864b66fc0590d547373a37a3a64c2125d86be648c3f830dedbe743dd531810c85132a1dd90da1613850f94ad781c48b5bd0ee5eea9f40bfbfd3bf9a0e7214b49c7cdade3adb699d78df9f1252347d8ea5ba4b682d77916a7edca88dff3d7bf6c6fba6850e8f925a7d01e995eee8775b907ec3154dc0e2803ba358741902ef541c9441bd79001e68b32e2a217e5b28cb2d8ffd9752358de6ee548fd7eccae167ccda0a8e016be002cc39715efdbfe89b51e029483ad02de2c5fa224396de158411ebecf3675d6b3a844cd7cf6ee2337310c39ca1694391600b5d6a52c6f9bdbd5262e9e6b35f5b73e84a7f54395b3420596c2f760e353c2f39682ab6e26728aff7ab4fe58f64e5298fd535135d6f9871b9f1dbbdb55aa0e1380936794cfd983bc46d8c49fbc599a0ce8c6e852e050ed88a951a9611a590058a9daf96fca71f2b4442e332aa6588ff14fde48dcf026f02cd7b6c04adbfcb06f5f5e986c5c500231611e98dc14ace404b59163b773f0cb38d1060107451c24d2e8a8e446c9df7d4225a0fcdfc00f8e0f8c2d1deaa8d24d58521352f361188d1c5ab5c4bedf7ebb5551e1f3c3b0254b52463116c9449a2791d825456c2f46e1dc6a25e8c892950626f5c85c4dbda14a8ed517ea9656465bd1fc600e6c6c1666fa831e30045c67104174bcab89e38f6cf29257012e3420a220e22be799adcaea8994224a0e7c534d6a2ed216177b79ec61030c3f70d563e299a9363303a76811490d56890378f595f0a521886acbf5e7c63aec1d075fa2eb1e06e379540acbe26df1eed848bc4af61d7afb683dac1534b4b7e9d54e6e19013f3c324f28f7067aec3c8517ff0a698646c47e19656b00c4a484a1b27725aa46a8343c609e37b4d536c26e5c283318079252c57eb28153a407d445fce683df5fc2ad96e3ab861cd192cb9b9b73aa6514f14d9247f9251f4945ac078fda5a967f4f1dea4be670142eaf765d0b246308cacad14867a87d512c1542f1d4df44f419e67ae4d7e1775744a957d36e9019f19dcfdc86234b4abde0aecb4e4e5f02311ad286d68e39b34ab93fdf7ebfefd90fb1c36b710666b1a786de85accdc1e46b8572070c88e78e1eda2e0ceaff10cb2ecad11f878ffbfe10010dcbb88ffc01ab0eaa5f8eb3f4a3901a30555635af34e3187eab829003cdba311ba1bd131dda7ee485dda0836d41d2b398eddaa890efb25fe396b28680e343cb937cbe73b0067738169943e1f6098f8d4635b0e582887cdbfe50a2b8e5174fbe24ac781de9765353e1700a01ad850c9fbe0b178c5bea73a8a420c84ca175769cc37b9b1f8648e3a814666b91b7130ddc6761832a54e3d5d05c3e7b1e4faf9fae636a79212eaf0b832f25098b11d35ed1f2105820e1447ffb88df66be340a2717e1d363fbe6f7bdd49657b4e02effbcc937dcd0f03bc4afe5507b7aea986f76822932bac54a8a1a8c2f353de6dff3312ed1918e49b4dca176666b4b1a2c2394afef109bce3e64bf8f46d490e68eca2650edbcc17021730b79afa27f3bc9aeb82d98f9665cc8fbe14f8e8001864b574c1439ca94aa6732bca8f592426a45ad3122c8070bdd13223bf087964e02469c2a4868c246a0ad4275b80afb6d22ca1b5c3ec0b7606ad97ab4bbec9962547552c1b052c5e67e0ee103864d1065d61de5b1e59ea317791c7aa956b9dbbfee1d482e1320e87b52daa315fd9a1c87a27ad6deb04de10a13f11b343b0a554e56a6989c2e6256b508a0b242bea8ff7f19671960120cf8ab29141e3a8802cbe6fe77dfd0be33547bb6b0a76b3346a5a320a038d977cd88b17a68a0bda75786c3ebc485654e2e32b5cbd16ebda4a6c0c6a69634354348f7f866ed5ad0ef1836774eaf22239af5a026006406fb286963087162142b238a817590d146f94364991cd508cab46774fe5bb2beda30dda89625b1e47d24d5b3b6ecf39749656e08d2ef3e026584e0aa3dde04b0388358b77a23c5dc74baecd648a8ee7caedaa9c32e91bb621b6fa48dff6ff24321cced7beaf5f2693b559259f18fef6a42ecbc852e08daf12088a643e9091ee32503412622191e3ca3c50a8fb7282834af0c142835654c2ba63efcee0bba6e1cc8fd620e38f1d0b6c2b4fe8cefa9e60556a97a95b6c6295c87b96e2c5ce9504632cc9c18d97f701d5ae9e0b01b1ebf7fd78896128caeb82616c391c623661f964363254ec05c0513251d95529823c6b5d49cb123f3b1b8fb829c7628f9318ba00f5fac22a8a387ee7af2cf27fab4a6ed9fd51d45ebecd6b9eae6879e494e538ec3c15235424b1b5b3aaccf01af3b57d231b20df0546862ef9c5f3fc3c85d18d48305ffc1b1dda6e1228319a0110f6c0181f7fa39e47ab7e298a74753e6a79123c7af41cc0f4f642f087083ef3068f7f61a0da1dd9d035d4fd7a02c5d762b493afcdf422853668beb8893d3946b5a28cc772c3bb4e07ab1ba6d966cf1499da19f92302300f3c4dd8a0b47c10becdaec2cb36ad7dc10a7c35b4d7be10505af02d8fc0539546790c84d22b4fcf1f5bcfd97a556577c25aa56ebffdc45c1feb1f3b75232d6483c0946fca1ddab793b5615d7d46399f11a5c27fbb2ef95d4dfebab588cd1b174627bb15089831a9f5a11dd7b787535e631486991e9aa777f7603a1edeb065fad17f17228a3dbaaa1f4f467f43048484cdd2a8e0c9d8357ca9d90c44e2960a1f50a105e36fe3c462021033c859b1d24069a021b59402065000b784e38656f5a3927af5f9a6ca56dcc725d9f07e818427757b6056711792d1e7e37ae3c937158990fe87c177a524898d6dbbea6a2adae60c39da46dfbc8f01e7d3f198f7ba809636fba94f6a49b4792b41b7aa3928ac15002aab90289af404dc52b6708b8601867ae7a05ffbdfe3e4d97c171c6c7534294879023a66792dc7d7f67af5b0c42445a23ecd5703bc1719177e7f9fef8e15b51998a0c5e5ebb300e02416c1afd949638dc237c5d139dd894db4500c25210f39ad69b45d971d902cbcca3cf5af3c0b0e11b96f2e318ef3ac4be979fd65a186a5523ae861d5088efa9a046aab5f9b0c66fb1905e033ced9e763d0664b85755032c6680b04c8e8ab295c8ccdbf0451ad69a75fa53a729c1e85e68a34f0375d516f5b550aa594b2863fccd27bbccbf01379a2f1b212913c314bb02b499ee3085cd5d3adcc6cbd0cbc9f6297b6707d8bdcbed2640fd4ae14ff2464b5d786ea1c73a0cf1010dc14c6f68a4a358df60f82d8fc8e8f0454f7d898c0234e4719fc9cddf5240679dfe78559c8b6188bab25c62119329870efa9030c9c007e2ed189d0fe7cd4bd2b12792d2c78bf0d3dba51cec3d4f1e34d771c750b183488c89d6bb44bcf9220ed06ae0149a59108604619c6fc6d8b9ca27369e3fa087176fb8431b61648f98e69c9d17d2e49730835c3836001cf4eade47ed13f42b9dba9bcf09a6bf45509af00541771da524322ca2af2e2ef020e905e1de0899ef1433c3e57c8ec4e8aa3d9a88bfbe633e9d318a7d6284d60f6024ab59203a13df91e6df9d7eb9717630feffd9ebff869a06c41091bdc13c8982720348c33bd22c63963d6283f77b26ffb06d9960c3c28f3428ae2064352e0fb074b5107a7ac0670b26edaf3cbede0f9bb53713645d42fd243db5d40400d71afe918fadd3c1dc296da528275f6f4f8cab9816c205ad110a4c3d703cf20af1539252a6a1bff052f86ed050dea0a0d7a6f532a9739b064a77309e0c6a0aa2707ca7dd02593f03c3eb2d0170296cf8c1decd788907c6755a8ff0e0aeda0df3ff11157c05a30498686353755d563817ac94b163de9004f551350f4f84b75a2cada669ccc9b9371e4160724bb10e3b6f7398347bde4aaccd2257bea3e9fa6e730e41eda26d261685ce9e5289676020cddbaa6ba46f93649c80ff3de380f4ded991ac020bd7a3420bc60501fccaa8716e321f1d8f461932f9b58c5b37aa620bc949d8a9731f62fb0f6ab2e2ed25a987590d517d15c5d3d0f4f4e6d76cdc78679452655a653db5dc2987e25ff87d5658414d1f046cc0cc6b0a648dcc837222290c9310b8a64231bbe9a8d39c78a556a7d1db7840cce358d0b2d4865ff9cce174de151e507b03ee0b26fd61f3dc3263417fab777c589fc58905bbf49651c96a3e830d08176ff3377daf2d67c9e9c7e9fbf4289c3f434d83897cc1b9d47b596e8356e737de00af886784c0c54ddc247d85b69f3cec4ed0ee5373f158366c962a102669a97f649c24472337b9dd95a1934b69fffddb3022a4a3bf51b0832b0bcff018b2ea10c28dae44fc8da0cb75fa36d6d0c66ead482e64959de3009c5dae0f6510fe45767d02f29e8eec513260dfcac236fe70fc3724cdc2620e08967b6fdfe6a4601ecd865f8dbcc224952e515bb9cf40df1de2e20e094b9c63eca42a2e40469c6c3c76193692b10151acfcb0113b23224698ddba09b622f6eb3e5cee3ae2c155a2d8658d2efd998c4a437a5d5033f8865dd4050b8b7bbd592cd31c89a624f4b9ffba5bf42e235196a480c5245fd18d576ca962c770a0748e4f0e754727ddfd340b4d13e02c8ba0020b1fd8402a9686bd8477bab8e6ba75bfe0cf6814c9b83717bb88ff66c849ac49abd523cfc90235e235ee46e44fab4f8bff63e67e19480ceed4316b505a3e6ad8050d263f9c0fba30e9f24a938f30234df9f1e91f046acdecf0955b7bd94c126ebfc217daa9a941def674d7c0eec7d4ef04b31ec1d992603d7bd1c08e28f7478c7540865e8aaac58a1a7f17b87a80fdf2c7c13180d8fbfefb22ee2dc21a06b3cd2b44f66077d29bfa52e62ee88ee9ccb39d4a1f1edb5eee64752efc62e5eddf8067ed9451a37bfedfc8efd6ba62fc12e474f5022f40fb672a895471e58c3dfc5d129885ec25cbe69f93e5e91b1a8cdd0f6ab32cad99f47c62b5596ab2187c41654442e0f41cc9ab14eef5a8c13babcd2930913629d43377d50724a1682e2d383785cf898f94137b2c5a3af291df888f30438b807b4a76294c976e34daac162db5b49c41d85bd070163d50044244ea4595f14e2cfe7c7490d1d0eb37d459601ae138b1f11661705f284eebc5b64132df091c0cf699d6bb810f54e8afa437d7d493b9b3ebd88b1d3497a4ae95df460563b6f9f7c0b3eb21f5caf86877b91e8654dbd3cb091ebac46ca2e919214bfa739ff0dfcc274bc488c090db960a8a464e0466726fc005c22321908072a874312418a1afde7db37342cd1f43cdd078bc1a3c9c689a1cf84767570d0589a9b100566aa2d93d7178cd7ba87651876d13a566ae6249f671a413fb6fdacb948d905a43e3eacd017dfd575537bf077cd70ff4b862558b304a391484192112c7a632202704061823bbe3bb1ed09f38cc5ccf4f510b5783446d640026eee29c93f94b8e2dbf287d1f41f3d86453b7c9aa99041c0498458c9687403a875162f69c1ac299d43ac47e6c482d8460c25c52cb6774448cc5530ea3bde0a4bdd71b15702f5c1aa5618e216bd9ffa9692fecbf026fabc0bdd39fdeeb1729fc055ec348ec55eb6506e5c342b574cd1b4667aec1f8a155a8509ee31e79a1ab903c93757626e5f97ee8aa27853a505790d84879c82c96003703a840de3e7fa63cac55bc6b33f028f5c3e799997b8b6152cbf0a02d3b0df2f5d1c31a2987740302607f64018187ba0d1233984a1debd78e90e1574a356ff134cc0c6280c1332be04c78e08c72510f987e1381b584fa366afe7ed02e8513b45674b071417a113b78e2a7e4513be63ebc4f2064efe3b10fd7c41d257ee98279f88afdd483717a2cfba4dd0f7511e68076f078bbe61a74a8a29bfcdf57df3fef5f78a1").unwrap());
    }
    #[test]
    fn test_sha256_long_len() {
        check_sha_hash(&hex::decode("bed8c54bf955c8d2b928b04f3b71fb48602a946c5adbeaf91491e1fdda594319901e06e39e8554ddbd941fbae2f32e2f81e3d33176de2892b72e9ecfd98336a0d9b186be5051e6c7078ce6306ccd852b7c6d644936d8c16d5bb7da658c1e6cc85748d8e828d24ecde3f4907d170e3851c716291edcbb8d479a115087bb4e0feef172894603213bac041a40c438a4550f02c152747c65ebdfd449c6e13f457f24b8f1b72d398ea8c91fc18f3e8a28c4a20a255e93badc8084591108db772a33ad49bfed389174580663a54bfd5884cb4c4a864b66fc0590d547373a37a3a64c2125d86be648c3f830dedbe743dd531810c85132a1dd90da1613850f94ad781c48b5bd0ee5eea9f40bfbfd3bf9a0e7214b49c7cdade3adb699d78df9f1252347d8ea5ba4b682d77916a7edca88dff3d7bf6c6fba6850e8f925a7d01e995eee8775b907ec3154dc0e2803ba358741902ef541c9441bd79001e68b32e2a217e5b28cb2d8ffd9752358de6ee548fd7eccae167ccda0a8e016be002cc39715efdbfe89b51e029483ad02de2c5fa224396de158411ebecf3675d6b3a844cd7cf6ee2337310c39ca1694391600b5d6a52c6f9bdbd5262e9e6b35f5b73e84a7f54395b3420596c2f760e353c2f39682ab6e26728aff7ab4fe58f64e5298fd535135d6f9871b9f1dbbdb55aa0e1380936794cfd983bc46d8c49fbc599a0ce8c6e852e050ed88a951a9611a590058a9daf96fca71f2b4442e332aa6588ff14fde48dcf026f02cd7b6c04adbfcb06f5f5e986c5c500231611e98dc14ace404b59163b773f0cb38d1060107451c24d2e8a8e446c9df7d4225a0fcdfc00f8e0f8c2d1deaa8d24d58521352f361188d1c5ab5c4bedf7ebb5551e1f3c3b0254b52463116c9449a2791d825456c2f46e1dc6a25e8c892950626f5c85c4dbda14a8ed517ea9656465bd1fc600e6c6c1666fa831e30045c67104174bcab89e38f6cf29257012e3420a220e22be799adcaea8994224a0e7c534d6a2ed216177b79ec61030c3f70d563e299a9363303a76811490d56890378f595f0a521886acbf5e7c63aec1d075fa2eb1e06e379540acbe26df1eed848bc4af61d7afb683dac1534b4b7e9d54e6e19013f3c324f28f7067aec3c8517ff0a698646c47e19656b00c4a484a1b27725aa46a8343c609e37b4d536c26e5c283318079252c57eb28153a407d445fce683df5fc2ad96e3ab861cd192cb9b9b73aa6514f14d9247f9251f4945ac078fda5a967f4f1dea4be670142eaf765d0b246308cacad14867a87d512c1542f1d4df44f419e67ae4d7e1775744a957d36e9019f19dcfdc86234b4abde0aecb4e4e5f02311ad286d68e39b34ab93fdf7ebfefd90fb1c36b710666b1a786de85accdc1e46b8572070c88e78e1eda2e0ceaff10cb2ecad11f878ffbfe10010dcbb88ffc01ab0eaa5f8eb3f4a3901a30555635af34e3187eab829003cdba311ba1bd131dda7ee485dda0836d41d2b398eddaa890efb25fe396b28680e343cb937cbe73b0067738169943e1f6098f8d4635b0e582887cdbfe50a2b8e5174fbe24ac781de9765353e1700a01ad850c9fbe0b178c5bea73a8a420c84ca175769cc37b9b1f8648e3a814666b91b7130ddc6761832a54e3d5d05c3e7b1e4faf9fae636a79212eaf0b832f25098b11d35ed1f2105820e1447ffb88df66be340a2717e1d363fbe6f7bdd49657b4e02effbcc937dcd0f03bc4afe5507b7aea986f76822932bac54a8a1a8c2f353de6dff3312ed1918e49b4dca176666b4b1a2c2394afef109bce3e64bf8f46d490e68eca2650edbcc17021730b79afa27f3bc9aeb82d98f9665cc8fbe14f8e8001864b574c1439ca94aa6732bca8f592426a45ad3122c8070bdd13223bf087964e02469c2a4868c246a0ad4275b80afb6d22ca1b5c3ec0b7606ad97ab4bbec9962547552c1b052c5e67e0ee103864d1065d61de5b1e59ea317791c7aa956b9dbbfee1d482e1320e87b52daa315fd9a1c87a27ad6deb04de10a13f11b343b0a554e56a6989c2e6256b508a0b242bea8ff7f19671960120cf8ab29141e3a8802cbe6fe77dfd0be33547bb6b0a76b3346a5a320a038d977cd88b17a68a0bda75786c3ebc485654e2e32b5cbd16ebda4a6c0c6a69634354348f7f866ed5ad0ef1836774eaf22239af5a026006406fb286963087162142b238a817590d146f94364991cd508cab46774fe5bb2beda30dda89625b1e47d24d5b3b6ecf39749656e08d2ef3e026584e0aa3dde04b0388358b77a23c5dc74baecd648a8ee7caedaa9c32e91bb621b6fa48dff6ff24321cced7beaf5f2693b559259f18fef6a42ecbc852e08daf12088a643e9091ee32503412622191e3ca3c50a8fb7282834af0c142835654c2ba63efcee0bba6e1cc8fd620e38f1d0b6c2b4fe8cefa9e60556a97a95b6c6295c87b96e2c5ce9504632cc9c18d97f701d5ae9e0b01b1ebf7fd78896128caeb82616c391c623661f964363254ec05c0513251d95529823c6b5d49cb123f3b1b8fb829c7628f9318ba00f5fac22a8a387ee7af2cf27fab4a6ed9fd51d45ebecd6b9eae6879e494e538ec3c15235424b1b5b3aaccf01af3b57d231b20df0546862ef9c5f3fc3c85d18d48305ffc1b1dda6e1228319a0110f6c0181f7fa39e47ab7e298a74753e6a79123c7af41cc0f4f642f087083ef3068f7f61a0da1dd9d035d4fd7a02c5d762b493afcdf422853668beb8893d3946b5a28cc772c3bb4e07ab1ba6d966cf1499da19f92302300f3c4dd8a0b47c10becdaec2cb36ad7dc10a7c35b4d7be10505af02d8fc0539546790c84d22b4fcf1f5bcfd97a556577c25aa56ebffdc45c1feb1f3b75232d6483c0946fca1ddab793b5615d7d46399f11a5c27fbb2ef95d4dfebab588cd1b174627bb15089831a9f5a11dd7b787535e631486991e9aa777f7603a1edeb065fad17f17228a3dbaaa1f4f467f43048484cdd2a8e0c9d8357ca9d90c44e2960a1f50a105e36fe3c462021033c859b1d24069a021b59402065000b784e38656f5a3927af5f9a6ca56dcc725d9f07e818427757b6056711792d1e7e37ae3c937158990fe87c177a524898d6dbbea6a2adae60c39da46dfbc8f01e7d3f198f7ba809636fba94f6a49b4792b41b7aa3928ac15002aab90289af404dc52b6708b8601867ae7a05ffbdfe3e4d97c171c6c7534294879023a66792dc7d7f67af5b0c42445a23ecd5703bc1719177e7f9fef8e15b51998a0c5e5ebb300e02416c1afd949638dc237c5d139dd894db4500c25210f39ad69b45d971d902cbcca3cf5af3c0b0e11b96f2e318ef3ac4be979fd65a186a5523ae861d5088efa9a046aab5f9b0c66fb1905e033ced9e763d0664b85755032c6680b04c8e8ab295c8ccdbf0451ad69a75fa53a729c1e85e68a34f0375d516f5b550aa594b2863fccd27bbccbf01379a2f1b212913c314bb02b499ee3085cd5d3adcc6cbd0cbc9f6297b6707d8bdcbed2640fd4ae14ff2464b5d786ea1c73a0cf1010dc14c6f68a4a358df60f82d8fc8e8f0454f7d898c0234e4719fc9cddf5240679dfe78559c8b6188bab25c62119329870efa9030c9c007e2ed189d0fe7cd4bd2b12792d2c78bf0d3dba51cec3d4f1e34d771c750b183488c89d6bb44bcf9220ed06ae0149a59108604619c6fc6d8b9ca27369e3fa087176fb8431b61648f98e69c9d17d2e49730835c3836001cf4eade47ed13f42b9dba9bcf09a6bf45509af00541771da524322ca2af2e2ef020e905e1de0899ef1433c3e57c8ec4e8aa3d9a88bfbe633e9d318a7d6284d60f6024ab59203a13df91e6df9d7eb9717630feffd9ebff869a06c41091bdc13c8982720348c33bd22c63963d6283f77b26ffb06d9960c3c28f3428ae2064352e0fb074b5107a7ac0670b26edaf3cbede0f9bb53713645d42fd243db5d40400d71afe918fadd3c1dc296da528275f6f4f8cab9816c205ad110a4c3d703cf20af1539252a6a1bff052f86ed050dea0a0d7a6f532a9739b064a77309e0c6a0aa2707ca7dd02593f03c3eb2d0170296cf8c1decd788907c6755a8ff0e0aeda0df3ff11157c05a30498686353755d563817ac94b163de9004f551350f4f84b75a2cada669ccc9b9371e4160724bb10e3b6f7398347bde4aaccd2257bea3e9fa6e730e41eda26d261685ce9e5289676020cddbaa6ba46f93649c80ff3de380f4ded991ac020bd7a3420bc60501fccaa8716e321f1d8f461932f9b58c5b37aa620bc949d8a9731f62fb0f6ab2e2ed25a987590d517d15c5d3d0f4f4e6d76cdc78679452655a653db5dc2987e25ff87d5658414d1f046cc0cc6b0a648dcc837222290c9310b8a64231bbe9a8d39c78a556a7d1db7840cce358d0b2d4865ff9cce174de151e507b03ee0b26fd61f3dc3263417fab777c589fc58905bbf49651c96a3e830d08176ff3377daf2d67c9e9c7e9fbf4289c3f434d83897cc1b9d47b596e8356e737de00af886784c0c54ddc247d85b69f3cec4ed0ee5373f158366c962a102669a97f649c24472337b9dd95a1934b69fffddb3022a4a3bf51b0832b0bcff018b2ea10c28dae44fc8da0cb75fa36d6d0c66ead482e64959de3009c5dae0f6510fe45767d02f29e8eec513260dfcac236fe70fc3724cdc2620e08967b6fdfe6a4601ecd865f8dbcc224952e515bb9cf40df1de2e20e094b9c63eca42a2e40469c6c3c76193692b10151acfcb0113b23224698ddba09b622f6eb3e5cee3ae2c155a2d8658d2efd998c4a437a5d5033f8865dd4050b8b7bbd592cd31c89a624f4b9ffba5bf42e235196a480c5245fd18d576ca962c770a0748e4f0e754727ddfd340b4d13e02c8ba0020b1fd8402a9686bd8477bab8e6ba75bfe0cf6814c9b83717bb88ff66c849ac49abd523cfc90235e235ee46e44fab4f8bff63e67e19480ceed4316b505a3e6ad8050d263f9c0fba30e9f24a938f30234df9f1e91f046acdecf0955b7bd94c126ebfc217daa9a941def674d7c0eec7d4ef04b31ec1d992603d7bd1c08e28f7478c7540865e8aaac58a1a7f17b87a80fdf2c7c13180d8fbfefb22ee2dc21a06b3cd2b44f66077d29bfa52e62ee88ee9ccb39d4a1f1edb5eee64752efc62e5eddf8067ed9451a37bfedfc8efd6ba62fc12e474f5022f40fb672a895471e58c3dfc5d129885ec25cbe69f93e5e91b1a8cdd0f6ab32cad99f47c62b5596ab2187c41654442e0f41cc9ab14eef5a8c13babcd2930913629d43377d50724a1682e2d383785cf898f94137b2c5a3af291df888f30438b807b4a76294c976e34daac162db5b49c41d85bd070163d50044244ea4595f14e2cfe7c7490d1d0eb37d459601ae138b1f11661705f284eebc5b64132df091c0cf699d6bb810f54e8afa437d7d493b9b3ebd88b1d3497a4ae95df460563b6f9f7c0b3eb21f5caf86877b91e8654dbd3cb091ebac46ca2e919214bfa739ff0dfcc274bc488c090db960a8a464e0466726fc005c22321908072a874312418a1afde7db37342cd1f43cdd078bc1a3c9c689a1cf84767570d0589a9b100566aa2d93d7178cd7ba87651876d13a566ae6249f671a413fb6fdacb948d905a43e3eacd017dfd575537bf077cd70ff4b862558b304a391484192112c7a632202704061823bbe3bb1ed09f38cc5ccf4f510b5783446d640026eee29c93f94b8e2dbf287d1f41f3d86453b7c9aa99041c0498458c9687403a875162f69c1ac299d43ac47e6c482d8460c25c52cb6774448cc5530ea3bde0a4bdd71b15702f5c1aa5618e216bd9ffa9692fecbf026fabc0bdd39fdeeb1729fc055ec348ec55eb6506e5c342b574cd1b4667aec1f8a155a8509ee31e79a1ab903c93757626e5f97ee8aa27853a505790d84879c82c96003703a840de3e7fa63cac55bc6b33f028f5c3e799997b8b6152cbf0a02d3b0df2f5d1c31a2987740302607f64018187ba0d1233984a1debd78e90e1574a356ff134cc0c6280c1332be04c78e08c72510f987e1381b584fa366afe7ed02e8513b45674b071417a113b78e2a7e4513be63ebc4f2064efe3b10fd7c41d257ee98279f88afdd483717a2cfba4dd0f7511e68076f078bbe61a74a8a29bfcdf57df3fef5f78a1").unwrap());
        check_pos_hash(&hex::decode("bed8c54bf955c8d2b928b04f3b71fb48602a946c5adbeaf91491e1fdda594319901e06e39e8554ddbd941fbae2f32e2f81e3d33176de2892b72e9ecfd98336a0d9b186be5051e6c7078ce6306ccd852b7c6d644936d8c16d5bb7da658c1e6cc85748d8e828d24ecde3f4907d170e3851c716291edcbb8d479a115087bb4e0feef172894603213bac041a40c438a4550f02c152747c65ebdfd449c6e13f457f24b8f1b72d398ea8c91fc18f3e8a28c4a20a255e93badc8084591108db772a33ad49bfed389174580663a54bfd5884cb4c4a864b66fc0590d547373a37a3a64c2125d86be648c3f830dedbe743dd531810c85132a1dd90da1613850f94ad781c48b5bd0ee5eea9f40bfbfd3bf9a0e7214b49c7cdade3adb699d78df9f1252347d8ea5ba4b682d77916a7edca88dff3d7bf6c6fba6850e8f925a7d01e995eee8775b907ec3154dc0e2803ba358741902ef541c9441bd79001e68b32e2a217e5b28cb2d8ffd9752358de6ee548fd7eccae167ccda0a8e016be002cc39715efdbfe89b51e029483ad02de2c5fa224396de158411ebecf3675d6b3a844cd7cf6ee2337310c39ca1694391600b5d6a52c6f9bdbd5262e9e6b35f5b73e84a7f54395b3420596c2f760e353c2f39682ab6e26728aff7ab4fe58f64e5298fd535135d6f9871b9f1dbbdb55aa0e1380936794cfd983bc46d8c49fbc599a0ce8c6e852e050ed88a951a9611a590058a9daf96fca71f2b4442e332aa6588ff14fde48dcf026f02cd7b6c04adbfcb06f5f5e986c5c500231611e98dc14ace404b59163b773f0cb38d1060107451c24d2e8a8e446c9df7d4225a0fcdfc00f8e0f8c2d1deaa8d24d58521352f361188d1c5ab5c4bedf7ebb5551e1f3c3b0254b52463116c9449a2791d825456c2f46e1dc6a25e8c892950626f5c85c4dbda14a8ed517ea9656465bd1fc600e6c6c1666fa831e30045c67104174bcab89e38f6cf29257012e3420a220e22be799adcaea8994224a0e7c534d6a2ed216177b79ec61030c3f70d563e299a9363303a76811490d56890378f595f0a521886acbf5e7c63aec1d075fa2eb1e06e379540acbe26df1eed848bc4af61d7afb683dac1534b4b7e9d54e6e19013f3c324f28f7067aec3c8517ff0a698646c47e19656b00c4a484a1b27725aa46a8343c609e37b4d536c26e5c283318079252c57eb28153a407d445fce683df5fc2ad96e3ab861cd192cb9b9b73aa6514f14d9247f9251f4945ac078fda5a967f4f1dea4be670142eaf765d0b246308cacad14867a87d512c1542f1d4df44f419e67ae4d7e1775744a957d36e9019f19dcfdc86234b4abde0aecb4e4e5f02311ad286d68e39b34ab93fdf7ebfefd90fb1c36b710666b1a786de85accdc1e46b8572070c88e78e1eda2e0ceaff10cb2ecad11f878ffbfe10010dcbb88ffc01ab0eaa5f8eb3f4a3901a30555635af34e3187eab829003cdba311ba1bd131dda7ee485dda0836d41d2b398eddaa890efb25fe396b28680e343cb937cbe73b0067738169943e1f6098f8d4635b0e582887cdbfe50a2b8e5174fbe24ac781de9765353e1700a01ad850c9fbe0b178c5bea73a8a420c84ca175769cc37b9b1f8648e3a814666b91b7130ddc6761832a54e3d5d05c3e7b1e4faf9fae636a79212eaf0b832f25098b11d35ed1f2105820e1447ffb88df66be340a2717e1d363fbe6f7bdd49657b4e02effbcc937dcd0f03bc4afe5507b7aea986f76822932bac54a8a1a8c2f353de6dff3312ed1918e49b4dca176666b4b1a2c2394afef109bce3e64bf8f46d490e68eca2650edbcc17021730b79afa27f3bc9aeb82d98f9665cc8fbe14f8e8001864b574c1439ca94aa6732bca8f592426a45ad3122c8070bdd13223bf087964e02469c2a4868c246a0ad4275b80afb6d22ca1b5c3ec0b7606ad97ab4bbec9962547552c1b052c5e67e0ee103864d1065d61de5b1e59ea317791c7aa956b9dbbfee1d482e1320e87b52daa315fd9a1c87a27ad6deb04de10a13f11b343b0a554e56a6989c2e6256b508a0b242bea8ff7f19671960120cf8ab29141e3a8802cbe6fe77dfd0be33547bb6b0a76b3346a5a320a038d977cd88b17a68a0bda75786c3ebc485654e2e32b5cbd16ebda4a6c0c6a69634354348f7f866ed5ad0ef1836774eaf22239af5a026006406fb286963087162142b238a817590d146f94364991cd508cab46774fe5bb2beda30dda89625b1e47d24d5b3b6ecf39749656e08d2ef3e026584e0aa3dde04b0388358b77a23c5dc74baecd648a8ee7caedaa9c32e91bb621b6fa48dff6ff24321cced7beaf5f2693b559259f18fef6a42ecbc852e08daf12088a643e9091ee32503412622191e3ca3c50a8fb7282834af0c142835654c2ba63efcee0bba6e1cc8fd620e38f1d0b6c2b4fe8cefa9e60556a97a95b6c6295c87b96e2c5ce9504632cc9c18d97f701d5ae9e0b01b1ebf7fd78896128caeb82616c391c623661f964363254ec05c0513251d95529823c6b5d49cb123f3b1b8fb829c7628f9318ba00f5fac22a8a387ee7af2cf27fab4a6ed9fd51d45ebecd6b9eae6879e494e538ec3c15235424b1b5b3aaccf01af3b57d231b20df0546862ef9c5f3fc3c85d18d48305ffc1b1dda6e1228319a0110f6c0181f7fa39e47ab7e298a74753e6a79123c7af41cc0f4f642f087083ef3068f7f61a0da1dd9d035d4fd7a02c5d762b493afcdf422853668beb8893d3946b5a28cc772c3bb4e07ab1ba6d966cf1499da19f92302300f3c4dd8a0b47c10becdaec2cb36ad7dc10a7c35b4d7be10505af02d8fc0539546790c84d22b4fcf1f5bcfd97a556577c25aa56ebffdc45c1feb1f3b75232d6483c0946fca1ddab793b5615d7d46399f11a5c27fbb2ef95d4dfebab588cd1b174627bb15089831a9f5a11dd7b787535e631486991e9aa777f7603a1edeb065fad17f17228a3dbaaa1f4f467f43048484cdd2a8e0c9d8357ca9d90c44e2960a1f50a105e36fe3c462021033c859b1d24069a021b59402065000b784e38656f5a3927af5f9a6ca56dcc725d9f07e818427757b6056711792d1e7e37ae3c937158990fe87c177a524898d6dbbea6a2adae60c39da46dfbc8f01e7d3f198f7ba809636fba94f6a49b4792b41b7aa3928ac15002aab90289af404dc52b6708b8601867ae7a05ffbdfe3e4d97c171c6c7534294879023a66792dc7d7f67af5b0c42445a23ecd5703bc1719177e7f9fef8e15b51998a0c5e5ebb300e02416c1afd949638dc237c5d139dd894db4500c25210f39ad69b45d971d902cbcca3cf5af3c0b0e11b96f2e318ef3ac4be979fd65a186a5523ae861d5088efa9a046aab5f9b0c66fb1905e033ced9e763d0664b85755032c6680b04c8e8ab295c8ccdbf0451ad69a75fa53a729c1e85e68a34f0375d516f5b550aa594b2863fccd27bbccbf01379a2f1b212913c314bb02b499ee3085cd5d3adcc6cbd0cbc9f6297b6707d8bdcbed2640fd4ae14ff2464b5d786ea1c73a0cf1010dc14c6f68a4a358df60f82d8fc8e8f0454f7d898c0234e4719fc9cddf5240679dfe78559c8b6188bab25c62119329870efa9030c9c007e2ed189d0fe7cd4bd2b12792d2c78bf0d3dba51cec3d4f1e34d771c750b183488c89d6bb44bcf9220ed06ae0149a59108604619c6fc6d8b9ca27369e3fa087176fb8431b61648f98e69c9d17d2e49730835c3836001cf4eade47ed13f42b9dba9bcf09a6bf45509af00541771da524322ca2af2e2ef020e905e1de0899ef1433c3e57c8ec4e8aa3d9a88bfbe633e9d318a7d6284d60f6024ab59203a13df91e6df9d7eb9717630feffd9ebff869a06c41091bdc13c8982720348c33bd22c63963d6283f77b26ffb06d9960c3c28f3428ae2064352e0fb074b5107a7ac0670b26edaf3cbede0f9bb53713645d42fd243db5d40400d71afe918fadd3c1dc296da528275f6f4f8cab9816c205ad110a4c3d703cf20af1539252a6a1bff052f86ed050dea0a0d7a6f532a9739b064a77309e0c6a0aa2707ca7dd02593f03c3eb2d0170296cf8c1decd788907c6755a8ff0e0aeda0df3ff11157c05a30498686353755d563817ac94b163de9004f551350f4f84b75a2cada669ccc9b9371e4160724bb10e3b6f7398347bde4aaccd2257bea3e9fa6e730e41eda26d261685ce9e5289676020cddbaa6ba46f93649c80ff3de380f4ded991ac020bd7a3420bc60501fccaa8716e321f1d8f461932f9b58c5b37aa620bc949d8a9731f62fb0f6ab2e2ed25a987590d517d15c5d3d0f4f4e6d76cdc78679452655a653db5dc2987e25ff87d5658414d1f046cc0cc6b0a648dcc837222290c9310b8a64231bbe9a8d39c78a556a7d1db7840cce358d0b2d4865ff9cce174de151e507b03ee0b26fd61f3dc3263417fab777c589fc58905bbf49651c96a3e830d08176ff3377daf2d67c9e9c7e9fbf4289c3f434d83897cc1b9d47b596e8356e737de00af886784c0c54ddc247d85b69f3cec4ed0ee5373f158366c962a102669a97f649c24472337b9dd95a1934b69fffddb3022a4a3bf51b0832b0bcff018b2ea10c28dae44fc8da0cb75fa36d6d0c66ead482e64959de3009c5dae0f6510fe45767d02f29e8eec513260dfcac236fe70fc3724cdc2620e08967b6fdfe6a4601ecd865f8dbcc224952e515bb9cf40df1de2e20e094b9c63eca42a2e40469c6c3c76193692b10151acfcb0113b23224698ddba09b622f6eb3e5cee3ae2c155a2d8658d2efd998c4a437a5d5033f8865dd4050b8b7bbd592cd31c89a624f4b9ffba5bf42e235196a480c5245fd18d576ca962c770a0748e4f0e754727ddfd340b4d13e02c8ba0020b1fd8402a9686bd8477bab8e6ba75bfe0cf6814c9b83717bb88ff66c849ac49abd523cfc90235e235ee46e44fab4f8bff63e67e19480ceed4316b505a3e6ad8050d263f9c0fba30e9f24a938f30234df9f1e91f046acdecf0955b7bd94c126ebfc217daa9a941def674d7c0eec7d4ef04b31ec1d992603d7bd1c08e28f7478c7540865e8aaac58a1a7f17b87a80fdf2c7c13180d8fbfefb22ee2dc21a06b3cd2b44f66077d29bfa52e62ee88ee9ccb39d4a1f1edb5eee64752efc62e5eddf8067ed9451a37bfedfc8efd6ba62fc12e474f5022f40fb672a895471e58c3dfc5d129885ec25cbe69f93e5e91b1a8cdd0f6ab32cad99f47c62b5596ab2187c41654442e0f41cc9ab14eef5a8c13babcd2930913629d43377d50724a1682e2d383785cf898f94137b2c5a3af291df888f30438b807b4a76294c976e34daac162db5b49c41d85bd070163d50044244ea4595f14e2cfe7c7490d1d0eb37d459601ae138b1f11661705f284eebc5b64132df091c0cf699d6bb810f54e8afa437d7d493b9b3ebd88b1d3497a4ae95df460563b6f9f7c0b3eb21f5caf86877b91e8654dbd3cb091ebac46ca2e919214bfa739ff0dfcc274bc488c090db960a8a464e0466726fc005c22321908072a874312418a1afde7db37342cd1f43cdd078bc1a3c9c689a1cf84767570d0589a9b100566aa2d93d7178cd7ba87651876d13a566ae6249f671a413fb6fdacb948d905a43e3eacd017dfd575537bf077cd70ff4b862558b304a391484192112c7a632202704061823bbe3bb1ed09f38cc5ccf4f510b5783446d640026eee29c93f94b8e2dbf287d1f41f3d86453b7c9aa99041c0498458c9687403a875162f69c1ac299d43ac47e6c482d8460c25c52cb6774448cc5530ea3bde0a4bdd71b15702f5c1aa5618e216bd9ffa9692fecbf026fabc0bdd39fdeeb1729fc055ec348ec55eb6506e5c342b574cd1b4667aec1f8a155a8509ee31e79a1ab903c93757626e5f97ee8aa27853a505790d84879c82c96003703a840de3e7fa63cac55bc6b33f028f5c3e799997b8b6152cbf0a02d3b0df2f5d1c31a2987740302607f64018187ba0d1233984a1debd78e90e1574a356ff134cc0c6280c1332be04c78e08c72510f987e1381b584fa366afe7ed02e8513b45674b071417a113b78e2a7e4513be63ebc4f2064efe3b10fd7c41d257ee98279f88afdd483717a2cfba4dd0f7511e68076f078bbe61a74a8a29bfcdf57df3fef5f78a1").unwrap());
    }
    /*
    #[test]
    fn test_sha256_short_len() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        // build circuit for each test
        let input = hex_literal::hex!("11223344556677");
        let padded_input = pad_bytes_u32(&input);
        let expected_result = CoreSha256Hasher::hash_bytes(&input);
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let preimage_target = builder.add_virtual_u32_targets(padded_input.len() / 4);
        let expected_output_target = builder.add_virtual_hash256_target();

        let hash_output = sha256_digest_u32_array_with_byte_length(&mut builder,&preimage_target, input.len());
        builder.connect_hash256(hash_output, expected_output_target);

        let num_gates = builder.num_gates();
        let data = builder.build::<C>();
        println!(
            "sha256 ({} bytes) num_gates={}, quotient_degree_factor={}",
            input.len(),
            num_gates,
            data.common.quotient_degree_factor
        );
        let mut pw = PartialWitness::new();
        pw.set_u32_targets(&preimage_target, &bytes_to_u32_vec_be(&padded_input));
        pw.set_hash256_target(&expected_output_target, &expected_result.0);

        let start_time = std::time::Instant::now();
        let proof = data.prove(pw).unwrap();
        let duration_ms = start_time.elapsed().as_millis();
        println!("sha256 ({} bytes) proved in {}ms", input.len(), duration_ms);
        assert!(data.verify(proof).is_ok());

    }*/
}
