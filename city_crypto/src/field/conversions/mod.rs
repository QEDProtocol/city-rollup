use plonky2::hash::hash_types::RichField;

pub fn bytes33_to_public_key<F: RichField>(bytes: &[u8]) -> [F; 9] {
    core::array::from_fn(|i| {
        if i == 0 {
            F::from_canonical_u8(bytes[0])
        } else {
            let offset = 1 + (i - 1) * 4;
            let u32_val = u32::from_le_bytes([
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
            ]);
            F::from_canonical_u32(u32_val)
        }
    })
}
