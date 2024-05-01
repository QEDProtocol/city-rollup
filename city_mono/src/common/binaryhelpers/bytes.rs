pub fn bytes_to_u32_vec_le(bytes: &[u8]) -> Vec<u32> {
    bytes
        .chunks_exact(4)
        .map(|chunk| {
            let b = chunk.try_into().unwrap_or([0u8; 4]);
            u32::from_le_bytes(b)
        })
        .collect()
}
pub fn bytes_to_u32_vec_be(bytes: &[u8]) -> Vec<u32> {
    bytes
        .chunks_exact(4)
        .map(|chunk| {
            let b = chunk.try_into().unwrap_or([0u8; 4]);
            u32::from_be_bytes(b)
        })
        .collect()
}
pub fn u32_vec_to_bytes_be(u32s: &[u32]) -> Vec<u8> {
    u32s.iter()
        .flat_map(|&u| u.to_be_bytes().to_vec())
        .collect()
}

#[inline]
pub fn read_u32_be_at(array: &[u8], index: usize) -> u32 {
    ((array[index] as u32) << 24)
        + ((array[index + 1] as u32) << 16)
        + ((array[index + 2] as u32) << 8)
        + (array[index + 3] as u32)
}

#[inline]
pub fn read_u32_le_at(array: &[u8], index: usize) -> u32 {
    ((array[index + 3] as u32) << 24)
        + ((array[index + 2] as u32) << 16)
        + ((array[index + 1] as u32) << 8)
        + (array[index] as u32)
}
