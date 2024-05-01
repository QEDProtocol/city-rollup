pub const fn ceil_div_usize(a: usize, b: usize) -> usize {
    (a + b - 1) / b
}

pub fn read_u48_from_bytes_le(bytes: &[u8], offset: usize) -> u64 {
    let mut result = 0u64;
    for i in 0..6 {
        result |= (bytes[offset + i] as u64) << (i * 8);
    }
    result
}

pub fn read_u56_from_bytes_le(bytes: &[u8], offset: usize) -> u64 {
    let mut result = 0u64;
    for i in 0..7 {
        result |= (bytes[offset + i] as u64) << (i * 8);
    }
    result
}
