use super::traits::KVQSerializable;
impl<const SIZE: usize> KVQSerializable for [u8; SIZE] {
    fn to_bytes(&self) -> Vec<u8> {
        self.to_vec()
    }
    fn from_bytes(bytes: &[u8]) -> Self {
        let mut result = [0u8; SIZE];
        result.copy_from_slice(bytes);
        result
    }
}

impl KVQSerializable for Vec<u8> {
    fn to_bytes(&self) -> Vec<u8> {
        self.clone()
    }
    fn from_bytes(bytes: &[u8]) -> Self {
        bytes.to_vec()
    }
}
impl<const SIZE: usize> KVQSerializable for [u64; SIZE] {
    fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(SIZE * 8);
        for i in 0..SIZE {
            result.extend_from_slice(&self[i].to_be_bytes());
        }
        result
    }
    fn from_bytes(bytes: &[u8]) -> Self {
        let mut result = [0u64; SIZE];
        for i in 0..SIZE {
            let mut bytes_u64 = [0u8; 8];
            bytes_u64.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
            result[i] = u64::from_be_bytes(bytes_u64);
        }
        result
    }
}


impl<const SIZE: usize> KVQSerializable for [u32; SIZE] {
    fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(SIZE * 4);
        for i in 0..SIZE {
            result.extend_from_slice(&self[i].to_be_bytes());
        }
        result
    }
    fn from_bytes(bytes: &[u8]) -> Self {
        let mut result = [0u32; SIZE];
        for i in 0..SIZE {
            let mut bytes_u32 = [0u8; 4];
            bytes_u32.copy_from_slice(&bytes[i * 4..(i + 1) * 4]);
            result[i] = u32::from_be_bytes(bytes_u32);
        }
        result
    }
}


