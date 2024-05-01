pub fn varuint_size(value: u64) -> usize {
    if value < 0xfd {
        1
    } else if value <= 0xffff {
        3
    } else if value <= 0xffffffff {
        5
    } else {
        9
    }
}

pub fn encode_varuint(value: u64) -> Vec<u8> {
    if value < 0xfd {
        vec![value as u8]
    } else if value <= 0xffffu64 {
        let mut v = vec![0xfd];
        v.extend_from_slice(&(value as u16).to_le_bytes());
        v
    } else if value <= 0xffffffffu64 {
        let mut v = vec![0xfe];
        v.extend_from_slice(&(value as u32).to_le_bytes());
        v
    } else {
        let mut v = vec![0xff];
        v.extend_from_slice(&value.to_le_bytes());
        v
    }
}
#[derive(Debug, Clone)]
pub struct VaruintDecodingError;

impl core::fmt::Display for VaruintDecodingError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "tried to decode malformed bytes into varuint")
    }
}

pub fn decode_varuint(data: &[u8]) -> Result<u64, VaruintDecodingError> {
    if data.is_empty() {
        return Err(VaruintDecodingError);
    }
    let first_byte = data[0];
    if first_byte < 0xfd {
        Ok(first_byte as u64)
    } else if first_byte == 0xfd {
        if data.len() < 3 {
            return Err(VaruintDecodingError);
        }
        Ok(u64::from_le_bytes([data[1], data[2], 0, 0, 0, 0, 0, 0]))
    } else if first_byte == 0xfe {
        if data.len() < 5 {
            return Err(VaruintDecodingError);
        }
        Ok(u64::from_le_bytes([
            data[1], data[2], data[3], data[4], 0, 0, 0, 0,
        ]))
    } else {
        if data.len() < 9 {
            return Err(VaruintDecodingError);
        }
        Ok(u64::from_le_bytes([
            data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8],
        ]))
    }
}
