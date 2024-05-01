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

#[cfg(test)]
mod tests {
    use bitcoin::{
        consensus::{deserialize, serialize},
        VarInt,
    };

    use super::VaruintDecodingError;

    fn encode_varuint_bitcoin_lib(value: u64) -> Vec<u8> {
        let v = VarInt(value);
        serialize(&v)
    }

    fn decode_varuint_bitcoin_lib(data: &[u8]) -> Result<u64, VaruintDecodingError> {
        let v: Result<VarInt, _> = deserialize(data);

        if v.is_err() {
            Err(VaruintDecodingError)
        } else {
            Ok(v.unwrap().0)
        }
    }

    fn ensure_correct_encode_decode_size(value: u64) {
        let size = super::varuint_size(value);
        let encoded = super::encode_varuint(value);
        assert_eq!(encoded.len(), size);
        assert_eq!(super::decode_varuint(&encoded).unwrap(), value);
    }

    fn ensure_correct_bitcoin_lib(value: u64) {
        let encoded_bitcoin_lib = encode_varuint_bitcoin_lib(value);

        assert_eq!(
            decode_varuint_bitcoin_lib(&encoded_bitcoin_lib).unwrap(),
            value
        );
    }

    fn ensure_encode_parity_with_bitcoin_lib(value: u64) {
        let encoded = super::encode_varuint(value);
        let encoded_bitcoin_lib = encode_varuint_bitcoin_lib(value);
        assert_eq!(encoded, encoded_bitcoin_lib);
    }
    fn ensure_decode_parity_with_bitcoin_lib(data: &[u8]) {
        let encoded = super::decode_varuint(data);
        let encoded_bitcoin_lib = decode_varuint_bitcoin_lib(data);
        assert_eq!(encoded.is_err(), encoded_bitcoin_lib.is_err());
        if encoded.is_ok() {
            assert_eq!(encoded.unwrap(), encoded_bitcoin_lib.unwrap());
        }
    }

    fn ensure_correct_e2e_value(value: u64) {
        let encoded = super::encode_varuint(value);
        assert_eq!(super::decode_varuint(&encoded).unwrap(), value);

        ensure_correct_bitcoin_lib(value);
        ensure_correct_encode_decode_size(value);
        ensure_encode_parity_with_bitcoin_lib(value);
        ensure_decode_parity_with_bitcoin_lib(&encoded);
    }

    #[test]
    fn test_encode_decode() {
        ensure_correct_e2e_value(0);
        ensure_correct_e2e_value(1);
        ensure_correct_e2e_value(2);
        ensure_correct_e2e_value(16);
        ensure_correct_e2e_value(19);
        ensure_correct_e2e_value(0xffu64);
        ensure_correct_e2e_value(0x100u64);
        ensure_correct_e2e_value(0x1000u64);
        ensure_correct_e2e_value(0x10000u64);
        ensure_correct_e2e_value(0x100000u64);
        ensure_correct_e2e_value(0x1000000u64);
        ensure_correct_e2e_value(0x10000000u64);
        ensure_correct_e2e_value(0x100000000u64);
        ensure_correct_e2e_value(0xfffu64);
        ensure_correct_e2e_value(0xffffu64);
        ensure_correct_e2e_value(0x1337u64);
        ensure_correct_e2e_value(0x13371337u64);
        ensure_correct_e2e_value(0xffffffffu64);
        ensure_correct_e2e_value(0x13371337fu64);
        ensure_correct_e2e_value(0xfffffffffu64);
        ensure_correct_e2e_value(0x133713371337u64);
        ensure_correct_e2e_value(0x133713371337fu64);
        ensure_correct_e2e_value(0x1337133713371337u64);
        ensure_correct_e2e_value(0xffffffffffffffffu64);
    }
}
