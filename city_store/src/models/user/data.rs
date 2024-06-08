use kvq::traits::KVQSerializable;
use serde::{Deserialize, Serialize};

use crate::config::CityHash;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct L2UserIdKeyByPubicKeyIdCore<const TABLE_TYPE: u16>{
  pub public_key: CityHash,
  pub user_id: u64,
}

impl<const TABLE_TYPE: u16> KVQSerializable for L2UserIdKeyByPubicKeyIdCore<TABLE_TYPE> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
      let public_key_bytes = self.public_key.to_le_bytes();
      let user_id_be_bytes = self.user_id.to_be_bytes();
      
        Ok(vec![
            (TABLE_TYPE >> 8) as u8,
            (TABLE_TYPE & 0xff) as u8,
            public_key_bytes[0],
            public_key_bytes[1],
            public_key_bytes[2],
            public_key_bytes[3],
            public_key_bytes[4],
            public_key_bytes[5],
            public_key_bytes[6],
            public_key_bytes[7],
            public_key_bytes[8],
            public_key_bytes[9],
            public_key_bytes[10],
            public_key_bytes[11],
            public_key_bytes[12],
            public_key_bytes[13],
            public_key_bytes[14],
            public_key_bytes[15],
            public_key_bytes[16],
            public_key_bytes[17],
            public_key_bytes[18],
            public_key_bytes[19],
            public_key_bytes[20],
            public_key_bytes[21],
            public_key_bytes[22],
            public_key_bytes[23],
            public_key_bytes[24],
            public_key_bytes[25],
            public_key_bytes[26],
            public_key_bytes[27],
            public_key_bytes[28],
            public_key_bytes[29],
            public_key_bytes[30],
            public_key_bytes[31],
            user_id_be_bytes[0],
            user_id_be_bytes[1],
            user_id_be_bytes[2],
            user_id_be_bytes[3],
            user_id_be_bytes[4],
            user_id_be_bytes[5],
            user_id_be_bytes[6],
            user_id_be_bytes[7],
        ])
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() != 42 {
            anyhow::bail!(
                "expected 42 bytes for deserializing L2UserIdKeyByPubicKeyIdCore, got {} bytes",
                bytes.len()
            );
        }
        let public_key = CityHash::from_bytes(&bytes[2..34])?;
        let user_id = u64::from_be_bytes([
          bytes[34], bytes[35], bytes[36], bytes[37], bytes[38], bytes[39], bytes[40], bytes[41],
      ]);

        Ok(L2UserIdKeyByPubicKeyIdCore{
          public_key,
          user_id,
        })
    }
}