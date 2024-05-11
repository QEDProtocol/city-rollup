use city_rollup_common::api::data::store::CityL2BlockState;
use kvq::traits::KVQSerializable;
use serde::Deserialize;
use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct L2BlockStateKeyCore<const TABLE_TYPE: u16>(pub u64);

impl<const TABLE_TYPE: u16> KVQSerializable for L2BlockStateKeyCore<TABLE_TYPE> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let checkpoint_id_be_bytes = self.0.to_be_bytes();
        Ok(vec![
            (TABLE_TYPE >> 8) as u8,
            (TABLE_TYPE & 0xff) as u8,
            checkpoint_id_be_bytes[0],
            checkpoint_id_be_bytes[1],
            checkpoint_id_be_bytes[2],
            checkpoint_id_be_bytes[3],
            checkpoint_id_be_bytes[4],
            checkpoint_id_be_bytes[5],
            checkpoint_id_be_bytes[6],
            checkpoint_id_be_bytes[7],
        ])
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() != 34 {
            anyhow::bail!(
                "expected 34 bytes for deserializing L2BlockStateKeyCore, got {} bytes",
                bytes.len()
            );
        }
        Ok(L2BlockStateKeyCore(u64::from_be_bytes([
            bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9],
        ])))
    }
}
impl<const TABLE_TYPE: u16> From<&CityL2BlockState> for L2BlockStateKeyCore<TABLE_TYPE> {
    fn from(state: &CityL2BlockState) -> Self {
        L2BlockStateKeyCore(state.checkpoint_id)
    }
}
impl<const TABLE_TYPE: u16> From<u64> for L2BlockStateKeyCore<TABLE_TYPE> {
    fn from(checkpoint_id: u64) -> Self {
        L2BlockStateKeyCore(checkpoint_id)
    }
}
