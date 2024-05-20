use city_crypto::field::serialized_2d_felt_bls12381::Serialized2DFeltBLS12381;
use serde::{Deserialize, Serialize};

use crate::link::tx::encode_binary_witness_script_for_p2sh;

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug, Hash, Copy, Ord, PartialOrd, Eq)]
pub struct CityGroth16ProofData {
    pub pi_a: Serialized2DFeltBLS12381,
    pub pi_b_a0: Serialized2DFeltBLS12381,
    pub pi_b_a1: Serialized2DFeltBLS12381,
    pub pi_c: Serialized2DFeltBLS12381,
}

impl CityGroth16ProofData {
    pub fn new(
        pi_a: Serialized2DFeltBLS12381,
        pi_b_a0: Serialized2DFeltBLS12381,
        pi_b_a1: Serialized2DFeltBLS12381,
        pi_c: Serialized2DFeltBLS12381,
    ) -> Self {
        Self {
            pi_a,
            pi_b_a0,
            pi_b_a1,
            pi_c,
        }
    }
    pub fn to_ps_bytes(&self) -> [u8; 192] {
        let mut bytes = [0u8; 192];
        bytes[..48].copy_from_slice(&self.pi_a.0);
        bytes[48..96].copy_from_slice(&self.pi_b_a0.0);
        bytes[96..144].copy_from_slice(&self.pi_b_a1.0);
        bytes[144..].copy_from_slice(&self.pi_c.0);
        bytes
    }
    pub fn from_ps_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() != 192 {
            anyhow::bail!(
                "Invalid length for CityGroth16ProofData, expected 192 bytes, got {} bytes",
                bytes.len()
            );
        }
        Ok(Self {
            pi_a: Serialized2DFeltBLS12381::from_slice(&bytes[..48]),
            pi_b_a0: Serialized2DFeltBLS12381::from_slice(&bytes[48..96]),
            pi_b_a1: Serialized2DFeltBLS12381::from_slice(&bytes[96..144]),
            pi_c: Serialized2DFeltBLS12381::from_slice(&bytes[144..]),
        })
    }
    pub fn encode_witness_script(
        &self,
        verifier_data: &'static [u8],
        base_script: &[u8],
    ) -> Vec<u8> {
        let inputs = [
            &self.pi_a.0,
            &self.pi_b_a0.0,
            &self.pi_b_a1.0,
            &self.pi_c.0,
            verifier_data,
        ];
        encode_binary_witness_script_for_p2sh(base_script, inputs.into_iter())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serde() {
        serde_json::from_str::<CityGroth16ProofData>(r#"{"pi_a":"43776e03166caf84da077f7122bb0c92c27523130cdfb6f6dbde349778ce2c674a512cbfb0d350091d56c3dc4c2dd60f","pi_b_a0":"9cc3c5106b500a2ec272b098808568128c52199932d332849efe076da5f5107503c561314e7de04a5589fa299a9b9818","pi_b_a1":"951e39df42c826fd543238566bcbc9a41580514c337b0911aeac91d49c43aaf7b847c8539c4c57599a5b78611fdf5c96","pi_c":"c12b47a78500e2fb508153b28278067b9471f97457f02c8d3ca376e276479a24ae87bf7a6068f6a584b794ddff04f305"}"#).unwrap();
    }
}
