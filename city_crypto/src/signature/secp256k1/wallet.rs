use std::collections::HashMap;

use city_common::binaryhelpers::bytes::CompressedPublicKey;
use k256::ecdsa::signature::hazmat::PrehashSigner;
use plonky2::hash::hash_types::RichField;

use crate::hash::{
    base_types::{hash160::Hash160, hash256::Hash256},
    core::btc::btc_hash160,
    qhashout::QHashOut,
};

use super::core::QEDCompressedSecp256K1Signature;
pub trait CompressedPublicKeyToP2PKH {
    fn to_p2pkh_address(&self) -> Hash160;
}
impl CompressedPublicKeyToP2PKH for CompressedPublicKey {
    fn to_p2pkh_address(&self) -> Hash160 {
        btc_hash160(&self.0)
    }
}
pub trait Secp256K1WalletProvider {
    fn sign(
        &self,
        public_key: &CompressedPublicKey,
        message: Hash256,
    ) -> anyhow::Result<QEDCompressedSecp256K1Signature>;
    fn sign_qhashout<F: RichField>(
        &self,
        public_key: &CompressedPublicKey,
        message: QHashOut<F>,
    ) -> anyhow::Result<QEDCompressedSecp256K1Signature>;
    fn contains_public_key(&self, public_key: &CompressedPublicKey) -> bool;
    fn contains_p2pkh_address(&self, p2pkh_address: &Hash160) -> bool;
    fn get_public_key_for_p2pkh(&self, p2pkh: &Hash160) -> Option<CompressedPublicKey>;
    fn get_public_keys(&self) -> Vec<CompressedPublicKey>;
}
#[derive(Debug, Clone)]
pub struct MemorySecp256K1Wallet {
    key_map: HashMap<CompressedPublicKey, k256::ecdsa::SigningKey>,
    p2pkh_key_map: HashMap<Hash160, CompressedPublicKey>,
}

impl Secp256K1WalletProvider for MemorySecp256K1Wallet {
    fn sign(
        &self,
        public_key: &CompressedPublicKey,
        message: Hash256,
    ) -> anyhow::Result<QEDCompressedSecp256K1Signature> {
        let private_key_result = self.key_map.get(public_key);
        if private_key_result.is_some() {
            let result: k256::ecdsa::Signature =
                private_key_result.unwrap().sign_prehash(&message.0)?;
            let mut rs_bytes = [0u8; 64];

            let r_bytes = result.r().to_bytes();
            let s_bytes = result.s().to_bytes();
            rs_bytes[0..32].copy_from_slice(&r_bytes);
            rs_bytes[32..64].copy_from_slice(&s_bytes);

            Ok(QEDCompressedSecp256K1Signature {
                public_key: public_key.0,
                signature: rs_bytes,
                message,
            })
        } else {
            anyhow::bail!("private key not found")
        }
    }

    fn sign_qhashout<F: RichField>(
        &self,
        public_key: &CompressedPublicKey,
        message: QHashOut<F>,
    ) -> anyhow::Result<QEDCompressedSecp256K1Signature> {
        let msg = message.to_le_bytes();
        let bytes: Hash256 = Hash256(msg);
        self.sign(public_key, bytes)
    }

    fn contains_public_key(&self, public_key: &CompressedPublicKey) -> bool {
        self.key_map.contains_key(public_key)
    }

    fn get_public_keys(&self) -> Vec<CompressedPublicKey> {
        self.key_map.keys().cloned().collect()
    }

    fn contains_p2pkh_address(&self, p2pkh_address: &Hash160) -> bool {
        self.p2pkh_key_map.contains_key(p2pkh_address)
    }

    fn get_public_key_for_p2pkh(&self, p2pkh: &Hash160) -> Option<CompressedPublicKey> {
        self.p2pkh_key_map.get(p2pkh).cloned()
    }
}

impl MemorySecp256K1Wallet {
    pub fn new() -> Self {
        Self {
            key_map: HashMap::new(),
            p2pkh_key_map: HashMap::new(),
        }
    }
    pub fn add_private_key(&mut self, private_key: Hash256) -> anyhow::Result<CompressedPublicKey> {
        let signing_key = k256::ecdsa::SigningKey::from_slice(&private_key.0)?;
        let public_key = signing_key
            .verifying_key()
            .to_encoded_point(true)
            .to_bytes();
        let mut compressed = [0u8; 33];
        if public_key.len() == 33 {
            compressed.copy_from_slice(&public_key);
        } else {
            anyhow::bail!("public key length is not 33")
        }
        let pub_compressed = CompressedPublicKey(compressed);
        let p2pkh = pub_compressed.to_p2pkh_address();
        self.p2pkh_key_map.insert(p2pkh, pub_compressed);
        self.key_map.insert(pub_compressed, signing_key);
        Ok(pub_compressed)
    }
}
