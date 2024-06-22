use city_crypto::{hash::base_types::hash256::Hash256, signature::secp256k1::core::QEDCompressedSecp256K1Signature};
use serde::{Serialize, Deserialize};

use super::enc::SimpleEncryptionHelper;


#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Copy)]
pub struct UPWEncryptedZKSignatureJobRequestPayload {
  pub encrypted_private_key: Hash256,
  pub salt: Hash256,
  pub message: Hash256,
}
impl UPWEncryptedZKSignatureJobRequestPayload {
  pub fn decrypt<E: SimpleEncryptionHelper>(&self, encryption_helper: &E) -> UPWZKSignatureJobRequestPayload {
    let decrypted_key = encryption_helper.decrypt_32(self.salt, self.encrypted_private_key);
    UPWZKSignatureJobRequestPayload {
      private_key: decrypted_key,
      message: self.message,
    }
  }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Copy)]
pub struct UPWZKSignatureJobRequestPayload {
  pub private_key: Hash256,
  pub message: Hash256,
}
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Copy)]
pub struct UPWEncryptedPublicKeyJobRequestPayload {
  pub encrypted_private_key: Hash256,
  pub salt: Hash256,
}
impl UPWEncryptedPublicKeyJobRequestPayload {
  pub fn decrypt<E: SimpleEncryptionHelper>(&self, encryption_helper: &E) -> Hash256 {
    encryption_helper.decrypt_32(self.salt, self.encrypted_private_key)
  }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub enum UPWJobRequestPayload {
  Secp256K1SignatureProof(QEDCompressedSecp256K1Signature),
  ZKSignatureProof(UPWZKSignatureJobRequestPayload),
  EncryptedZKSignatureProof(UPWEncryptedZKSignatureJobRequestPayload),
  GetPublicKey(Hash256),
  EncryptedGetPublicKey(UPWEncryptedPublicKeyJobRequestPayload),
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct UPWJobRequest {
  pub request_id: Hash256,
  pub payload: UPWJobRequestPayload,
}