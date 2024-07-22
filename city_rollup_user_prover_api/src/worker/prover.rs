use city_crypto::{hash::{base_types::hash256::Hash256, qhashout::QHashOut}, signature::secp256k1::core::QEDCompressedSecp256K1Signature};
use city_rollup_circuit::wallet::memory::CityMemoryWallet;
use plonky2::{field::goldilocks_field::GoldilocksField, plonk::{config::{GenericHashOut, PoseidonGoldilocksConfig}, proof::ProofWithPublicInputs}};

use crate::common::{enc::SimpleEncryptionHelper, request::{UPWJobRequest, UPWJobRequestPayload}};

type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
const D: usize = 2;

pub struct UPWProver {
  wallet: CityMemoryWallet<C, D>,
}

impl UPWProver {
  pub fn new() -> Self {
    Self {
      wallet: CityMemoryWallet::<C, D>::new(),
    }
  }
  pub fn prove_secp256k1_signature(&self, signature: &QEDCompressedSecp256K1Signature) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
    self.wallet.zk_secp256k1_from_signature(signature)
  }
  pub fn prove_zk_signature(&self, private_key: QHashOut<F>, action_hash: QHashOut<F>) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
    self.wallet.zk_sign_with_private_key(private_key, action_hash)
  }
  pub fn get_public_key_for_private_key(&self, private_key: Hash256) -> anyhow::Result<Vec<u8>> {
    Ok(self.wallet.zk_wallet.basic_wallet.get_fingerprint_public_key_for_private_key(QHashOut::from_hash256_le(private_key)).to_le_bytes().to_vec())
  }

  pub fn prove_request<E: SimpleEncryptionHelper>(&self, encryption_helper: &E, request: &UPWJobRequest) -> anyhow::Result<Vec<u8>> {
    match request.payload {
      UPWJobRequestPayload::Secp256K1SignatureProof(core) => bincode::serialize(&self.prove_secp256k1_signature(&core)?).map_err(|e| e.into()),
      UPWJobRequestPayload::ZKSignatureProof(payload) => bincode::serialize(&self.prove_zk_signature(QHashOut::from_bytes(&payload.private_key.0), QHashOut::from_bytes(&payload.message.0))?).map_err(|e| e.into()),
      UPWJobRequestPayload::EncryptedZKSignatureProof(payload) => {
        let decrypted_payload = payload.decrypt(encryption_helper);
        bincode::serialize(&self.prove_zk_signature(QHashOut::from_hash256_le(decrypted_payload.private_key), QHashOut::from_hash256_le(decrypted_payload.message))?).map_err(|e| e.into())
      }
        UPWJobRequestPayload::GetPublicKey(payload) => self.get_public_key_for_private_key(payload),
        UPWJobRequestPayload::EncryptedGetPublicKey(payload) => {
          let decrypted_payload = payload.decrypt(encryption_helper);
          self.get_public_key_for_private_key(decrypted_payload)
        },
    }
  }
}