use city_crypto::{hash::qhashout::QHashOut, signature::secp256k1::core::QEDCompressedSecp256K1Signature};
use city_rollup_circuit::wallet::memory::CityMemoryWallet;
use plonky2::{field::goldilocks_field::GoldilocksField, plonk::{config::PoseidonGoldilocksConfig, proof::ProofWithPublicInputs}};

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

  pub fn prove_request<E: SimpleEncryptionHelper>(&self, encryption_helper: &E, request: &UPWJobRequest) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
    match request.payload {
      UPWJobRequestPayload::Secp256K1SignatureProof(core) => self.prove_secp256k1_signature(&core),
      UPWJobRequestPayload::ZKSignatureProof(payload) => self.prove_zk_signature(QHashOut::from_hash256_le(payload.private_key), QHashOut::from_hash256_le(payload.message)),
      UPWJobRequestPayload::EncryptedZKSignatureProof(payload) => {
        let decrypted_payload = payload.decrypt(encryption_helper);
        self.prove_zk_signature(QHashOut::from_hash256_le(decrypted_payload.private_key), QHashOut::from_hash256_le(decrypted_payload.message))
      }
    }
  }
}