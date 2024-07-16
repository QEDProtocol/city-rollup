use city_crypto::hash::{base_types::hash256::Hash256, core::sha256::CoreSha256Hasher};

pub trait SimpleEncryptionHelper: Clone + Send + Sync {
  fn encrypt_32(&self, salt: Hash256, data: Hash256) -> Hash256;
  fn decrypt_32(&self, salt: Hash256, encrypted_data: Hash256) -> Hash256;
}

#[derive(Clone)]
pub struct SimpleZeroPadEncryptionHelper {
  key: Hash256,
}

impl SimpleZeroPadEncryptionHelper {
  pub fn new(key: Hash256) -> Self {
    Self { key }
  }
  pub fn new_rand() -> Self {
    Self { key: Hash256::rand() }
  }
  pub fn new_no_encrypt() -> Self {
    Self { key: Hash256::ZERO }
  }
  pub fn get_decryption_key(&self) -> Hash256 {
    self.key
  }
}

impl SimpleEncryptionHelper for SimpleZeroPadEncryptionHelper {
  fn encrypt_32(&self, salt: Hash256, data: Hash256) -> Hash256 {
    let mut hasher = CoreSha256Hasher::new();
    hasher.update(&self.key.0);
    hasher.update(&salt.0);
    let key = hasher.finalize();
    data ^ key
  }
  fn decrypt_32(&self, salt: Hash256, encrypted_data: Hash256) -> Hash256 {
    let mut hasher = CoreSha256Hasher::new();
    hasher.update(&self.key.0);
    hasher.update(&salt.0);
    let key = hasher.finalize();
    encrypted_data ^ key
  }
}