use city_common::binaryhelpers::bytes::CompressedPublicKey;
use city_common_circuit::{
    circuits::l1_secp256k1_signature::L1Secp256K1SignatureCircuit,
    wallet::zk::{MemoryZKSignatureWallet, SimpleZKSignatureWallet, ZKSignatureWalletProvider},
};
use city_crypto::{
    hash::{base_types::hash256::Hash256, qhashout::QHashOut},
    signature::secp256k1::{
        core::QEDCompressedSecp256K1Signature,
        wallet::{MemorySecp256K1Wallet, Secp256K1WalletProvider},
    },
};
use plonky2::plonk::{
    config::{AlgebraicHasher, GenericConfig},
    proof::ProofWithPublicInputs,
};

#[derive(Clone)]
pub struct DebugScenarioWallet<C: GenericConfig<D> + 'static, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub zk_wallet: MemoryZKSignatureWallet<C, D, SimpleZKSignatureWallet<C, D>>,
    pub secp256k1_circuit: L1Secp256K1SignatureCircuit<C, D>,
    pub secp256k1_wallet: MemorySecp256K1Wallet,
}

impl<C: GenericConfig<D> + 'static, const D: usize> DebugScenarioWallet<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub fn new() -> Self {
        Self {
            zk_wallet: MemoryZKSignatureWallet::<C, D, SimpleZKSignatureWallet<C, D>>::new_memory(),
            secp256k1_wallet: MemorySecp256K1Wallet::new(),
            secp256k1_circuit: L1Secp256K1SignatureCircuit::new(),
        }
    }
    pub fn add_zk_private_key(&mut self, private_key: QHashOut<C::F>) -> QHashOut<C::F> {
        self.zk_wallet.add_private_key(private_key)
    }
    pub fn add_secp256k1_private_key(
        &mut self,
        private_key: Hash256,
    ) -> anyhow::Result<CompressedPublicKey> {
        self.secp256k1_wallet.add_private_key(private_key)
    }
    pub fn zk_sign(
        &self,
        fingerprint_hash: QHashOut<C::F>,
        message: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.zk_wallet.sign(fingerprint_hash, message)
    }
    pub fn zk_sign_hash_public_key(
        &self,
        hash_public_key: QHashOut<C::F>,
        message: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.zk_wallet
            .sign_by_hash_public_key(hash_public_key, message)
    }
    pub fn sign_secp256k1(
        &self,
        public_key: CompressedPublicKey,
        message: Hash256,
    ) -> anyhow::Result<QEDCompressedSecp256K1Signature> {
        self.secp256k1_wallet.sign(&public_key, message)
    }
    pub fn sign_hash_secp256k1(
        &self,
        public_key: CompressedPublicKey,
        message: QHashOut<C::F>,
    ) -> anyhow::Result<QEDCompressedSecp256K1Signature> {
        self.secp256k1_wallet.sign_qhashout(&public_key, message)
    }
    pub fn zk_sign_secp256k1(
        &self,
        public_key: CompressedPublicKey,
        message: Hash256,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let ecc_sig = self.sign_secp256k1(public_key, message)?;
        self.secp256k1_circuit.prove(&ecc_sig)
    }
    pub fn zk_sign_hash_secp256k1(
        &self,
        public_key: CompressedPublicKey,
        message: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let ecc_sig = self.sign_hash_secp256k1(public_key, message)?;
        self.secp256k1_circuit.prove(&ecc_sig)
    }
}
