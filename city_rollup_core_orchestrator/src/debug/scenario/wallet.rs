use city_common::{
    binaryhelpers::bytes::CompressedPublicKey,
    config::rollup_constants::{DEPOSIT_FEE_AMOUNT, WITHDRAWAL_FEE_AMOUNT},
};
use city_common_circuit::{
    circuits::l1_secp256k1_signature::L1Secp256K1SignatureCircuit,
    wallet::zk::{MemoryZKSignatureWallet, SimpleZKSignatureWallet, ZKSignatureWalletProvider},
};
use city_crypto::{
    hash::{
        base_types::{hash160::Hash160, hash256::Hash256},
        qhashout::QHashOut,
    },
    signature::secp256k1::{
        core::QEDCompressedSecp256K1Signature,
        wallet::{MemorySecp256K1Wallet, Secp256K1WalletProvider},
    },
};
use city_rollup_common::{
    api::data::{
        block::rpc_request::{
            CityAddWithdrawalRPCRequest, CityClaimDepositRPCRequest, CityTokenTransferRPCRequest,
        },
        store::CityL1Deposit,
    },
    introspection::rollup::signature::QEDSigAction,
};
use plonky2::{
    hash::poseidon::PoseidonHash,
    plonk::{
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

#[derive(Clone)]
pub struct DebugScenarioWallet<C: GenericConfig<D> + 'static, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub zk_wallet: MemoryZKSignatureWallet<C, D, SimpleZKSignatureWallet<C, D>>,
    pub secp256k1_circuit: Option<L1Secp256K1SignatureCircuit<C, D>>,
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
            secp256k1_circuit: Some(L1Secp256K1SignatureCircuit::new()),
        }
    }
    pub fn new_fast_setup() -> Self {
        Self {
            zk_wallet: MemoryZKSignatureWallet::<C, D, SimpleZKSignatureWallet<C, D>>::new_memory(),
            secp256k1_wallet: MemorySecp256K1Wallet::new(),
            secp256k1_circuit: None,
        }
    }
    pub fn setup_circuits(&mut self) {
        if self.secp256k1_circuit.is_none() {
            self.secp256k1_circuit = Some(L1Secp256K1SignatureCircuit::new());
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
        self.secp256k1_circuit.as_ref().unwrap().prove(&ecc_sig)
    }
    pub fn zk_sign_hash_secp256k1(
        &self,
        public_key: CompressedPublicKey,
        message: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let ecc_sig = self.sign_hash_secp256k1(public_key, message)?;
        self.secp256k1_circuit.as_ref().unwrap().prove(&ecc_sig)
    }
    pub fn sign_claim_deposit(
        &self,
        network_magic: u64,
        user_id: u64,
        l1_deposit: &CityL1Deposit,
    ) -> anyhow::Result<CityClaimDepositRPCRequest> {
        let sig_preimage = QEDSigAction::<C::F>::new_claim_deposit_action(
            network_magic,
            user_id,
            l1_deposit.txid,
            l1_deposit.value,
            DEPOSIT_FEE_AMOUNT,
        );
        println!(
            "sig_preimage: {}",
            serde_json::to_string(&sig_preimage).unwrap()
        );
        let hash = sig_preimage.get_qhash::<PoseidonHash>();
        let proof = self.zk_sign_hash_secp256k1(l1_deposit.public_key, hash)?;

        let signature_proof = bincode::serialize(&proof)?;
        Ok(CityClaimDepositRPCRequest {
            public_key: l1_deposit.public_key.0,
            user_id,
            deposit_id: l1_deposit.deposit_id,
            value: l1_deposit.value,
            txid: l1_deposit.txid,
            signature_proof,
        })
    }
    pub fn sign_l2_transfer(
        &self,
        public_key: QHashOut<C::F>,
        network_magic: u64,
        from: u64,
        to: u64,
        value: u64,
        nonce: u64,
    ) -> anyhow::Result<CityTokenTransferRPCRequest> {
        let sig_preimage =
            QEDSigAction::<C::F>::new_transfer_action(network_magic, from, nonce, to, value);
        let hash = sig_preimage.get_qhash::<PoseidonHash>();
        let proof = self.zk_sign(public_key, hash)?;

        let signature_proof = bincode::serialize(&proof)?;
        Ok(CityTokenTransferRPCRequest {
            signature_proof,
            to,
            nonce,
            user_id: from,
            value: value,
        })
    }
    pub fn sign_withdrawal(
        &self,
        public_key: QHashOut<C::F>,
        network_magic: u64,
        user_id: u64,
        l1_address: Hash160,
        value: u64,
        nonce: u64,
    ) -> anyhow::Result<CityAddWithdrawalRPCRequest> {
        let sig_preimage: QEDSigAction<C::F> =
            QEDSigAction::<C::F>::new_withdrawal_action::<PoseidonHash>(
                network_magic,
                user_id,
                nonce,
                l1_address,
                0,
                value,
                WITHDRAWAL_FEE_AMOUNT,
            );
        let hash = sig_preimage.get_qhash::<PoseidonHash>();
        let proof = self.zk_sign(public_key, hash)?;

        let signature_proof = bincode::serialize(&proof)?;
        Ok(CityAddWithdrawalRPCRequest {
            signature_proof,
            nonce,
            user_id: user_id,
            value: value,
            destination_type: 0,
            destination: l1_address,
        })
    }
}
