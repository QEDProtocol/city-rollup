use city_crypto::hash::qhashout::QHashOut;
use city_rollup_common::introspection::rollup::signature::SimpleL2PrivateKey;
use hashbrown::HashMap;
use plonky2::plonk::circuit_data::CommonCircuitData;
use plonky2::plonk::circuit_data::VerifierOnlyCircuitData;
use plonky2::plonk::config::AlgebraicHasher;
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;

use crate::circuits::traits::qstandard::QStandardCircuit;
use crate::circuits::zk_signature::fixed_public_key::ZKSignatureCircuitSimpleFixedPublicKey;
use crate::circuits::zk_signature::inner::ZKSignatureCircuitInner;
use crate::circuits::zk_signature_wrapper::ZKSignatureWrapperCircuit;

#[derive(Debug)]
pub struct SimpleZKSignatureWalletKey<C: GenericConfig<D> + 'static, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub circuit_fingerprint_public_key: QHashOut<C::F>,
    pub hash_public_key: QHashOut<C::F>,
    pub fixed_circuit: ZKSignatureCircuitSimpleFixedPublicKey<C, D>,
}
pub trait ZKSignatureBasicWalletProvider<C: GenericConfig<D> + 'static, const D: usize> {
    fn zk_sign(
        &self,
        private_key: QHashOut<C::F>,
        action_hash: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>;
    fn get_public_keys(&self) -> Vec<QHashOut<C::F>>;
    fn get_hash_public_keys(&self) -> Vec<QHashOut<C::F>>;
    fn add_hash_public_key(&mut self, hash_public_key: QHashOut<C::F>) -> QHashOut<C::F>;
    fn remove_public_key(&mut self, public_key: QHashOut<C::F>);
    fn contains_public_key(&self, public_key: QHashOut<C::F>) -> bool;
    fn contains_hash_public_key(&self, hash_public_key: QHashOut<C::F>) -> bool;
    fn get_public_key_from_hash_public_key(
        &self,
        hash_public_key: QHashOut<C::F>,
    ) -> Option<QHashOut<C::F>>;
    fn clear(&mut self);
}
pub trait ZKSignatureWalletProvider<C: GenericConfig<D> + 'static, const D: usize>:
    ZKSignatureBasicWalletProvider<C, D>
{
    fn sign(
        &self,
        public_key: QHashOut<C::F>,
        action_hash: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>;
    fn sign_by_hash_public_key(
        &self,
        hash_public_key: QHashOut<C::F>,
        action_hash: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>;
    fn add_private_key(&mut self, private_key: QHashOut<C::F>) -> QHashOut<C::F>;
}

pub struct SimpleZKSignatureWallet<C: GenericConfig<D> + 'static, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub inner_circuit: ZKSignatureCircuitInner<C, D>,
    pub wrapper_circuit: ZKSignatureWrapperCircuit<C, D>,
    pub key_map: HashMap<QHashOut<C::F>, SimpleZKSignatureWalletKey<C, D>>,
    pub hash_public_key_to_fingerprint: HashMap<QHashOut<C::F>, QHashOut<C::F>>,
}

impl<C: GenericConfig<D> + 'static, const D: usize> Clone for SimpleZKSignatureWallet<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn clone(&self) -> Self {
        let mut key_map: HashMap<QHashOut<C::F>, SimpleZKSignatureWalletKey<C, D>> = HashMap::new();
        let hash_public_key_to_fingerprint = self.hash_public_key_to_fingerprint.clone();
        let inner_circuit = self.inner_circuit.clone();
        let wrapper_circuit = self.wrapper_circuit.clone();
        self.key_map.iter().for_each(|(k, v)| {
            key_map.insert(
                *k,
                SimpleZKSignatureWalletKey {
                    circuit_fingerprint_public_key: v.circuit_fingerprint_public_key,
                    hash_public_key: v.hash_public_key,
                    fixed_circuit: ZKSignatureCircuitSimpleFixedPublicKey::<C, D>::new_from_isc(
                        &inner_circuit,
                        v.hash_public_key,
                    ),
                },
            );
        });

        Self {
            key_map,
            hash_public_key_to_fingerprint,
            inner_circuit,
            wrapper_circuit,
        }
    }
}
impl<C: GenericConfig<D> + 'static, const D: usize> SimpleZKSignatureWallet<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub fn new() -> Self {
        let inner_circuit = ZKSignatureCircuitInner::new();
        let fixed_circuit = ZKSignatureCircuitSimpleFixedPublicKey::new_from_isc(
            &inner_circuit,
            QHashOut::from_values(1337, 1337, 1337, 1337),
        );
        let wrapper_circuit = ZKSignatureWrapperCircuit::new_from_common(
            &fixed_circuit.get_common_circuit_data_ref(),
            fixed_circuit
                .get_verifier_config_ref()
                .constants_sigmas_cap
                .height(),
        );

        Self {
            inner_circuit,
            wrapper_circuit,
            key_map: HashMap::new(),
            hash_public_key_to_fingerprint: HashMap::new(),
        }
    }
}

impl<C: GenericConfig<D> + 'static, const D: usize> ZKSignatureBasicWalletProvider<C, D>
    for SimpleZKSignatureWallet<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn zk_sign(
        &self,
        private_key: QHashOut<C::F>,
        action_hash: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let pk = SimpleL2PrivateKey::new(private_key);
        let hash_public_key = pk.get_public_key::<C::Hasher>();
        let fingeprint_result = self.hash_public_key_to_fingerprint.get(&hash_public_key);
        if fingeprint_result.is_some() {
            let key_result = self.key_map.get(fingeprint_result.unwrap());
            if key_result.is_some() {
                let key = key_result.unwrap();
                let inner_proof = self.inner_circuit.prove_base(private_key, action_hash)?;
                let fixed_proof = key.fixed_circuit.prove_base(&inner_proof)?;
                self.wrapper_circuit
                    .prove_base(&fixed_proof, key.fixed_circuit.get_verifier_config_ref())
            } else {
                anyhow::bail!("Key not found");
            }
        } else {
            anyhow::bail!("Key not found");
        }
    }

    fn get_public_keys(&self) -> Vec<QHashOut<C::F>> {
        self.key_map.keys().cloned().collect()
    }

    fn get_hash_public_keys(&self) -> Vec<QHashOut<C::F>> {
        self.hash_public_key_to_fingerprint
            .keys()
            .cloned()
            .collect()
    }

    fn add_hash_public_key(&mut self, hash_public_key: QHashOut<C::F>) -> QHashOut<C::F> {
        if self
            .hash_public_key_to_fingerprint
            .contains_key(&hash_public_key)
        {
            return self.hash_public_key_to_fingerprint[&hash_public_key];
        }

        let fixed_circuit = ZKSignatureCircuitSimpleFixedPublicKey::new_from_isc(
            &self.inner_circuit,
            hash_public_key,
        );
        let circuit_fingerprint_public_key = fixed_circuit.get_fingerprint();
        let key = SimpleZKSignatureWalletKey {
            circuit_fingerprint_public_key,
            hash_public_key,
            fixed_circuit,
        };
        self.key_map.insert(hash_public_key, key);
        self.hash_public_key_to_fingerprint
            .insert(hash_public_key, circuit_fingerprint_public_key);

        circuit_fingerprint_public_key
    }

    fn remove_public_key(&mut self, public_key: QHashOut<C::F>) {
        let fingerprint_result = self.hash_public_key_to_fingerprint.remove(&public_key);
        if fingerprint_result.is_some() {
            self.key_map.remove(&fingerprint_result.unwrap());
        }
    }

    fn contains_public_key(&self, public_key: QHashOut<C::F>) -> bool {
        self.key_map.contains_key(&public_key)
    }

    fn contains_hash_public_key(&self, hash_public_key: QHashOut<C::F>) -> bool {
        self.hash_public_key_to_fingerprint
            .contains_key(&hash_public_key)
    }

    fn get_public_key_from_hash_public_key(
        &self,
        hash_public_key: QHashOut<C::F>,
    ) -> Option<QHashOut<C::F>> {
        let result = self.hash_public_key_to_fingerprint.get(&hash_public_key);
        if result.is_some() {
            Some(*result.unwrap())
        } else {
            None
        }
    }

    fn clear(&mut self) {
        self.hash_public_key_to_fingerprint.clear();
        self.key_map.clear();
    }
}

pub struct MemoryZKSignatureWallet<
    C: GenericConfig<D> + 'static,
    const D: usize,
    BP: ZKSignatureBasicWalletProvider<C, D>,
> where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub basic_wallet: BP,
    fingerprint_public_key_to_private_key: HashMap<QHashOut<C::F>, QHashOut<C::F>>,
}

impl<C: GenericConfig<D> + 'static, const D: usize> QStandardCircuit<C, D>
    for MemoryZKSignatureWallet<C, D, SimpleZKSignatureWallet<C, D>>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn get_fingerprint(&self) -> QHashOut<C::F> {
        self.basic_wallet.wrapper_circuit.get_fingerprint()
    }

    fn get_verifier_config_ref(&self) -> &VerifierOnlyCircuitData<C, D> {
        self.basic_wallet.wrapper_circuit.get_verifier_config_ref()
    }

    fn get_common_circuit_data_ref(&self) -> &CommonCircuitData<C::F, D> {
        self.basic_wallet
            .wrapper_circuit
            .get_common_circuit_data_ref()
    }
}
impl<
        C: GenericConfig<D> + 'static,
        const D: usize,
        BP: ZKSignatureBasicWalletProvider<C, D> + Clone,
    > Clone for MemoryZKSignatureWallet<C, D, BP>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn clone(&self) -> Self {
        Self {
            basic_wallet: self.basic_wallet.clone(),
            fingerprint_public_key_to_private_key: self
                .fingerprint_public_key_to_private_key
                .clone(),
        }
    }
}
impl<C: GenericConfig<D> + 'static, const D: usize, BP: ZKSignatureBasicWalletProvider<C, D>>
    MemoryZKSignatureWallet<C, D, BP>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub fn new(basic_wallet: BP) -> Self {
        Self {
            basic_wallet,
            fingerprint_public_key_to_private_key: HashMap::new(),
        }
    }
    pub fn new_memory() -> MemoryZKSignatureWallet<C, D, SimpleZKSignatureWallet<C, D>> {
        MemoryZKSignatureWallet::<C, D, SimpleZKSignatureWallet<C, D>>::new(
            SimpleZKSignatureWallet::new(),
        )
    }
}

impl<C: GenericConfig<D> + 'static, const D: usize, BP: ZKSignatureBasicWalletProvider<C, D>>
    ZKSignatureBasicWalletProvider<C, D> for MemoryZKSignatureWallet<C, D, BP>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn zk_sign(
        &self,
        private_key: QHashOut<C::F>,
        action_hash: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.basic_wallet.zk_sign(private_key, action_hash)
    }

    fn get_public_keys(&self) -> Vec<QHashOut<C::F>> {
        self.basic_wallet.get_public_keys()
    }

    fn get_hash_public_keys(&self) -> Vec<QHashOut<C::F>> {
        self.basic_wallet.get_hash_public_keys()
    }

    fn add_hash_public_key(&mut self, hash_public_key: QHashOut<C::F>) -> QHashOut<C::F> {
        self.basic_wallet.add_hash_public_key(hash_public_key)
    }

    fn remove_public_key(&mut self, public_key: QHashOut<C::F>) {
        self.fingerprint_public_key_to_private_key
            .remove(&public_key);
        self.basic_wallet.remove_public_key(public_key)
    }

    fn contains_public_key(&self, public_key: QHashOut<C::F>) -> bool {
        self.basic_wallet.contains_public_key(public_key)
    }

    fn contains_hash_public_key(&self, hash_public_key: QHashOut<C::F>) -> bool {
        self.basic_wallet.contains_public_key(hash_public_key)
    }

    fn get_public_key_from_hash_public_key(
        &self,
        hash_public_key: QHashOut<C::F>,
    ) -> Option<QHashOut<C::F>> {
        self.basic_wallet
            .get_public_key_from_hash_public_key(hash_public_key)
    }

    fn clear(&mut self) {
        self.fingerprint_public_key_to_private_key.clear();
        self.basic_wallet.clear();
    }
}

impl<C: GenericConfig<D> + 'static, const D: usize, BP: ZKSignatureBasicWalletProvider<C, D>>
    ZKSignatureWalletProvider<C, D> for MemoryZKSignatureWallet<C, D, BP>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn sign(
        &self,
        public_key: QHashOut<C::F>,
        action_hash: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let private_key = self.fingerprint_public_key_to_private_key.get(&public_key);
        if private_key.is_some() {
            self.zk_sign(*private_key.unwrap(), action_hash)
        } else {
            anyhow::bail!("Private key not found")
        }
    }

    fn add_private_key(&mut self, private_key: QHashOut<C::F>) -> QHashOut<C::F> {
        let pk = SimpleL2PrivateKey::new(private_key);
        let hash_public_key = pk.get_public_key::<C::Hasher>();
        let public_key = self.basic_wallet.add_hash_public_key(hash_public_key);
        self.fingerprint_public_key_to_private_key
            .insert(public_key, private_key);
        public_key
    }

    fn sign_by_hash_public_key(
        &self,
        hash_public_key: QHashOut<C::F>,
        action_hash: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let public_key_result = self.get_public_key_from_hash_public_key(hash_public_key);
        if public_key_result.is_some() {
            self.sign(public_key_result.unwrap(), action_hash)
        } else {
            anyhow::bail!("Public key not found")
        }
    }
}
