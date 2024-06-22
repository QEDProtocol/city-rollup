use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};

use city_common::data::u8bytes::{U8Bytes, U8BytesFixed};
use city_crypto::hash::base_types::hash256::Hash256;
use city_crypto::signature::secp256k1::core::QEDCompressedSecp256K1Signature;
use jsonrpsee::core::async_trait;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::{ErrorObject, ErrorObjectOwned};

use crate::common::request::{
    UPWEncryptedPublicKeyJobRequestPayload, UPWEncryptedZKSignatureJobRequestPayload, UPWJobRequest, UPWJobRequestPayload, UPWZKSignatureJobRequestPayload
};
use crate::worker::store::UserProverWorkerStore;

#[rpc(server, client, namespace = "cr")]
pub trait Rpc {
    #[method(name = "ping")]
    async fn ping(&self, message: String) -> Result<String, ErrorObjectOwned>;
    #[method(name = "prove_secp256k1_signature")]
    async fn prove_secp256k1_signature(
        &self,
        public_key: U8BytesFixed<33>,
        signature: U8BytesFixed<64>,
        message: Hash256,
    ) -> Result<Hash256, ErrorObjectOwned>;
    #[method(name = "prove_zk_signature")]
    async fn prove_zk_signature(
        &self,
        private_key: Hash256,
        message: Hash256,
    ) -> Result<Hash256, ErrorObjectOwned>;
    #[method(name = "prove_zk_signature_enc")]
    async fn prove_zk_signature_enc(
        &self,
        encrypted_private_key: Hash256,
        message: Hash256,
        salt: Hash256,
    ) -> Result<Hash256, ErrorObjectOwned>;
    #[method(name = "get_zk_public_key")]
    async fn get_zk_public_key(
        &self,
        private_key: Hash256,
    ) -> Result<Hash256, ErrorObjectOwned>;
    #[method(name = "get_zk_public_key_enc")]
    async fn get_zk_public_key_enc(
        &self,
        encrypted_private_key: Hash256,
        salt: Hash256,
    ) -> Result<Hash256, ErrorObjectOwned>;
    #[method(name = "get_result")]
    async fn get_result(&self, id: Hash256) -> Result<U8Bytes, ErrorObjectOwned>;
}

#[derive(Clone)]
pub struct RpcServerImpl {
    pub store: Arc<Mutex<UserProverWorkerStore>>,
    pub tx_worker: Sender<UPWJobRequest>,
}

#[async_trait]
impl RpcServer for RpcServerImpl {
    async fn ping(&self, message: String) -> Result<String, ErrorObjectOwned> {
        Ok(message.chars().rev().collect::<String>())
    }
    async fn get_result(&self, id: Hash256) -> Result<U8Bytes, ErrorObjectOwned> {
        let result = self.store.lock().unwrap().get_result_and_clear(&id);

        if result.is_none() {
            return Err(ErrorObject::owned(404, "Result not found", Some(0)));
        }
        Ok(U8Bytes(result.unwrap()))
    }
    async fn prove_secp256k1_signature(
        &self,
        public_key: U8BytesFixed<33>,
        signature: U8BytesFixed<64>,
        message: Hash256,
    ) -> Result<Hash256, ErrorObjectOwned> {
        let id = Hash256::rand();
        let request = UPWJobRequest {
            request_id: id,
            payload: UPWJobRequestPayload::Secp256K1SignatureProof(
                QEDCompressedSecp256K1Signature {
                    public_key: public_key.0,
                    signature: signature.0,
                    message,
                },
            ),
        };
        self.tx_worker
            .send(request)
            .map_err(|_| ErrorObject::owned(500, "Error sending request to worker", Some(0)))?;
        Ok(id)
    }
    async fn prove_zk_signature(
        &self,
        private_key: Hash256,
        message: Hash256,
    ) -> Result<Hash256, ErrorObjectOwned> {
        let id = Hash256::rand();
        let request = UPWJobRequest {
            request_id: id,
            payload: UPWJobRequestPayload::ZKSignatureProof(UPWZKSignatureJobRequestPayload {
                private_key,
                message,
            }),
        };
        self.tx_worker
            .send(request)
            .map_err(|_| ErrorObject::owned(500, "Error sending request to worker", Some(0)))?;
        Ok(id)
    }
    async fn prove_zk_signature_enc(
        &self,
        encrypted_private_key: Hash256,
        message: Hash256,
        salt: Hash256,
    ) -> Result<Hash256, ErrorObjectOwned> {
        let id = Hash256::rand();
        let request = UPWJobRequest {
            request_id: id,
            payload: UPWJobRequestPayload::EncryptedZKSignatureProof(
                UPWEncryptedZKSignatureJobRequestPayload {
                    message,
                    salt,
                    encrypted_private_key,
                },
            ),
        };
        self.tx_worker
            .send(request)
            .map_err(|_| ErrorObject::owned(500, "Error sending request to worker", Some(0)))?;
        Ok(id)
    }

    async fn get_zk_public_key(
        &self,
        private_key: Hash256,
    ) -> Result<Hash256, ErrorObjectOwned>{
        let id = Hash256::rand();
        let request = UPWJobRequest {
            request_id: id,
            payload: UPWJobRequestPayload::GetPublicKey(private_key),
        };
        self.tx_worker
            .send(request)
            .map_err(|_| ErrorObject::owned(500, "Error sending request to worker", Some(0)))?;
        Ok(id)
    }
    async fn get_zk_public_key_enc(
        &self,
        encrypted_private_key: Hash256,
        salt: Hash256,
    ) -> Result<Hash256, ErrorObjectOwned> {
        let id = Hash256::rand();
        let request = UPWJobRequest {
            request_id: id,
            payload: UPWJobRequestPayload::EncryptedGetPublicKey(
                UPWEncryptedPublicKeyJobRequestPayload {
                    salt,
                    encrypted_private_key,
                },
            ),
        };
        self.tx_worker
            .send(request)
            .map_err(|_| ErrorObject::owned(500, "Error sending request to worker", Some(0)))?;
        Ok(id)
    }
}
