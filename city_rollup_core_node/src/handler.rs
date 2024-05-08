use std::net::SocketAddr;

use bytes::{Buf, Bytes};
use city_common::cli::args::RPCServerArgs;
use city_common_circuit::circuits::zk_signature::verify_standard_wrapped_zk_signature_proof;
use city_rollup_common::{
    api::data::block::requested_actions::{
        CityAddWithdrawalRequest, CityClaimDepositRequest, CityRegisterUserRequest,
        CityTokenTransferRequest,
    },
    qworker::{job_id::QProvingJobDataID, proof_store::QProofStoreWriterAsync},
};
use city_rollup_worker_dispatch::{
    implementations::redis::{
        rollup_key::{
            LAST_BLOCK_ID, TOKEN_TRANSFER_COUNTER, USER_COUNTER, USER_ID, USER_PUBKEY,
            WITHDRWAL_COUNTER,
        },
        RedisStore, Q_DEBUG, Q_TX,
    },
    traits::{
        proving_dispatcher::{KeyValueStoreWithInc, ProvingDispatcher},
        proving_worker::ProvingWorkerListener,
    },
};
use city_store::config::{C, D};
use http_body_util::{BodyExt, Full};
use hyper::{
    body::Incoming, header, server::conn::http1, service::service_fn, Method, Request, Response,
    StatusCode,
};
use hyper_util::rt::TokioIo;
use plonky2::plonk::config::GenericHashOut;
use redis::AsyncCommands;
use tokio::{net::TcpListener, task::spawn_blocking};

use crate::rpc::{RequestParams, ResponseResult, RpcRequest, RpcResponse, Version};

type BoxBody = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;

static NOTFOUND: &[u8] = b"Not Found";
static INDEX_HTML: &str = include_str!("../public/index.html");

#[derive(Clone)]
pub struct CityRollupRPCServerHandler {
    pub args: RPCServerArgs,
    pub store: RedisStore,
}

impl CityRollupRPCServerHandler {
    pub async fn new(args: RPCServerArgs, store: RedisStore) -> anyhow::Result<Self> {
        Ok(Self { args, store })
    }

    pub async fn handle(
        &mut self,
        req: Request<hyper::body::Incoming>,
    ) -> anyhow::Result<Response<BoxBody>> {
        match (req.method(), req.uri().path()) {
            (&Method::GET, "/editor") => Ok(serve_editor()),
            (&Method::POST, "/") => self.serve_rpc_requests(req).await,
            _ => Ok(not_found()),
        }
    }

    pub async fn serve_rpc_requests(
        &mut self,
        req: Request<Incoming>,
    ) -> anyhow::Result<Response<BoxBody>> {
        // Aggregate the body...
        let whole_body = req.collect().await?.aggregate();
        // Decode as JSON...
        let data = serde_json::from_reader::<_, RpcRequest>(whole_body.reader())?;
        let res = match data.request {
            // Dev
            RequestParams::Get(key) => hex::encode(self.store.get(&key).await?),
            RequestParams::Set((key, value)) => {
                self.store.put(&key, &value).await?;
                String::new()
            }
            RequestParams::Push((topic, value)) => {
                self.store.dispatch::<Q_DEBUG>(topic, &value).await?;
                String::new()
            }
            RequestParams::Pull(topic) => {
                hex::encode(self.store.get_next_message::<Q_DEBUG>(topic).await?)
            }

            // User
            RequestParams::TokenTransfer(req) => {
                let mut pubkey_bytes: Vec<u8> = self.store.hget(USER_PUBKEY, req.user_id).await?;
                pubkey_bytes.reverse();

                let signature_proof = spawn_blocking(move || {
                    let proof = verify_standard_wrapped_zk_signature_proof::<C, D>(
                        pubkey_bytes,
                        req.signature_proof,
                    )?;
                    Ok::<_, anyhow::Error>(proof)
                })
                .await??;

                let (signature_proof_id, block_id) = {
                    let mut conn = self.store.get_connection().await?;
                    let block_id: u64 = conn.get(LAST_BLOCK_ID).await.unwrap_or(0);
                    let transfer_counter: u32 =
                        conn.incr(TOKEN_TRANSFER_COUNTER, 1).await.unwrap_or(1);

                    let signature_proof_id = QProvingJobDataID::transfer_signature_proof(
                        self.args.rpc_node_id,
                        block_id,
                        transfer_counter - 1,
                    );

                    (signature_proof_id, block_id)
                };

                self.store
                    .set_proof_by_id(signature_proof_id, &signature_proof)
                    .await?;

                self.store
                    .dispatch::<Q_TX>(
                        block_id,
                        &serde_json::to_vec(&CityTokenTransferRequest::new(
                            req.user_id,
                            req.to,
                            req.value,
                            req.nonce,
                            signature_proof_id,
                        ))?,
                    )
                    .await?;

                String::new()
            }
            RequestParams::ClaimDeposit(req) => {
                let mut pubkey_bytes: Vec<u8> = self.store.hget(USER_PUBKEY, req.user_id).await?;
                pubkey_bytes.reverse();

                let signature_proof = spawn_blocking(move || {
                    let proof = verify_standard_wrapped_zk_signature_proof::<C, D>(
                        pubkey_bytes,
                        req.signature_proof,
                    )?;
                    Ok::<_, anyhow::Error>(proof)
                })
                .await??;

                let (signature_proof_id, block_id) = {
                    let mut conn = self.store.get_connection().await?;
                    let block_id: u64 = conn.get(LAST_BLOCK_ID).await.unwrap_or(0);

                    let signature_proof_id = QProvingJobDataID::claim_deposit_l1_signature_proof(
                        self.args.rpc_node_id,
                        block_id,
                        req.deposit_id,
                    );

                    (signature_proof_id, block_id)
                };

                self.store
                    .set_proof_by_id(signature_proof_id, &signature_proof)
                    .await?;

                self.store
                    .dispatch::<Q_TX>(
                        block_id,
                        &serde_json::to_vec(&CityClaimDepositRequest::new(
                            req.user_id,
                            req.nonce,
                            req.deposit_id,
                            req.value,
                            req.txid,
                            req.public_key,
                            signature_proof_id,
                        ))?,
                    )
                    .await?;

                String::new()
            }
            RequestParams::AddWithdrawal(req) => {
                let mut pubkey_bytes: Vec<u8> = self.store.hget(USER_PUBKEY, req.user_id).await?;
                pubkey_bytes.reverse();

                let signature_proof = spawn_blocking(move || {
                    let proof = verify_standard_wrapped_zk_signature_proof::<C, D>(
                        pubkey_bytes,
                        req.signature_proof,
                    )?;
                    Ok::<_, anyhow::Error>(proof)
                })
                .await??;

                let (signature_proof_id, block_id, withdrawal_id) = {
                    let mut conn = self.store.get_connection().await?;
                    let block_id: u64 = conn.get(LAST_BLOCK_ID).await.unwrap_or(0);
                    let withdrawal_counter: u32 =
                        conn.incr(WITHDRWAL_COUNTER, 1).await.unwrap_or(1);
                    let withdrawal_id = withdrawal_counter - 1;

                    let signature_proof_id = QProvingJobDataID::withdrawal_signature_proof(
                        self.args.rpc_node_id,
                        block_id,
                        withdrawal_id,
                    );

                    (signature_proof_id, block_id, withdrawal_id)
                };
                self.store
                    .set_proof_by_id(signature_proof_id, &signature_proof)
                    .await?;

                self.store
                    .dispatch::<Q_TX>(
                        block_id,
                        &serde_json::to_vec(&CityAddWithdrawalRequest::new(
                            req.user_id,
                            req.value,
                            req.nonce,
                            withdrawal_id.into(),
                            req.destination_type,
                            req.destination,
                            signature_proof_id,
                        ))?,
                    )
                    .await?;
                String::new()
            }
            RequestParams::RegisterUser(req) => {
                let mut pubkey_bytes = req.public_key.0.to_bytes();
                pubkey_bytes.reverse();

                let (user_id, block_id) = {
                    let mut pipeline = redis::pipe();
                    pipeline.atomic();

                    let mut conn = self.store.get_connection().await?;
                    let count: u64 = conn.get(USER_COUNTER).await.unwrap_or(0);
                    let user_id: Option<u64> = conn.hget(USER_ID, &pubkey_bytes).await?;
                    let [user_id]: [u64; 1] = if user_id.is_none() {
                        pipeline
                            .hset(USER_ID, &pubkey_bytes, count)
                            .ignore()
                            .hset(USER_PUBKEY, count, &pubkey_bytes)
                            .ignore()
                            .incr(USER_COUNTER, 1)
                            .ignore()
                            .hget(USER_ID, &pubkey_bytes)
                            .query_async(&mut *conn)
                            .await?
                    } else {
                        pipeline
                            .hget(USER_ID, &pubkey_bytes)
                            .query_async(&mut *conn)
                            .await?
                    };

                    let block_id: u64 = conn.get(LAST_BLOCK_ID).await.unwrap_or(0);

                    (user_id, block_id)
                };

                self.store
                    .dispatch::<Q_TX>(
                        block_id,
                        &serde_json::to_vec(&CityRegisterUserRequest::new(
                            user_id,
                            self.args.rpc_node_id.into(),
                            req.public_key,
                        ))?,
                    )
                    .await?;

                user_id.to_string()
            }
        };

        let response = RpcResponse {
            jsonrpc: Version::V2,
            id: Some(data.id.clone()),
            result: ResponseResult::Success(res),
        };

        // TODO: handle rpc error
        Ok(Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .body(full(serde_json::to_vec(&response)?))?)
    }
}

pub async fn start_city_rollup_rpc_server(args: RPCServerArgs) -> anyhow::Result<()> {
    let addr: SocketAddr = args.rollup_rpc_address.parse()?;

    let listener = TcpListener::bind(addr).await?;
    println!("Listening on http://{}", addr);
    let store = RedisStore::new(&args.redis_uri).await?;
    let handler = CityRollupRPCServerHandler::new(args, store).await?;

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let handler = handler.clone();

        tokio::task::spawn(async move {
            // TODO: should remove the extra clone
            let service = service_fn(|req| async { handler.clone().handle(req).await });

            if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                println!("Failed to serve connection: {:?}", err);
            }
        });
    }
}

fn not_found() -> Response<BoxBody> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Full::new(NOTFOUND.into()).map_err(|e| match e {}).boxed())
        .unwrap()
}

fn serve_editor() -> Response<BoxBody> {
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/html")
        .body(Full::new(INDEX_HTML.into()).map_err(|e| match e {}).boxed())
        .unwrap()
}

fn full<T: Into<Bytes>>(chunk: T) -> BoxBody {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}
