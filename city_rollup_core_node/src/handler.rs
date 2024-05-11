use std::net::SocketAddr;

use bytes::Buf;
use bytes::Bytes;
use city_common::cli::args::RPCServerArgs;
use city_common_circuit::circuits::zk_signature::verify_standard_wrapped_zk_signature_proof;
use city_redis_store::RedisStore;
use city_redis_store::ADD_WITHDRWAL_COUNTER;
use city_redis_store::CLAIM_L1_DEPOSIT_COUNTER;
use city_redis_store::TOKEN_TRANSFER_COUNTER;
use city_rollup_common::api::data::block::requested_actions::CityAddWithdrawalRequest;
use city_rollup_common::api::data::block::requested_actions::CityClaimDepositRequest;
use city_rollup_common::api::data::block::requested_actions::CityRegisterUserRequest;
use city_rollup_common::api::data::block::requested_actions::CityRequest;
use city_rollup_common::api::data::block::requested_actions::CityTokenTransferRequest;
use city_rollup_common::qworker::job_id::QProvingJobDataID;
use city_rollup_worker_dispatch::implementations::redis::RedisDispatcher;
use city_rollup_worker_dispatch::implementations::redis::Q_TX;
use city_rollup_worker_dispatch::traits::proving_dispatcher::ProvingDispatcher;
use city_store::config::C;
use city_store::config::D;
use city_store::config::F;
use http_body_util::BodyExt;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::header;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::Method;
use hyper::Request;
use hyper::Response;
use hyper::StatusCode;
use hyper_util::rt::TokioIo;
use plonky2::plonk::config::GenericHashOut;
use tokio::net::TcpListener;
use tokio::task::spawn_blocking;

use crate::rpc::RequestParams;
use crate::rpc::ResponseResult;
use crate::rpc::RpcRequest;
use crate::rpc::RpcResponse;
use crate::rpc::Version;

type BoxBody = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;

static NOTFOUND: &[u8] = b"Not Found";
static INDEX_HTML: &str = include_str!("../public/index.html");

#[derive(Clone)]
pub struct CityRollupRPCServerHandler {
    pub args: RPCServerArgs,
    pub store: RedisStore,
    pub dispatcher: RedisDispatcher,
}

impl CityRollupRPCServerHandler {
    pub async fn new(args: RPCServerArgs, store: RedisStore) -> anyhow::Result<Self> {
        Ok(Self {
            args,
            dispatcher: RedisDispatcher::new_with_pool(store.get_pool())?,
            store,
        })
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

    async fn verify_signature_proof(
        &self,
        user_id: u64,
        signature_proof: Vec<u8>,
    ) -> anyhow::Result<()> {
        let mut pubkey_bytes: Vec<u8> = self
            .store
            .get_user_public_key(user_id)
            .await?
            .ok_or(anyhow::anyhow!("User not found"))?;
        pubkey_bytes.reverse();

        spawn_blocking(move || {
            verify_standard_wrapped_zk_signature_proof::<C, D>(pubkey_bytes, signature_proof)?;
            Ok::<_, anyhow::Error>(())
        })
        .await??;

        Ok(())
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
            // User
            RequestParams::TokenTransfer(req) => {
                self.verify_signature_proof(req.user_id, req.signature_proof.clone())
                    .await?;

                let (token_transfer_id, block_id) = self
                    .store
                    .incr_block_state_counter(TOKEN_TRANSFER_COUNTER)
                    .await?;

                let signature_proof_id = QProvingJobDataID::transfer_signature_proof(
                    self.args.rpc_node_id,
                    block_id,
                    token_transfer_id as u32,
                );

                self.store
                    .set_bytes_by_id(signature_proof_id, &req.signature_proof)
                    .await?;

                self.dispatcher
                    .dispatch::<Q_TX>(
                        block_id,
                        CityRequest::<F>::CityTokenTransferRequest((
                            self.args.rpc_node_id,
                            CityTokenTransferRequest::new(
                                req.user_id,
                                req.to,
                                req.value,
                                req.nonce,
                                signature_proof_id,
                            ),
                        )),
                    )
                    .await?;

                String::new()
            }
            RequestParams::ClaimDeposit(req) => {
                self.verify_signature_proof(req.user_id, req.signature_proof.clone())
                    .await?;

                let (deposit_id, block_id) = self
                    .store
                    .incr_block_state_counter(CLAIM_L1_DEPOSIT_COUNTER)
                    .await?;

                let signature_proof_id = QProvingJobDataID::claim_deposit_l1_signature_proof(
                    self.args.rpc_node_id,
                    block_id,
                    deposit_id as u32,
                );

                self.store
                    .set_bytes_by_id(signature_proof_id, &req.signature_proof)
                    .await?;

                self.dispatcher
                    .dispatch::<Q_TX>(
                        block_id,
                        CityRequest::<F>::CityClaimDepositRequest((
                            self.args.rpc_node_id,
                            CityClaimDepositRequest::new(
                                req.user_id,
                                req.nonce,
                                req.deposit_id,
                                req.value,
                                req.txid,
                                req.public_key,
                                signature_proof_id,
                            ),
                        )),
                    )
                    .await?;

                String::new()
            }
            RequestParams::AddWithdrawal(req) => {
                self.verify_signature_proof(req.user_id, req.signature_proof.clone())
                    .await?;

                let (withdrawal_id, block_id) = self
                    .store
                    .incr_block_state_counter(ADD_WITHDRWAL_COUNTER)
                    .await?;

                let signature_proof_id = QProvingJobDataID::withdrawal_signature_proof(
                    self.args.rpc_node_id,
                    block_id,
                    withdrawal_id as u32,
                );

                self.store
                    .set_bytes_by_id(signature_proof_id, &req.signature_proof)
                    .await?;

                self.dispatcher
                    .dispatch::<Q_TX>(
                        block_id,
                        CityRequest::<F>::CityAddWithdrawalRequest((
                            self.args.rpc_node_id,
                            CityAddWithdrawalRequest::new(
                                req.user_id,
                                req.value,
                                req.nonce,
                                withdrawal_id.into(),
                                req.destination_type,
                                req.destination,
                                signature_proof_id,
                            ),
                        )),
                    )
                    .await?;

                String::new()
            }
            RequestParams::RegisterUser(req) => {
                let (user_id, block_id) = self
                    .store
                    .register_user(&req.public_key.0.to_bytes())
                    .await?;

                self.dispatcher
                    .dispatch::<Q_TX>(
                        block_id,
                        CityRequest::CityRegisterUserRequest((
                            self.args.rpc_node_id,
                            CityRegisterUserRequest::new(user_id, req.public_key),
                        )),
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

pub async fn run(args: RPCServerArgs) -> anyhow::Result<()> {
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
