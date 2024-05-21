use std::marker::PhantomData;
use std::net::SocketAddr;

use bytes::Buf;
use bytes::Bytes;
use city_common::cli::args::RPCServerArgs;
use city_redis_store::RedisStore;
use city_rollup_common::actors::traits::OrchestratorRPCEventSenderSync;
use city_rollup_common::api::data::block::rpc_request::*;
use city_rollup_worker_dispatch::implementations::redis::QueueCmd;
use city_rollup_worker_dispatch::implementations::redis::RedisQueue;
use city_rollup_worker_dispatch::implementations::redis::Q_CMD;
use city_rollup_worker_dispatch::implementations::redis::Q_RPC_ADD_WITHDRAWAL;
use city_rollup_worker_dispatch::implementations::redis::Q_RPC_CLAIM_DEPOSIT;
use city_rollup_worker_dispatch::implementations::redis::Q_RPC_REGISTER_USER;
use city_rollup_worker_dispatch::implementations::redis::Q_RPC_TOKEN_TRANSFER;
use city_rollup_worker_dispatch::traits::proving_dispatcher::ProvingDispatcher;
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
use plonky2::hash::hash_types::RichField;
use tokio::net::TcpListener;

use crate::rpc::RequestParams;
use crate::rpc::ResponseResult;
use crate::rpc::RpcRequest;
use crate::rpc::RpcResponse;
use crate::rpc::Version;

type BoxBody = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;

static NOTFOUND: &[u8] = b"Not Found";
static INDEX_HTML: &str = include_str!("../public/index.html");

#[derive(Clone)]
pub struct CityRollupRPCServerHandler<F: RichField> {
    pub args: RPCServerArgs,
    pub store: RedisStore,
    pub tx_queue: RedisQueue,
    _marker: PhantomData<F>,
}

impl<F: RichField> CityRollupRPCServerHandler<F> {
    pub async fn new(args: RPCServerArgs, store: RedisStore) -> anyhow::Result<Self> {
        Ok(Self {
            tx_queue: RedisQueue::new(&args.redis_uri)?,
            args,
            store,
            _marker: PhantomData,
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
        // let pubkey_bytes = self.store.get_user_state(user_id)?.public_key;
        //
        // spawn_blocking(move || {
        //     verify_standard_wrapped_zk_signature_proof::<C, D>(pubkey_bytes, signature_proof)?;
        //     Ok::<_, anyhow::Error>(())
        // })
        // .await??;

        Ok(())
    }

    pub async fn serve_rpc_requests(
        &mut self,
        req: Request<Incoming>,
    ) -> anyhow::Result<Response<BoxBody>> {
        // Aggregate the body...
        let whole_body = req.collect().await?.aggregate();
        // Decode as JSON...
        let data = serde_json::from_reader::<_, RpcRequest<F>>(whole_body.reader())?;
        let res = match data.request {
            RequestParams::TokenTransfer(req) => {
                self.verify_signature_proof(req.user_id, req.signature_proof.clone())
                    .await?;

                self.notify_rpc_token_transfer(&req)?;
            }
            RequestParams::ClaimDeposit(req) => {
                self.verify_signature_proof(req.user_id, req.signature_proof.clone())
                    .await?;

                self.notify_rpc_claim_deposit(&req)?;
            }
            RequestParams::AddWithdrawal(req) => {
                self.verify_signature_proof(req.user_id, req.signature_proof.clone())
                    .await?;

                self.notify_rpc_add_withdrawal(&req)?;
            }
            RequestParams::RegisterUser(req) => {
                self.notify_rpc_register_user(&req)?;
            }
            RequestParams::ProduceBlock => self.notify_rpc_produce_block()?,
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

impl<F: RichField> OrchestratorRPCEventSenderSync<F> for CityRollupRPCServerHandler<F> {
    fn notify_rpc_claim_deposit(
        &mut self,
        event: &CityClaimDepositRPCRequest,
    ) -> anyhow::Result<()> {
        self.tx_queue.dispatch(Q_RPC_CLAIM_DEPOSIT, event.clone())?;
        Ok(())
    }

    fn notify_rpc_register_user(
        &mut self,
        event: &CityRegisterUserRPCRequest<F>,
    ) -> anyhow::Result<()> {
        self.tx_queue.dispatch(Q_RPC_REGISTER_USER, event.clone())?;
        Ok(())
    }

    fn notify_rpc_add_withdrawal(
        &mut self,
        event: &CityAddWithdrawalRPCRequest,
    ) -> anyhow::Result<()> {
        self.tx_queue
            .dispatch(Q_RPC_ADD_WITHDRAWAL, event.clone())?;
        Ok(())
    }

    fn notify_rpc_token_transfer(
        &mut self,
        event: &CityTokenTransferRPCRequest,
    ) -> anyhow::Result<()> {
        self.tx_queue
            .dispatch(Q_RPC_TOKEN_TRANSFER, event.clone())?;
        Ok(())
    }

    fn notify_rpc_produce_block(&mut self) -> anyhow::Result<()> {
        println!("produce block");
        self.tx_queue.dispatch(Q_CMD, QueueCmd::ProduceBlock)?;
        Ok(())
    }
}

pub async fn run<F: RichField>(args: RPCServerArgs) -> anyhow::Result<()> {
    let addr: SocketAddr = args.rollup_rpc_address.parse()?;

    let listener = TcpListener::bind(addr).await?;
    println!("Listening on http://{}", addr);
    let store = RedisStore::new(&args.redis_uri)?;
    let handler = CityRollupRPCServerHandler::<F>::new(args, store).await?;

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
