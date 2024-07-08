

use std::sync::{Arc, Mutex};

use crate::api::RpcServerImpl;
use crate::common::enc::SimpleZeroPadEncryptionHelper;
use city_common::logging::trace_timer::TraceTimer;
use city_crypto::hash::base_types::hash256::Hash256;
use jsonrpsee::server::Server;
use crate::worker::processor::UserProverWorker;
use crate::worker::store::UserProverWorkerStore;
use crate::api::RpcServer;

use hyper::Method;
use tower_http::cors::{Any, CorsLayer};

pub async fn run_server(server_addr: String, api_key: Hash256) -> anyhow::Result<()> {
    let mut timer = TraceTimer::new("user_prover_api_server");
    timer.lap("initializing server");
    let encryption_helper = SimpleZeroPadEncryptionHelper::new(api_key);
    let server_addr_copy = server_addr.clone();

	let cors = CorsLayer::new()
        // Allow `POST` when accessing the resource
        .allow_methods([Method::POST])
        // Allow requests from any origin
        .allow_origin(Any)
        .allow_headers([hyper::header::CONTENT_TYPE]);
    let middleware = tower::ServiceBuilder::new().layer(cors);

    // The RPC exposes the access control for filtering and the middleware for
    // modifying requests / responses. These features are independent of one another
    // and can also be used separately.
    // In this example, we use both features.
    let server = Server::builder().set_http_middleware(middleware).build(server_addr).await?;
    let store = Arc::new(Mutex::new(UserProverWorkerStore::new()));
    let tx_worker = UserProverWorker::start_worker(store.clone(), &encryption_helper);

    
    let store_rpc = store.clone();
    let rpc_server_impl = RpcServerImpl {  store: store_rpc, tx_worker};
    timer.event(format!("server started at {}", server_addr_copy));
    let handle = server.start(rpc_server_impl.into_rpc());
    tokio::spawn(handle.stopped());
    Ok(futures::future::pending::<()>().await)
}
