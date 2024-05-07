use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;

use bytes::{Buf, Bytes};
use city_common::cli::args::RPCServerArgs;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming as IncomingBody;
use hyper::server::conn::http1;
use hyper::service::Service;
use hyper::{Method, Request, Response, StatusCode};

use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use crate::handler::{CityRollupRPCServerHandler, RPCInputPayload};

type GenericError = Box<dyn std::error::Error + Send + Sync>;
type Result<T> = std::result::Result<T, GenericError>;
type BoxBody = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;

static NOTFOUND: &[u8] = b"Not Found";
//static MUTEX_ERROR: &[u8] = b"{\"error\": \"error aquiriring lock\"}";
static INDEX_HTML: &str = include_str!("../public/index.html");

#[derive(Clone)]
struct CityRollupRPCServer {
    store: CityRollupRPCServerHandler,
}
impl CityRollupRPCServer {
    /*
    pub async fn handle_api_request(
        mut self,
        req: Request<hyper::body::Incoming>,
    ) -> Result<Response<BoxBody>> {
        // Aggregate the body...
        let whole_body = req.collect().await?.aggregate();
        // Decode as JSON...
        let data: RPCInputPayload = serde_json::from_reader(whole_body.reader())?;

        let result = self.store.run_cmd(data).await?;

        Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json")
            .body(Full::new(result.into()).map_err(|e| match e {}).boxed())
            .unwrap())
    }
    pub async fn handle_request(
        self,
        req: Request<hyper::body::Incoming>,
    ) -> Result<Response<BoxBody>> {
        match (req.method(), req.uri().path()) {
            (&Method::GET, "/") | (&Method::GET, "/index.html") => Ok(index_html()),
            (&Method::GET, "/test") => Ok(test_string()),
            (&Method::POST, "/api") => self.handle_api_request(req).await,

            _ => Ok(not_found()),
        }
    }
    */
}
impl Service<Request<IncomingBody>> for CityRollupRPCServer {
    type Response = Response<BoxBody>;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future =
        Pin<Box<dyn Future<Output = std::result::Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, req: Request<IncomingBody>) -> Self::Future {
        /*fn mutex_error_reply() -> std::result::Result<Response<BoxBody>, hyper::Error> {
            Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(
                    Full::new(MUTEX_ERROR.into())
                        .map_err(|e| match e {})
                        .boxed(),
                )
                .unwrap())
        }*/
        /*
        let locked = self.store.lock().unwrap().handle_request(req).
        Box::pin(if locked.is_err() {
            mutex_error_reply()?
        } else {
            locked.unwrap().handle_request(req)
        })
        */
        Box::pin(response_examples(req, self.store.clone()))
    }
}

pub async fn start_city_rollup_rpc_server(args: RPCServerArgs) -> anyhow::Result<()> {
    let addr: SocketAddr = args.rollup_rpc_address.parse()?;

    let listener = TcpListener::bind(addr).await?;
    println!("Listening on http://{}", addr);
    //let store = RedisStore::new(&args.redis_uri).await?;
    let store = CityRollupRPCServerHandler::new_handler(args).await?;
    let svc = CityRollupRPCServer { store: store };

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let svc_clone = svc.clone();
        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new().serve_connection(io, svc_clone).await {
                println!("Failed to serve connection: {:?}", err);
            }
        });
    }
}
/*

pub async fn start_city_rollup_rpc_server(
    args: &RPCServerArgs,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let addr: SocketAddr = args.rollup_rpc_address.parse()?;

    let listener = TcpListener::bind(addr).await?;

    let handler = CityRollupRPCServer::create_server(args.clone()).await?;
    println!(
        "[City Rollup RPC Server] Listening on {}",
        args.rollup_rpc_address
    );

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let svc_clone = handler.clone();

        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new().serve_connection(io, svc_clone).await {
                println!("Failed to serve connection: {:?}", err);
            }
        });
    }
}
*/

async fn response_examples(
    req: Request<hyper::body::Incoming>,
    handler: CityRollupRPCServerHandler,
) -> Result<Response<BoxBody>> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/") | (&Method::GET, "/index.html") => Ok(index_html()),
        (&Method::GET, "/test") => Ok(test_string()),
        (&Method::POST, "/api") => api_post_response(req, handler).await,

        _ => Ok(not_found()),
    }
}
async fn api_post_response(
    req: Request<IncomingBody>,
    handler: CityRollupRPCServerHandler,
) -> Result<Response<BoxBody>> {
    let whole_body = req.collect().await?.aggregate();
    // Decode as JSON...
    let data: RPCInputPayload = serde_json::from_reader(whole_body.reader())?;

    let result = handler.clone().run_cmd(data).await?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .body(Full::new(result.into()).map_err(|e| match e {}).boxed())
        .unwrap())
}

/// HTTP status code 404
fn not_found() -> Response<BoxBody> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Full::new(NOTFOUND.into()).map_err(|e| match e {}).boxed())
        .unwrap()
}
fn test_string() -> Response<BoxBody> {
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/html")
        .body(
            Full::new("<html><head><title>blah</title></head><body>test123</body></html>".into())
                .map_err(|e| match e {})
                .boxed(),
        )
        .unwrap()
}
fn index_html() -> Response<BoxBody> {
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/html")
        .body(Full::new(INDEX_HTML.into()).map_err(|e| match e {}).boxed())
        .unwrap()
}
