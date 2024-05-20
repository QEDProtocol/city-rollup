use std::future::Future;

use lazy_static::lazy_static;
use tokio::runtime::{Builder, Runtime};

lazy_static! {
    static ref RT: Runtime = Builder::new_multi_thread().build().unwrap();
}

pub fn block_on<F: Future>(future: F) -> F::Output {
    RT.handle().block_on(future)
}
