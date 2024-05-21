use std::future::Future;

use lazy_static::lazy_static;
use tokio::runtime::Handle;

pub fn block_on<F: Future>(future: F) -> F::Output {
    futures::executor::block_on(future)
}
