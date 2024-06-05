use city_common::cli::{args::RPCServerArgs, message::CITY_ROLLUP_BANNER};
use city_store::config::F;

use crate::build;

#[tokio::main]
pub async fn run(args: RPCServerArgs) -> anyhow::Result<()> {
    println!(
        "{}",
        CITY_ROLLUP_BANNER
    );
    city_rollup_core_node::handler::run::<F>(args).await?;
    Ok(())
}
