use city_common::cli::args::RPCServerArgs;

use crate::build;
use crate::error::Result;

pub async fn run(args: RPCServerArgs) -> Result<()> {
    println!(
        "
----------------------------------------
|           CityRollup v{}             |
----------------------------------------
",
        build::PKG_VERSION
    );
    //let indexer = city_indexer::Indexer::new(args).await?;
    //indexer.listen().await?;
    city_rollup_core_node::rpc::start_city_rollup_rpc_server(args).await?;
    Ok(())
}
