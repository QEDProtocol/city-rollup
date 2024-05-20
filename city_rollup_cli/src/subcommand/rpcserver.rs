use city_common::cli::args::RPCServerArgs;
use city_store::config::F;

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
    city_rollup_core_node::handler::run::<F>(args).await?;
    Ok(())
}
