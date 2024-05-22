use city_common::cli::args::APIServerArgs;

use crate::build;

#[tokio::main]
pub async fn run(args: APIServerArgs) -> anyhow::Result<()> {
    println!(
        "
----------------------------------------
|           CityRollup v{}          |
----------------------------------------
",
        build::PKG_VERSION
    );
    city_rollup_core_api::run_server(args).await?;
    Ok(())
}
