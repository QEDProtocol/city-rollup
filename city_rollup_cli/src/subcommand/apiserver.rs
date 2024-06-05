use city_common::cli::args::APIServerArgs;

use crate::build;

#[tokio::main]
pub async fn run(_args: APIServerArgs) -> anyhow::Result<()> {
    tracing::info!(
        "
----------------------------------------
|           CityRollup v{}          |
----------------------------------------
",
        build::PKG_VERSION
    );
    Ok(())
}
