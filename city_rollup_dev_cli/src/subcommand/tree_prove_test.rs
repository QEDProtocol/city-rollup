use crate::build;
use crate::error::Result;
use city_common::cli::dev_args::TreeProveTestArgs;

pub async fn run(args: TreeProveTestArgs) -> Result<()> {
    tracing::info!(
        "
----------------------------------------
|           CityRollup v{}             |
----------------------------------------
{}
",
        build::PKG_VERSION,
        args.network
    );
    Ok(())
}
