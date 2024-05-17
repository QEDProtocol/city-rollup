use crate::build;
use crate::error::Result;
use city_common::cli::dev_args::TreeProveTestArgs;
pub async fn run(_args: TreeProveTestArgs) -> Result<()> {
    println!(
        "
----------------------------------------
|           CityRollup v{}             |
----------------------------------------
",
        build::PKG_VERSION
    );
    Ok(())
}
