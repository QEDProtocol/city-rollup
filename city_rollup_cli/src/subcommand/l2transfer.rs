use city_common::cli::args::L2TransferArgs;

use crate::build;

pub fn run(_args: L2TransferArgs) -> anyhow::Result<()> {
    println!(
        "
----------------------------------------
|           CityRollup v{}          |
----------------------------------------
",
        build::PKG_VERSION
    );
    Ok(())
}
