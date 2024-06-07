use city_common::cli::{message::CITY_ROLLUP_BANNER, args::L2WorkerArgs};


pub fn run(args: L2WorkerArgs) -> anyhow::Result<()> {
    println!(
        "{}",
        CITY_ROLLUP_BANNER
    );
    city_rollup_core_worker::run(args)?;
    Ok(())
}
