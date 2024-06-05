use city_common::cli::{message::CITY_ROLLUP_BANNER, args::APIServerArgs};


#[tokio::main]
pub async fn run(_args: APIServerArgs) -> anyhow::Result<()> {
    println!(
        "{}",
        CITY_ROLLUP_BANNER
    );
    Ok(())
}
