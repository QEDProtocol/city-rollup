mod error;
mod subcommand;

use shadow_rs::shadow;

shadow!(build);

use clap::Parser;
use error::Result;

#[cfg(debug_assertions)]
use crate::subcommand::l2transfer;
use crate::subcommand::rpcserver;
#[cfg(debug_assertions)]
use crate::subcommand::worker;
use crate::subcommand::Cli;
use crate::subcommand::Commands;

#[tokio::main]
async fn main() -> Result<()> {
    dotenv::dotenv().ok();
    //city_common::setup_logger();

    let cli = Cli::parse();
    match cli.command {
        Commands::RPCServer(args) => rpcserver::run(args).await?,
        #[cfg(debug_assertions)]
        Commands::L2Transfer(args) => l2transfer::run(&args).await?,
        Commands::Worker(args) => worker::run(&args).await?,
    }

    Ok(())
}
