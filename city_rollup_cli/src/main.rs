mod error;
mod subcommand;

use shadow_rs::shadow;

shadow!(build);

use clap::Parser;
use error::Result;

use crate::subcommand::l2transfer;
use crate::subcommand::l2worker;
use crate::subcommand::orchestrator;
use crate::subcommand::rpcserver;
use crate::subcommand::Cli;
use crate::subcommand::Commands;

#[tokio::main]
async fn main() -> Result<()> {
    dotenv::dotenv().ok();
    //city_common::setup_logger();

    let cli = Cli::parse();
    match cli.command {
        Commands::RPCServer(args) => rpcserver::run(args).await?,
        Commands::L2Transfer(args) => l2transfer::run(args).await?,
        Commands::L2Worker(args) => l2worker::run(args).await?,
        Commands::Orchestrator(args) => orchestrator::run(args).await?,
    }

    Ok(())
}
