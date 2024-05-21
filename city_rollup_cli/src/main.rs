mod subcommand;

use shadow_rs::shadow;

shadow!(build);

use clap::Parser;

use crate::subcommand::l2transfer;
use crate::subcommand::l2worker;
use crate::subcommand::orchestrator;
use crate::subcommand::rpcserver;
use crate::subcommand::Cli;
use crate::subcommand::Commands;

fn main() -> anyhow::Result<()> {
    dotenv::dotenv().ok();
    //city_common::setup_logger();

    let cli = Cli::parse();
    match cli.command {
        Commands::RPCServer(args) => {
            rpcserver::run(args)?;
        },
        Commands::L2Transfer(args) => {
            l2transfer::run(args)?;
        }
        Commands::L2Worker(args) => {
            l2worker::run(args)?;
        }
        Commands::Orchestrator(args) => {
            orchestrator::run(args)?;
        }
    };
    Ok::<_, anyhow::Error>(())
}
