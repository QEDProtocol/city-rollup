mod error;
mod subcommand;

use shadow_rs::shadow;

shadow!(build);

use clap::Parser;
use error::Result;

use crate::subcommand::full_block;
use crate::subcommand::print_circuit_info;
use crate::subcommand::tree_prove_test;
use crate::subcommand::Cli;
use crate::subcommand::Commands;

#[tokio::main]
async fn main() -> Result<()> {
    dotenv::dotenv().ok();
    //city_common::setup_logger();

    let cli = Cli::parse();
    match cli.command {
        Commands::PrintCircuitInfo(args) => print_circuit_info::run(args).await?,
        Commands::TreeProveTest(args) => tree_prove_test::run(args).await?,
        Commands::FullBlock(args) => full_block::run(args).await?,
    }

    Ok(())
}
