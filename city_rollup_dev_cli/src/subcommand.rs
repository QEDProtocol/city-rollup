use clap::command;
use clap::Parser;
use clap::Subcommand;
pub mod print_circuit_info;
pub mod tree_prove_test;
#[derive(Parser)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    PrintCircuitInfo(city_common::cli::dev_args::PrintCircuitInfoArgs),
    TreeProveTest(city_common::cli::dev_args::TreeProveTestArgs),
}
