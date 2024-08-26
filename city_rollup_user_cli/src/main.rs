mod error;
mod subcommand;

use shadow_rs::shadow;

shadow!(build);

#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

use clap::Parser;
use error::Result;

use crate::subcommand::add_withdrawal;
use crate::subcommand::claim_deposit;
use crate::subcommand::register_user;
use crate::subcommand::token_transfer;
use crate::subcommand::l1_deposit;
use crate::subcommand::l1_refund;

use crate::subcommand::get_public_key;
use crate::subcommand::random_wallet;
use crate::subcommand::sign_hash;
use crate::subcommand::repl;
use crate::subcommand::prover_rpc;

use crate::subcommand::Cli;
use crate::subcommand::Commands;

#[tokio::main]
async fn main() -> Result<()> {
    dotenv::dotenv().ok();
    city_common::logging::setup_env_logger();

    let cli = Cli::parse();
    match cli.command {
        Commands::AddWithdrawal(args) => add_withdrawal::run(args).await?,
        Commands::ClaimDeposit(args) => claim_deposit::run(args).await?,
        Commands::RegisterUser(args) => register_user::run(args).await?,
        Commands::TokenTransfer(args) => token_transfer::run(args).await?,
        Commands::L1Deposit(args) => l1_deposit::run(args).await?,
        Commands::L1Refund(args) => l1_refund::run(args).await?,

        Commands::SignHash(args) => sign_hash::run(args).await?,
        Commands::GetPublicKey(args) => get_public_key::run(args).await?,
        Commands::RandomWallet(args) => random_wallet::run(args).await?,
        Commands::Repl(args) => repl::run(args).await?,
        Commands::ProverRPC(args) => prover_rpc::run(args).await?,
    }


    Ok(())
}
