use clap::command;
use clap::Parser;
use clap::Subcommand;

pub mod add_withdrawal;
pub mod claim_deposit;
pub mod register_user;
pub mod token_transfer;
pub mod l1_deposit;

pub mod sign_hash;
pub mod get_public_key;
pub mod random_wallet;
pub mod repl;
pub mod prover_rpc;

#[derive(Parser)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    AddWithdrawal(city_common::cli::user_args::AddWithdrawalArgs),
    ClaimDeposit(city_common::cli::user_args::ClaimDepositArgs),
    RegisterUser(city_common::cli::user_args::RegisterUserArgs),
    TokenTransfer(city_common::cli::user_args::TokenTransferArgs),
    L1Deposit(city_common::cli::user_args::L1DepositArgs),

    SignHash(city_common::cli::user_args::SignHashArgs),
    GetPublicKey(city_common::cli::user_args::GetPublicKeyArgs),
    RandomWallet(city_common::cli::user_args::RandomWalletArgs),
    Repl(city_common::cli::user_args::RPCReplArgs),
    ProverRPC(city_common::cli::user_args::ProverRPCArgs),
}
