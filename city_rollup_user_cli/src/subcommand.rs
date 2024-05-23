use clap::command;
use clap::Parser;
use clap::Subcommand;

pub mod add_withdrawal;
pub mod claim_deposit;
pub mod get_public_key;
pub mod random_wallet;
pub mod register_user;
pub mod sign_hash;
pub mod token_transfer;

#[derive(Parser)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    AddWithdrawal(city_common::cli::user_args::AddWithdrawalArgs),
    ClaimDeposit(city_common::cli::user_args::ClaimDepositArgs),
    GetPublicKey(city_common::cli::user_args::GetPublicKeyArgs),
    RandomWallet(city_common::cli::user_args::RandomWalletArgs),
    RegisterUser(city_common::cli::user_args::RegisterUserArgs),
    SignHash(city_common::cli::user_args::SignHashArgs),
    TokenTransfer(city_common::cli::user_args::TokenTransferArgs),
}
