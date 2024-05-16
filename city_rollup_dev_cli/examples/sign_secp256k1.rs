use city_common::logging::debug_timer::DebugTimer;
use city_crypto::hash::base_types::hash256::Hash256;
use city_rollup_common::{
    api::data::store::CityL1Deposit, introspection::rollup::constants::NETWORK_MAGIC_DOGE_REGTEST,
};
use city_rollup_core_orchestrator::debug::scenario::wallet::DebugScenarioWallet;
use plonky2::plonk::config::PoseidonGoldilocksConfig;

fn prove_sig_demo() -> anyhow::Result<()> {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    let network_magic = NETWORK_MAGIC_DOGE_REGTEST;

    //toolbox_circuits.print_op_common_data();

    let mut timer = DebugTimer::new("prove_block_demo");

    timer.lap("start creating wallets");

    let mut wallet = DebugScenarioWallet::<C, D>::new();

    let deposit_0_public_key = wallet.add_secp256k1_private_key(Hash256(hex_literal::hex!(
        "e6baf19a8b0b9b8537b9354e178a0a42d0887371341d4b2303537c5d18d7bb87"
    )))?;
    timer.lap("end creating wallets");

    let l1_deposit_0 = CityL1Deposit {
        deposit_id: 0,
        checkpoint_id: 1,
        value: 100000000,
        txid: Hash256::from_hex_string(
            "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
        )?,
        public_key: deposit_0_public_key,
    };
    let claim_deposit_0_req = wallet.sign_claim_deposit(network_magic, 0, &l1_deposit_0)?;

    Ok(())
}
fn main() {
    prove_sig_demo().unwrap();

    //println!("Proof: {:?}", proof);
}
