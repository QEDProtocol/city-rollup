use city_common::logging::debug_timer::DebugTimer;
use city_crypto::hash::{base_types::hash256::Hash256, qhashout::QHashOut};
use city_rollup_common::introspection::rollup::constants::NETWORK_MAGIC_DOGE_REGTEST;
use city_rollup_core_orchestrator::debug::scenario::wallet::DebugScenarioWallet;
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    hash::hash_types::HashOut,
    plonk::config::PoseidonGoldilocksConfig,
};

fn prove_sig_demo() -> anyhow::Result<()> {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = GoldilocksField;
    let _network_magic = NETWORK_MAGIC_DOGE_REGTEST;

    //toolbox_circuits.print_op_common_data();

    let mut timer = DebugTimer::new("prove_block_demo");

    timer.lap("start creating wallets");

    let mut wallet = DebugScenarioWallet::<C, D>::new();

    let deposit_0_public_key = wallet.add_secp256k1_private_key(Hash256(hex_literal::hex!(
        "e6baf19a8b0b9b8537b9354e178a0a42d0887371341d4b2303537c5d18d7bb87"
    )))?;
    timer.lap("end creating wallets");

    let _claim_deposit_0_req = wallet.zk_sign_hash_secp256k1(
        deposit_0_public_key,
        QHashOut(HashOut::<F> {
            elements: [
                F::from_noncanonical_u64(3445860687603287005),
                F::from_noncanonical_u64(16402394832886008019),
                F::from_noncanonical_u64(13093881128284034227),
                F::from_noncanonical_u64(5162935472209379774),
            ],
        }),
    )?;

    Ok(())
}
fn main() {
    prove_sig_demo().unwrap();

    //println!("Proof: {:?}", proof);
}
