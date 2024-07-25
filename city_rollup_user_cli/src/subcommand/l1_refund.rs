use anyhow::Result;
use city_common::cli::user_args::L1RefundArgs;
use city_common_circuit::circuits::traits::qstandard::QStandardCircuit;
use city_crypto::{
    hash::base_types::hash256::Hash256, signature::secp256k1::wallet::MemorySecp256K1Wallet,
};
use city_rollup_circuit::{sighash_circuits::{sighash_refund::CRSigHashRefundCircuit, sighash_refund_final_gl::CRSigHashRefundFinalGLCircuit, sighash_wrapper::CRSigHashWrapperCircuit}, worker::toolbox::root::CRWorkerToolboxRootCircuits};
use city_rollup_common::{
    introspection::{rollup::{constants::get_network_magic_for_str, introspection::RefundSpendIntrospectionHint}, sighash::{SigHashPreimage, SIGHASH_ALL}, transaction::{BTCTransaction, BTCTransactionInput, BTCTransactionOutput}},
    link::{
        data::{AddressToBTCScript, BTCAddress160},
        link_api::BTCLinkAPI,
        traits::QBitcoinAPISync,
    }, qworker::job_witnesses::sighash::CRSigHashWrapperRefundCircuitInput,
};
use city_rollup_rpc_provider::RpcProvider;
use city_store::store::sighash::SigHashMerkleTree;
use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig};

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = GoldilocksField;

pub async fn run(args: L1RefundArgs) -> Result<()> {
    let provider = RpcProvider::new(&args.rpc_address);
    let mut wallet = MemorySecp256K1Wallet::new();

    let api = BTCLinkAPI::new_str(&args.bitcoin_rpc, &args.electrs_api);
    let from = BTCAddress160::from_p2pkh_key(
        wallet.add_private_key(Hash256::from_hex_string(&args.private_key)?)?,
    );

    let txid = Hash256::from_hex_string(&args.txid)?;
    let funding_transactions =
        api.get_funding_transactions_with_vout(BTCAddress160::new_p2sh(from.address),
        |utxo| utxo.txid == txid
    )?;

    if funding_transactions.is_empty() {
        return Err(anyhow::anyhow!("specified utxo not found"));
    }

    let funding_transaction = &funding_transactions[0].transaction;

    let outputs = [
        vec![BTCTransactionOutput {
            script: from.to_btc_script(),
            value: funding_transaction.outputs[0].value,
        }],
    ]
    .concat();

    let base_tx = BTCTransaction {
        version: 2,
        inputs: vec![BTCTransactionInput {
                hash: funding_transaction.get_hash(),
                sequence: 0xffffffff,
                script: vec![],
                index: 0,
        }],
        outputs,
        locktime: 0,
    };
    let base_sighash_preimage = SigHashPreimage {
        transaction: base_tx,
        sighash_type: SIGHASH_ALL,
    };

    let hint = RefundSpendIntrospectionHint {
        sighash_preimage: base_sighash_preimage,
        funding_transaction: funding_transaction.clone(),
    };

    let network_magic = get_network_magic_for_str(args.network.to_string())?;
    let sighash_whitelist_tree = SigHashMerkleTree::new();
    let circuits =
        CRWorkerToolboxRootCircuits::<C, D>::new(network_magic, sighash_whitelist_tree.root);

    let sighash_refund_circuit = CRSigHashRefundCircuit::<C, D>::new(hint.get_config());
    let sighash_refund_proof = sighash_refund_circuit.prove_base(&hint)?;

    let sighash_circuit_whitelist_root = SigHashMerkleTree::new();
    let sighash_wrapper_circuit = CRSigHashWrapperCircuit::<C, D>::new(sighash_circuit_whitelist_root.root);
    let whitelist_inclusion_proof = sighash_circuit_whitelist_root.get_proof_for_index(0)?;
    let sighash_wrapper_proof = sighash_wrapper_circuit.prove_refund(&CRSigHashWrapperRefundCircuitInput {
        introspection_hint: hint,
        whitelist_inclusion_proof,
    })?;

    let sighash_refund_final_gl = CRSigHashRefundFinalGLCircuit::<C, D>::new(
        sighash_wrapper_circuit.get_verifier_config_ref(),
        sighash_wrapper_circuit.get_common_circuit_data_ref()
    );
    let sighash_refund_final_gl_proof = sighash_refund_final_gl.prove_base(&sighash_wrapper_proof);



    //
    //
    // let utxo = utxos.iter().find(|x| x.txid == txid).ok_or(anyhow::anyhow!("specified utxo not found"))?;
    //
    // let txid = api.ask_for_refund(
    //     &wallet,
    //     from,
    //     &utxo,
    // )?;
    // println!("{{\"txid\": \"{}\"}}", txid.to_hex_string());

    Ok(())
}
