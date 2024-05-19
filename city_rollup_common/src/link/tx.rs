use bitcoin::consensus::encode;
use city_crypto::{
    hash::{
        base_types::{hash160::Hash160, hash256::Hash256},
        core::btc::btc_hash160,
    },
    signature::secp256k1::wallet::Secp256K1WalletProvider,
};

use crate::{
    block_template::{get_genesis_block_script_bytes, BLOCK_GROTH16_ENCODED_VERIFIER_DATA},
    introspection::{
        sighash::{SigHashPreimage, SIGHASH_ALL},
        transaction::{
            BTCTransaction, BTCTransactionInput, BTCTransactionInputWithoutScript,
            BTCTransactionOutput,
        },
    },
};

use super::data::{
    AddressToBTCScript, BTCAddress160, BTCTransactionWithVout, PartialBTCUTXO, BTCUTXO,
};

pub trait QBitcoinAPISync {
    fn get_funding_transactions(
        &self,
        address: BTCAddress160,
    ) -> anyhow::Result<Vec<BTCTransaction>>;
    fn get_utxos(&self, address: BTCAddress160) -> anyhow::Result<Vec<BTCUTXO>>;
    fn get_partial_utxos(&self, address: BTCAddress160) -> anyhow::Result<Vec<PartialBTCUTXO>> {
        Ok(self
            .get_utxos(address)?
            .into_iter()
            .map(|utxo| PartialBTCUTXO {
                txid: utxo.txid,
                vout: utxo.vout,
                value: utxo.value,
            })
            .collect())
    }
    fn get_funding_transactions_with_vout(
        &self,
        address: BTCAddress160,
    ) -> anyhow::Result<Vec<BTCTransactionWithVout>>;
    fn get_transaction(&self, txid: Hash256) -> anyhow::Result<BTCTransaction>;
    fn send_transaction(&self, tx: &BTCTransaction) -> anyhow::Result<Hash256>;
}
pub trait QBitcoinAPIFunderSync {
    fn fund_address(&self, address: Hash160, amount: u64) -> anyhow::Result<Hash256>;
}

pub fn create_p2pkh_tx<W: Secp256K1WalletProvider>(
    wallet: &W,
    address: Hash160,
    inputs: Vec<BTCTransactionInputWithoutScript>,
    outputs: Vec<BTCTransactionOutput>,
) -> anyhow::Result<BTCTransaction> {
    let inputs_len = inputs.len();
    let script = BTCAddress160::new_p2pkh(address).to_btc_script();

    let mut base_tx = BTCTransaction::from_partial(inputs, outputs);
    let sighashes: Vec<Hash256> = (0..inputs_len)
        .map(|i| {
            SigHashPreimage::for_transaction_pre_segwit(&base_tx, i, &script, SIGHASH_ALL)
                .get_hash()
        })
        .collect();

    let public_key = wallet
        .get_public_key_for_p2pkh(&address)
        .ok_or_else(|| anyhow::anyhow!("public key not found"))?;

    for i in 0..inputs_len {
        base_tx.inputs[i].script = wallet.sign(&public_key, sighashes[i])?.to_btc_script();
    }

    Ok(base_tx)
}
pub fn encode_binary_stack_item(item: &[u8]) -> Vec<u8> {
    if item.len() < 0x76 {
        let mut result = Vec::with_capacity(item.len() + 1);
        result.push(item.len() as u8);
        result.extend_from_slice(item);
        result
    } else if item.len() < 0x100 {
        let mut result = Vec::with_capacity(item.len() + 2);
        result.push(0x76);
        result.push(item.len() as u8);
        result.extend_from_slice(item);
        result
    } else if item.len() < 0x10000 {
        let mut result = Vec::with_capacity(item.len() + 3);
        result.push(0x77);
        result.push(item.len() as u8);
        result.push((item.len() >> 8) as u8);
        result.extend_from_slice(item);
        result
    } else if item.len() < 0x1000000 {
        let mut result = Vec::with_capacity(item.len() + 4);
        result.push(0x78);
        result.push(item.len() as u8);
        result.push((item.len() >> 8) as u8);
        result.push((item.len() >> 16) as u8);
        result.extend_from_slice(item);
        result
    } else {
        let mut result = Vec::with_capacity(item.len() + 5);
        result.push(0x79);
        result.push(item.len() as u8);
        result.push((item.len() >> 8) as u8);
        result.push((item.len() >> 16) as u8);
        result.push((item.len() >> 24) as u8);
        result.extend_from_slice(item);
        result
    }
}
pub fn encode_binary_witness_script_for_p2sh<'a>(
    base_script: &'a [u8],
    binary_stack_items: impl Iterator<Item = &'a [u8]>,
) -> Vec<u8> {
    binary_stack_items
        .chain([base_script].into_iter())
        .map(|x| encode_binary_stack_item(x))
        .flatten()
        .collect::<Vec<u8>>()
}
pub fn send_entire_balance_simple_p2pkh<W: Secp256K1WalletProvider, A: QBitcoinAPISync>(
    api: &A,
    wallet: &W,
    from: Hash160,
    to: BTCAddress160,
    fee: u64,
) -> anyhow::Result<Hash256> {
    let inputs = api.get_partial_utxos(BTCAddress160::new_p2pkh(from))?;
    let total_balance = inputs.iter().map(|x| x.value).sum::<u64>();
    let outputs = vec![BTCTransactionOutput {
        value: total_balance - fee,
        script: to.to_btc_script(),
    }];
    let tx_inputs = inputs
        .iter()
        .map(|x| BTCTransactionInputWithoutScript {
            hash: x.txid,
            index: x.vout,
            sequence: 0xffffffff,
        })
        .collect();
    let tx = create_p2pkh_tx(wallet, from, tx_inputs, outputs)?;
    api.send_transaction(&tx)
}
pub fn setup_genesis_block<W: Secp256K1WalletProvider, A: QBitcoinAPISync>(
    api: &A,
    wallet: &W,
    funder: Hash160,
    funding_txid: Hash256,
    fee: u64,
    genesis_hash: Hash256,
) -> anyhow::Result<Hash256> {
    let funding_tx = api.get_transaction(funding_txid)?;
    assert!(funding_tx.outputs.len() == 1);
    let base_value = funding_tx.outputs[0].value;

    let genesis_block_script = get_genesis_block_script_bytes(genesis_hash.0).to_vec();
    let script_address = BTCAddress160::new_p2sh(btc_hash160(&genesis_block_script));
    let tx_0 = create_p2pkh_tx(
        wallet,
        funder,
        vec![BTCTransactionInputWithoutScript {
            hash: funding_txid,
            index: 0,
            sequence: 0xffffffff,
        }],
        vec![BTCTransactionOutput {
            value: base_value - fee,
            script: script_address.to_btc_script(),
        }],
    )?;
    let txid_0 = api.send_transaction(&tx_0)?;

    let pi_a = &hex_literal::hex!("a0e77690fd601f556d295b3c6ede845fe2bcad660ebc15a2739502aa9e4a6ca497bad5b54b4cbfd37e72931eee7eba12").to_vec();
    let pi_a_a0 = &hex_literal::hex!("1539fd0dc27931a996e47b36e444092d8fd1adf6f6f837af609486977008fc06235e9c18e1bdd3d911de8095f96d9900").to_vec();
    let pi_b_a1 = &hex_literal::hex!("f3c752a8e22f85a03a2695bbbd062b9e11c903095ed802c8bdbdab25acd58926e8cb48f9294ef9a707b067242accf517").to_vec();
    let pi_c = &hex_literal::hex!("eb5b88d8e1878edc6bf8dbce6cbccbb83394689fe959d525e2a7a175062010f18a1a700be662c2f0efee7255e6b56209").to_vec();
    let witness: [&[u8]; 5] = [
        &pi_a,
        &pi_a_a0,
        &pi_b_a1,
        &pi_c,
        &BLOCK_GROTH16_ENCODED_VERIFIER_DATA[0].to_vec(),
    ];

    let tx_inputs = vec![BTCTransactionInput {
        hash: txid_0,
        index: 0,
        sequence: 0xffffffff,
        script: encode_binary_witness_script_for_p2sh(&genesis_block_script, witness.into_iter()),
    }];
    let mut tx_1 = BTCTransaction {
        inputs: tx_inputs,
        outputs: vec![BTCTransactionOutput {
            value: base_value - fee * 2,
            script: script_address.to_btc_script(),
        }],
        version: 2,
        locktime: 0,
    };
    let txid_1 = api.send_transaction(&tx_1)?;
    tx_1.inputs[0].hash = txid_1;
    tx_1.inputs[0].index = 0;
    tx_1.outputs[0].value -= fee;
    let txid_2 = api.send_transaction(&tx_1)?;
    Ok(txid_2)
}

pub trait QBitcoinScriptBuilderSync {
    fn create_p2pkh<W: Secp256K1WalletProvider, A: QBitcoinAPISync>(
        &self,
        api: &A,
        wallet: &W,
        from: Hash160,
        inputs: &[BTCTransactionInputWithoutScript],
        outputs: &[BTCTransactionOutput],
        amount: u64,
    ) -> anyhow::Result<BTCTransaction>;
    fn send_p2sh<W: Secp256K1WalletProvider, A: QBitcoinAPISync>(
        &self,
        api: &A,
        from: Hash160,
        inputs: &[BTCTransactionInputWithoutScript],
        outputs: &[BTCTransactionOutput],
        amount: u64,
    ) -> anyhow::Result<Hash256>;
}
