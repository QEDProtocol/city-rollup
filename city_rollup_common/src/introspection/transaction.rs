use bitcoin::consensus::deserialize_partial;
use bitcoin::consensus::serialize;
use bitcoin::VarInt;
use city_crypto::hash::base_types::hash256::Hash256;
use city_crypto::hash::core::btc::btc_hash256;
use serde::Deserialize;
use serde::Serialize;
use serde_with::serde_as;

use super::rollup::introspection::BlockSpendCoreConfig;
use super::sighash::SigHashPreimage;
use super::size::BTCTransactionLayout;
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct BTCTransaction {
    pub version: u32,
    pub inputs: Vec<BTCTransactionInput>,
    pub outputs: Vec<BTCTransactionOutput>,
    pub locktime: u32,
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug, Hash, Eq, PartialOrd, Ord)]
pub struct BTCTransactionConfig {
    pub layout: BTCTransactionLayout,
    pub locktime: u32,
    pub version: u32,
}

impl BTCTransactionConfig {
    pub fn generate_funding_block_tx_from_template(
        config: &BlockSpendCoreConfig,
        last_block_num_deposits: usize,
        last_block_num_withdrawals: usize,
    ) -> Self {
        let input_script_sizes =
            vec![config.block_funding_script_size; last_block_num_deposits + 1];
        let output_script_sizes = (0..(last_block_num_withdrawals + 1))
            .map(|i| {
                if i == config.block_spend_index {
                    config.block_output_script_size
                } else {
                    config.withdrawal_output_script_size
                }
            })
            .collect::<Vec<_>>();
        Self {
            layout: BTCTransactionLayout {
                input_script_sizes,
                output_script_sizes,
            },
            locktime: config.locktime,
            version: config.version,
        }
    }
    pub fn generate_current_block_sighash_tx_from_template(
        config: &BlockSpendCoreConfig,
        num_deposits: usize,
        num_withdrawals: usize,
        current_spend_index: usize,
    ) -> Self {
        let mut input_script_sizes = vec![0; num_deposits + 1];
        input_script_sizes[current_spend_index] = config.block_sighash_script_size;
        let output_script_sizes = (0..(num_withdrawals + 1))
            .map(|i| {
                if i == config.block_spend_index {
                    config.block_output_script_size
                } else {
                    config.withdrawal_output_script_size
                }
            })
            .collect::<Vec<_>>();
        Self {
            layout: BTCTransactionLayout {
                input_script_sizes,
                output_script_sizes,
            },
            locktime: config.locktime,
            version: config.version,
        }
    }
    pub fn generate_funding_deposit_tx_from_template(config: &BlockSpendCoreConfig) -> Self {
        Self {
            layout: BTCTransactionLayout {
                input_script_sizes: vec![config.deposit_funding_script_size],
                output_script_sizes: vec![config.block_output_script_size],
            },
            locktime: config.locktime,
            version: config.version,
        }
    }
}

#[serde_as]
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct BTCTransactionOutput {
    pub value: u64,
    #[serde_as(as = "serde_with::hex::Hex")]
    pub script: Vec<u8>,
}

#[serde_as]
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct BTCTransactionInput {
    pub hash: Hash256,
    pub index: u32,
    #[serde_as(as = "serde_with::hex::Hex")]
    pub script: Vec<u8>,
    pub sequence: u32,
    // TODO: implement witnesses for advanced transactions supported by bitcoin
    // pub witness: Vec<u8>,
}
impl BTCTransaction {
    pub fn get_layout(&self) -> BTCTransactionLayout {
        BTCTransactionLayout {
            input_script_sizes: self.inputs.iter().map(|inp| inp.script.len()).collect(),
            output_script_sizes: self
                .outputs
                .iter()
                .map(|op: &BTCTransactionOutput| op.script.len())
                .collect(),
        }
    }
    pub fn get_tx_config(&self) -> BTCTransactionConfig {
        BTCTransactionConfig {
            layout: self.get_layout(),
            locktime: self.locktime,
            version: self.version,
        }
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.extend(self.version.to_le_bytes());
        let inputs_len = VarInt(self.inputs.len() as u64);
        bytes.extend(serialize(&inputs_len));
        for input in &self.inputs {
            bytes.extend(input.to_bytes());
        }
        let outputs_len = VarInt(self.outputs.len() as u64);
        bytes.extend(serialize(&outputs_len));
        for output in &self.outputs {
            bytes.extend(output.to_bytes());
        }
        bytes.extend(self.locktime.to_le_bytes());
        bytes
    }
    pub fn from_bytes_offset(bytes: &[u8], offset: usize) -> anyhow::Result<(Self, usize)> {
        if bytes.len() - offset < (32 + 4 + 4 + 1) {
            return Err(anyhow::anyhow!("Invalid bytes length"));
        }
        let mut read_index = offset;

        let version = u32::from_le_bytes(bytes[read_index..(read_index + 4)].try_into().unwrap());
        read_index += 4;
        let inputs_len: (VarInt, usize) = deserialize_partial(&bytes[read_index..])?;
        read_index += inputs_len.1;
        let inputs_size = inputs_len.0 .0 as usize;
        let mut inputs = vec![];
        for _ in 0..inputs_size {
            let (input, offset) = BTCTransactionInput::from_bytes(bytes, read_index)?;
            inputs.push(input);
            read_index = offset;
        }
        let outputs_len: (VarInt, usize) = deserialize_partial(&bytes[read_index..])?;
        read_index += outputs_len.1;
        let outputs_size = outputs_len.0 .0 as usize;
        let mut outputs = vec![];
        for _ in 0..outputs_size {
            let (output, offset) = BTCTransactionOutput::from_bytes(bytes.to_vec(), read_index)?;
            outputs.push(output);
            read_index = offset;
        }
        let locktime = u32::from_le_bytes(bytes[read_index..(read_index + 4)].try_into().unwrap());
        Ok((
            Self {
                version,
                inputs,
                outputs,
                locktime,
            },
            read_index + 4,
        ))
    }
    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        let (tx, _) = Self::from_bytes_offset(bytes, 0)?;
        Ok(tx)
    }
    pub fn get_hash(&self) -> Hash256 {
        btc_hash256(&self.to_bytes())
    }
    pub fn get_sig_hash_preimage(
        &self,
        input_index: usize,
        prev_out_script: &[u8],
        sighash_type: u32,
    ) -> SigHashPreimage {
        SigHashPreimage::for_transaction_pre_segwit(
            self,
            input_index,
            prev_out_script,
            sighash_type,
        )
    }
    pub fn get_sig_hash(
        &self,
        input_index: usize,
        prev_out_script: &[u8],
        sighash_type: u32,
    ) -> Hash256 {
        SigHashPreimage::for_transaction_pre_segwit(
            self,
            input_index,
            prev_out_script,
            sighash_type,
        )
        .get_hash()
    }
}
impl BTCTransactionInput {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.extend(&self.hash.0);
        bytes.extend(self.index.to_le_bytes());
        let len = VarInt(self.script.len() as u64);
        bytes.extend(serialize(&len));
        bytes.extend(&self.script);
        bytes.extend(self.sequence.to_le_bytes());
        bytes
    }
    pub fn from_bytes(bytes: &[u8], offset: usize) -> anyhow::Result<(Self, usize)> {
        if bytes.len() - offset < (32 + 4 + 4 + 1) {
            return Err(anyhow::anyhow!("Invalid bytes length"));
        }
        let mut read_index = offset;

        let hash_bytes: [u8; 32] = bytes[read_index..(read_index + 32)].try_into()?;
        let hash = Hash256(hash_bytes);
        read_index += 32;
        let index = u32::from_le_bytes(bytes[read_index..(read_index + 4)].try_into().unwrap());
        read_index += 4;
        let script_len: (VarInt, usize) = deserialize_partial(&bytes[read_index..])?;
        read_index += script_len.1;
        let script_size = script_len.0 .0 as usize;

        let script = bytes[read_index..(read_index + script_size)].to_vec();
        read_index += script_size;
        let sequence = u32::from_le_bytes(bytes[read_index..(read_index + 4)].try_into().unwrap());
        read_index += 4;

        Ok((
            Self {
                hash,
                index,
                script,
                sequence,
            },
            read_index,
        ))
    }
}
impl Default for BTCTransactionInput {
    fn default() -> Self {
        Self {
            hash: Hash256([0u8; 32]),
            index: 0,
            script: vec![],
            sequence: 0,
        }
    }
}

impl BTCTransactionOutput {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.extend(self.value.to_le_bytes());
        let len = VarInt(self.script.len() as u64);
        bytes.extend(serialize(&len));
        bytes.extend(&self.script);
        bytes
    }
    pub fn from_bytes(bytes: Vec<u8>, offset: usize) -> anyhow::Result<(Self, usize)> {
        if bytes.len() - offset < (8 + 1) {
            return Err(anyhow::anyhow!("Invalid bytes length"));
        }
        let mut read_index = offset;

        let value = u64::from_le_bytes(bytes[read_index..(read_index + 8)].try_into().unwrap());
        read_index += 8;
        let script_len: (VarInt, usize) = deserialize_partial(&bytes[read_index..])?;
        read_index += script_len.1;
        let script_size = script_len.0 .0 as usize;

        let script = bytes[read_index..(read_index + script_size)].to_vec();
        read_index += script_size;

        Ok((Self { value, script }, read_index))
    }

    pub fn blank() -> Self {
        Self {
            value: 0xffffffffffffffffu64,
            script: vec![],
        }
    }
}
impl Default for BTCTransactionOutput {
    fn default() -> Self {
        Self {
            value: 0,
            script: vec![],
        }
    }
}
#[cfg(test)]
mod tests {
    use bitcoin::consensus::encode::deserialize;
    use bitcoin::consensus::encode::serialize;
    use bitcoin::Transaction;

    use crate::introspection::transaction::BTCTransaction;

    fn get_example_raw_txs() -> Vec<Vec<u8>> {
        vec![
            hex_literal::hex!("020000000142eedadeda5e79813b413d360b9e4a4dfe0f65159eb26eb5e3819954bd6bec4200000000fd1203305718d0a4c82f338c23ffdb184122fcd167159cee33024d243a1b656470e5595b5966eb2e18bdf384d1765beaedb372af30afff564fee031cfdb741e89884c80ebd2773ac14b2c6157b09caed45b39b051cf8b64ff43949f96aaff7935fe27e3b22303250ab2c76f8713b2d164828c7770ca02e9b2e8f13bbf64e0e21270e16ebf7a4446ac19bd8fa7d054ee31d56c2f2d999307520125401373dadedeacc198c175b814d548f780d336649e73ad96d7aeb443b01e22e73f808683f1eeb0e71575582ae4c500c8e4f5f9025c9a972b9970491740c0473465e81e64f32a51350bb054dc86a447999404a9e2c3533679a33034dcb310e88b9f797ffeb96230a055ac0f6d5ed4eb4ea316cd6b0a93d6f1ef714039d05944df9013008aa981e382121567aecaaf228e0b9722249cc4af36b98899a9990492b9858c9cfc7b9e1a1dc235d8342e5e5ff4d912c7c76a8201eee570455bbbd58923add8a280cbed0bcce549a2fdc780bba35621d37181b3d884c5057a7823a3e9b8e7d72389f4398707b78138d570fca0a9ae9a2f240ad3760ed8800f1400c516bd9a2c86725ff75b6ff09e87a71a5a7038d707ae5163a424cb44cc47c61d99fbac95835b38d8626c8268f4c500de5798a1ac6f3d4bfbd7f4ecb018fc5a1a35618c1543261d9edd51627faded3e81e6dd3560ad5632e6b746fc43ced61f5c8109ba680257343d49b9c55ab3c8b197cad346f4b214f90fb72fc4a1b1eb74c500e57bd51a2073f508cf82bb7305a648abddaf7e8053f6d004f7e8a39791ae1677e7af9291a2708f1ea2f4a83efc15bbde38f519624f962ac07bea41963a7b1836d4c53b5a4dbf2fbb3c1ce3e61765ed04c50447dcd68928fb58caf4d5250d973213b665d39cafb0da9414cabc8fb8341251086e3beec6c46a26b55cbe563010de2e71b2cdb4295c22734ed304a6fccc0bcb73980407863eebaa982a8067e97174d6d4c5079105ee3ee45b69efc35b4ab3f6dd6b3daa07c373ca3c26b2ce63a7002430aba4bb130f9cade132cf19632b02f44f98d7b50457b31f8ee73a4eee572a656da8b36910c1e4302f7731619bf64d9a78f7751926d6d6d6d6d6d51ffffffff01002f68590000000017a91400b6cf04571f8d62644b0fdfacf96538a18f3d4d8700000000").to_vec(),
        ]
    }
    #[test]
    fn test_bitcoin_pkg() {
        let raw_txs = get_example_raw_txs();
        for rtx in raw_txs {
            let tx: Transaction = deserialize(&rtx).unwrap();
            let tx_bytes = serialize(&tx);
            assert_eq!(tx_bytes, rtx);
        }
    }
    #[test]
    fn test_bitcoin_pkg_btc_tx() {
        let raw_txs = get_example_raw_txs();
        for rtx in raw_txs {
            let tx: Transaction = deserialize(&rtx).unwrap();
            let tx_bytes = serialize(&tx);
            assert_eq!(tx_bytes, rtx);

            let btc_tx = BTCTransaction::from_bytes(&rtx).unwrap();
            let btc_tx_bytes = btc_tx.to_bytes();
            assert_eq!(btc_tx_bytes, rtx);
        }
    }

    #[test]
    fn test_deser_btc_tx() {
        let tx = BTCTransaction::from_bytes(&hex_literal::hex!("020000000142eedadeda5e79813b413d360b9e4a4dfe0f65159eb26eb5e3819954bd6bec4200000000fd1203305718d0a4c82f338c23ffdb184122fcd167159cee33024d243a1b656470e5595b5966eb2e18bdf384d1765beaedb372af30afff564fee031cfdb741e89884c80ebd2773ac14b2c6157b09caed45b39b051cf8b64ff43949f96aaff7935fe27e3b22303250ab2c76f8713b2d164828c7770ca02e9b2e8f13bbf64e0e21270e16ebf7a4446ac19bd8fa7d054ee31d56c2f2d999307520125401373dadedeacc198c175b814d548f780d336649e73ad96d7aeb443b01e22e73f808683f1eeb0e71575582ae4c500c8e4f5f9025c9a972b9970491740c0473465e81e64f32a51350bb054dc86a447999404a9e2c3533679a33034dcb310e88b9f797ffeb96230a055ac0f6d5ed4eb4ea316cd6b0a93d6f1ef714039d05944df9013008aa981e382121567aecaaf228e0b9722249cc4af36b98899a9990492b9858c9cfc7b9e1a1dc235d8342e5e5ff4d912c7c76a8201eee570455bbbd58923add8a280cbed0bcce549a2fdc780bba35621d37181b3d884c5057a7823a3e9b8e7d72389f4398707b78138d570fca0a9ae9a2f240ad3760ed8800f1400c516bd9a2c86725ff75b6ff09e87a71a5a7038d707ae5163a424cb44cc47c61d99fbac95835b38d8626c8268f4c500de5798a1ac6f3d4bfbd7f4ecb018fc5a1a35618c1543261d9edd51627faded3e81e6dd3560ad5632e6b746fc43ced61f5c8109ba680257343d49b9c55ab3c8b197cad346f4b214f90fb72fc4a1b1eb74c500e57bd51a2073f508cf82bb7305a648abddaf7e8053f6d004f7e8a39791ae1677e7af9291a2708f1ea2f4a83efc15bbde38f519624f962ac07bea41963a7b1836d4c53b5a4dbf2fbb3c1ce3e61765ed04c50447dcd68928fb58caf4d5250d973213b665d39cafb0da9414cabc8fb8341251086e3beec6c46a26b55cbe563010de2e71b2cdb4295c22734ed304a6fccc0bcb73980407863eebaa982a8067e97174d6d4c5079105ee3ee45b69efc35b4ab3f6dd6b3daa07c373ca3c26b2ce63a7002430aba4bb130f9cade132cf19632b02f44f98d7b50457b31f8ee73a4eee572a656da8b36910c1e4302f7731619bf64d9a78f7751926d6d6d6d6d6d51ffffffff01002f68590000000017a91400b6cf04571f8d62644b0fdfacf96538a18f3d4d8700000000")).unwrap();
        println!("{:?}", tx);
        let json_data = serde_json::to_string_pretty(&tx).unwrap();
        println!("tx json:\n {}", json_data);
        let hex_enc = hex::encode(tx.to_bytes());
        println!("tx hex: {}", hex_enc);
    }
    #[test]
    fn test_deser_btc_tx2() {
        let tx = BTCTransaction::from_bytes(&hex_literal::hex!("02000000030740a1993aea97cd87a0cff0b51df8b10275b459d4132f93be1252b3f9c6a07400000000fd010330a0e77690fd601f556d295b3c6ede845fe2bcad660ebc15a2739502aa9e4a6ca497bad5b54b4cbfd37e72931eee7eba12301539fd0dc27931a996e47b36e444092d8fd1adf6f6f837af609486977008fc06235e9c18e1bdd3d911de8095f96d990030f3c752a8e22f85a03a2695bbbd062b9e11c903095ed802c8bdbdab25acd58926e8cb48f9294ef9a707b067242accf51730eb5b88d8e1878edc6bf8dbce6cbccbb83394689fe959d525e2a7a175062010f18a1a700be662c2f0efee7255e6b562094c50c5c997331fe67bea6076b9f4ac834625f53e867884b0b739c93f676766fba2d393d7a791ea53543b8a3ad213298eaa92cc7c2eb036e8142ce3f720cc16bd6d53ab7506114bd1bdc4eef900848629f5ec4de8011fb8738e1b8a316565888ab866bb653d9a1ae502cf30300efed0ce3f29588eb27c76a82041bc615547f574731f534691b33adc81791ca47ec80ba15674cbac83812e8c83884c507116e78d9b4b2d72021a874d832e4b05480e8a783bf5a6ed4daa55229992072d4e2b7eec3c5b194161af8a32b8357c3e5f9844d6606d89a8dd565da3cb377d162bdea1270e2e545969897640d3ef6f7f4c50becf0d9d59bb22b16f6595a46bab5325c08b071a7955b77da48fc03d2b054903d5dfc7f88f5c746b75d697581ae50dc840d15432c8249c1643112c54d936960731ce39686feebb0ee178df3ff4a246194c5091b419e750faa2b5340481b62564fc1249d92b08853d76109f1e69ce47c1be3c064ef1e720b54a9f6f2151a67a6de6006ba6dc479e132fdb8ea4b964818415fcb03395fd79ef75de26eeec626d380fbf4c50d8dee1f026773c0972f7d9d37122e0082657eaf4e37cb590ecd240709ce6484fb30d35b3e0bd2fcf90b4bbed957ddf4e07107fba93f8b7f7a7c853eb45e72d97e3099830c13b169bd266b65acfbd219c4c507c210f0e09bba0575b67210255859c900eacdbe23d4c72705cc91573e318c319d4c327dc2d1b2484792657ec663ce454ae697109a1bb9f7dcd7b29dfb32a7e06109615a4eab686f4aad0b8953cbcda0251926d6d6d6d6d6d51ffffffff1b11ea813a1403d5f381c40ffc988d277a8b7279d75d4dd60641ea217a0524ed00000000fd010330a0e77690fd601f556d295b3c6ede845fe2bcad660ebc15a2739502aa9e4a6ca497bad5b54b4cbfd37e72931eee7eba12301539fd0dc27931a996e47b36e444092d8fd1adf6f6f837af609486977008fc06235e9c18e1bdd3d911de8095f96d990030f3c752a8e22f85a03a2695bbbd062b9e11c903095ed802c8bdbdab25acd58926e8cb48f9294ef9a707b067242accf51730eb5b88d8e1878edc6bf8dbce6cbccbb83394689fe959d525e2a7a175062010f18a1a700be662c2f0efee7255e6b562094c50c5c997331fe67bea6076b9f4ac834625f53e867884b0b739c93f676766fba2d393d7a791ea53543b8a3ad213298eaa92cc7c2eb036e8142ce3f720cc16bd6d53ab7506114bd1bdc4eef900848629f5ec4de8011fb8738e1b8a316565888ab866bb653d9a1ae502cf30300efed0ce3f29588eb27c76a82041bc615547f574731f534691b33adc81791ca47ec80ba15674cbac83812e8c83884c507116e78d9b4b2d72021a874d832e4b05480e8a783bf5a6ed4daa55229992072d4e2b7eec3c5b194161af8a32b8357c3e5f9844d6606d89a8dd565da3cb377d162bdea1270e2e545969897640d3ef6f7f4c50becf0d9d59bb22b16f6595a46bab5325c08b071a7955b77da48fc03d2b054903d5dfc7f88f5c746b75d697581ae50dc840d15432c8249c1643112c54d936960731ce39686feebb0ee178df3ff4a246194c5091b419e750faa2b5340481b62564fc1249d92b08853d76109f1e69ce47c1be3c064ef1e720b54a9f6f2151a67a6de6006ba6dc479e132fdb8ea4b964818415fcb03395fd79ef75de26eeec626d380fbf4c50d8dee1f026773c0972f7d9d37122e0082657eaf4e37cb590ecd240709ce6484fb30d35b3e0bd2fcf90b4bbed957ddf4e07107fba93f8b7f7a7c853eb45e72d97e3099830c13b169bd266b65acfbd219c4c507c210f0e09bba0575b67210255859c900eacdbe23d4c72705cc91573e318c319d4c327dc2d1b2484792657ec663ce454ae697109a1bb9f7dcd7b29dfb32a7e06109615a4eab686f4aad0b8953cbcda0251926d6d6d6d6d6d51ffffffff6007df6a96ab71af55e7485bdb6420fce4afcacbcd98877b7d2194dea1833c7300000000fd010330a0e77690fd601f556d295b3c6ede845fe2bcad660ebc15a2739502aa9e4a6ca497bad5b54b4cbfd37e72931eee7eba12301539fd0dc27931a996e47b36e444092d8fd1adf6f6f837af609486977008fc06235e9c18e1bdd3d911de8095f96d990030f3c752a8e22f85a03a2695bbbd062b9e11c903095ed802c8bdbdab25acd58926e8cb48f9294ef9a707b067242accf51730eb5b88d8e1878edc6bf8dbce6cbccbb83394689fe959d525e2a7a175062010f18a1a700be662c2f0efee7255e6b562094c50c5c997331fe67bea6076b9f4ac834625f53e867884b0b739c93f676766fba2d393d7a791ea53543b8a3ad213298eaa92cc7c2eb036e8142ce3f720cc16bd6d53ab7506114bd1bdc4eef900848629f5ec4de8011fb8738e1b8a316565888ab866bb653d9a1ae502cf30300efed0ce3f29588eb27c76a82041bc615547f574731f534691b33adc81791ca47ec80ba15674cbac83812e8c83884c507116e78d9b4b2d72021a874d832e4b05480e8a783bf5a6ed4daa55229992072d4e2b7eec3c5b194161af8a32b8357c3e5f9844d6606d89a8dd565da3cb377d162bdea1270e2e545969897640d3ef6f7f4c50becf0d9d59bb22b16f6595a46bab5325c08b071a7955b77da48fc03d2b054903d5dfc7f88f5c746b75d697581ae50dc840d15432c8249c1643112c54d936960731ce39686feebb0ee178df3ff4a246194c5091b419e750faa2b5340481b62564fc1249d92b08853d76109f1e69ce47c1be3c064ef1e720b54a9f6f2151a67a6de6006ba6dc479e132fdb8ea4b964818415fcb03395fd79ef75de26eeec626d380fbf4c50d8dee1f026773c0972f7d9d37122e0082657eaf4e37cb590ecd240709ce6484fb30d35b3e0bd2fcf90b4bbed957ddf4e07107fba93f8b7f7a7c853eb45e72d97e3099830c13b169bd266b65acfbd219c4c507c210f0e09bba0575b67210255859c900eacdbe23d4c72705cc91573e318c319d4c327dc2d1b2484792657ec663ce454ae697109a1bb9f7dcd7b29dfb32a7e06109615a4eab686f4aad0b8953cbcda0251926d6d6d6d6d6d51ffffffff0300105e5f0000000017a9140aa5f71da1254e2fbd235d5195008f87c7531e8b8700c2eb0b000000001976a914803256e1d359b3806ee3c39cb790e70ff214e1c788ac00a3e111000000001976a914437142db45be1b0e8db19bf620a5dcc26d9ca26b88ac00000000")).unwrap();
        println!("{:?}", tx);
        let json_data = serde_json::to_string_pretty(&tx).unwrap();
        println!("tx json:\n {}", json_data);
        let hex_enc = hex::encode(tx.to_bytes());
        println!("tx hex: {}", hex_enc);
    }
}
