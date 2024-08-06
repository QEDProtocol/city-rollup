use std::{collections::HashSet, str::FromStr};

use city_common::data::u8bytes::U8Bytes;
use city_crypto::hash::base_types::hash256::Hash256;
use reqwest::blocking::ClientBuilder;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use std::thread::sleep;
use std::time::Duration;
use crate::{
    errors::data_resolver::BTCDataResolverError, introspection::transaction::BTCTransaction,
};
use tracing::{debug};
use super::{
    data::{BTCAddress160, BTCFeeRateEstimate, BTCTransactionWithVout, BTCUTXO},
    traits::{QBitcoinAPIFunderSync, QBitcoinAPISync},
};

fn format_u64_8_decimal_places(value: u64) -> String {
    let integer_part = value / 100_000_000;
    let fractional_part = value % 100_000_000;
    format!("{}.{}", integer_part, format!("{:08}", fractional_part))
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, PartialOrd, Eq)]
pub struct BTCLinkRPCConfig {
    pub network: String,
    pub url: String,
    pub user: String,
    pub password: String,
    pub is_doge: bool,
    pub is_regtest: bool,
}
impl BTCLinkRPCConfig {
    pub fn new(rpc_url: &str) -> Self {
        let url = url::Url::from_str(rpc_url).unwrap();
        let path = url.path();
        let origin = url.origin().ascii_serialization();

        let rr = url
            .query_pairs()
            .find(|x| x.0.to_ascii_lowercase().eq("network"));

        let network = if rr.is_none() {
            "dogeRegtest".to_string()
        } else {
            rr.unwrap().1.to_string()
        };
        let final_url = format!("{}{}", origin, path);

        let user = url.username().to_string();
        let password = url.password().unwrap_or("").to_string();

        let is_doge = network.to_ascii_lowercase().contains("doge");
        let is_regtest = network.to_ascii_lowercase().contains("regtest");

        Self {
            url: final_url,
            user,
            password,
            network,
            is_doge,
            is_regtest,
        }
    }
    pub fn has_basic_auth(&self) -> bool {
        !(self.user.is_empty() && self.password.is_empty())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, PartialOrd, Eq)]
pub struct BTCLinkRPCCommand<T> {
    pub jsonrpc: String,
    pub method: String,
    pub params: T,
    pub id: u32,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, PartialOrd, Eq)]
pub struct BTCLinkRPCCommandResponse<R> {
    pub error: Option<String>,
    pub result: Option<R>,
    pub id: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BTCLinkAPI {
    pub rpc_config: BTCLinkRPCConfig,
    pub electrs_url: String,
    pub no_proxy: bool,
    pub last_fee_rate: u64,
}

impl BTCLinkAPI {
    pub fn new(rpc_url: String, electrs_url: String) -> Self {
        Self {
            rpc_config: BTCLinkRPCConfig::new(&rpc_url),
            electrs_url,
            no_proxy: true,
            last_fee_rate: 0,
        }
    }
    pub fn new_str(rpc_url: &str, electrs_url: &str) -> Self {
        Self {
            rpc_config: BTCLinkRPCConfig::new(rpc_url),
            electrs_url: electrs_url.to_string(),
            no_proxy: true,
            last_fee_rate: 0,
        }
    }
    pub fn new_with_proxy(rpc_url: String, electrs_url: String) -> Self {
        Self {
            rpc_config: BTCLinkRPCConfig::new(&rpc_url),
            electrs_url,
            no_proxy: false,
            last_fee_rate: 0,
        }
    }
    pub fn new_str_with_proxy(rpc_url: &str, electrs_url: &str) -> Self {
        Self {
            rpc_config: BTCLinkRPCConfig::new(rpc_url),
            electrs_url: electrs_url.to_string(),
            no_proxy: false,
            last_fee_rate: 0,
        }
    }
    pub fn send_command<T: Serialize, R: DeserializeOwned>(
        &self,
        method: &str,
        version: &str,
        params: T,
    ) -> Result<R, BTCDataResolverError> {
        self.send_command_with_path("", method, version, params)
    }
    pub fn send_command_with_path<T: Serialize, R: DeserializeOwned>(
        &self,
        path: &str,
        method: &str,
        version: &str,
        params: T,
    ) -> Result<R, BTCDataResolverError> {
        let cmd: BTCLinkRPCCommand<T> = BTCLinkRPCCommand {
            jsonrpc: version.to_string(),
            method: method.to_string(),
            params,
            id: 1,
        };
        let client = if self.no_proxy {
            ClientBuilder::new()
                .no_proxy()
                .build()
                .expect("Client::new()")
        } else {
            ClientBuilder::new().build().expect("Client::new()")
        };
        let rpc_url = format!("{}{}", &self.rpc_config.url, path);
        let base = if self.rpc_config.has_basic_auth() {
            client.post(&rpc_url).basic_auth(
                self.rpc_config.user.to_string(),
                Some(self.rpc_config.password.to_string()),
            )
        } else {
            client.post(&rpc_url)
        };
        let result = base
            .json(&cmd)
            .send()
            .map_err(|err| BTCDataResolverError::new(err.to_string()))?;
        let result_text = result
            .text()
            .map_err(|err| BTCDataResolverError::new(err.to_string()))?;
        let json_result = serde_json::from_str::<BTCLinkRPCCommandResponse<R>>(&result_text);
        if json_result.is_err() {
            Err(BTCDataResolverError {
                message: result_text,
            })
        } else {
            let res = json_result.unwrap();
            if res.result.is_some() {
                Ok(res.result.unwrap())
            } else {
                Err(BTCDataResolverError {
                    message: res.error.unwrap_or("error parsing response".to_string()),
                })
            }
        }
    }
    pub fn get_electrs<R: DeserializeOwned>(
        &self,
        path: String,
    ) -> Result<R, BTCDataResolverError> {
        const RETRY_INTERVAL: Duration = Duration::from_millis(200); // in milliseconds
        const MAX_RETRIES: usize = 300; // 300 * 200ms = 60s, may need to adjust

        let client = self.create_http_client();
        let uri = format!("{}/{}", self.electrs_url, path);

        for attempt in 1..=MAX_RETRIES {
            debug!("Attempt {} to fetch UTXO from Electrum", attempt);
            let response = client.get(&uri).send().map_err(|e| BTCDataResolverError { message: e.to_string() })?;
            let text = response.text().map_err(|e| BTCDataResolverError { message: e.to_string() })?;

            // Check if the response is an array that only contains "[]"
            if text != "[]" {
                debug!("Response from Electrum: {}", text);
                return match serde_json::from_str::<R>(&text) {
                    Ok(data) => Ok(data),
                    Err(e) => Err(BTCDataResolverError { message: e.to_string() }),
                }
            } else {
                debug!("Received empty response, retrying...");
            }

            // Check if we have reached the maximum number of retries
            if attempt == MAX_RETRIES {
                return Err(BTCDataResolverError {
                    message: "Maximum retries reached with empty response".to_string(),
                });
            }

            // sleep for a short interval before retrying
            sleep(RETRY_INTERVAL);
        }

        Err(BTCDataResolverError {
            message: "Failed to retrieve data after maximum retries".to_string(),
        })
    }
    pub fn is_doge(&self) -> bool {
        self.rpc_config.is_doge
    }
    pub fn is_regtest(&self) -> bool {
        self.rpc_config.is_regtest
    }
    pub fn btc_get_raw_transaction(&self, txid: Hash256) -> Result<U8Bytes, BTCDataResolverError> {
        self.send_command("getrawtransaction", "1.0", (txid,))
    }
    pub fn btc_get_new_addresss(
        &self,
        wallet_name: Option<String>,
    ) -> Result<String, BTCDataResolverError> {
        if self.is_doge() {
            self.send_command("getnewaddress", "1.0", ())
        } else {
            let wallet = wallet_name.unwrap_or("default".to_string());
            self.send_command_with_path(&format!("wallet/{}", wallet), "getnewaddress", "1.0", ())
        }
    }
    pub fn btc_send_to_address(
        &self,
        address: String,
        amount: f64,
        wallet_name: Option<String>,
    ) -> Result<Hash256, BTCDataResolverError> {
        if self.is_doge() {
            self.send_command("sendtoaddress", "1.0", (address, amount, "", "", false))
        } else {
            let wallet = wallet_name.unwrap_or("default".to_string());
            self.send_command_with_path(
                &format!("wallet/{}", wallet),
                "sendtoaddress",
                "1.0",
                (address, amount),
            )
        }
    }
    pub fn btc_send_to_address_str(
        &self,
        address: String,
        amount: String,
        wallet_name: Option<String>,
    ) -> Result<Hash256, BTCDataResolverError> {
        if self.is_doge() {
            self.send_command("sendtoaddress", "1.0", (address, amount, "", "", false))
        } else {
            let wallet = wallet_name.unwrap_or("default".to_string());
            self.send_command_with_path(
                &format!("wallet/{}", wallet),
                "sendtoaddress",
                "1.0",
                (address, amount),
            )
        }
    }
    pub fn btc_generate_to_address(
        &self,
        nblocks: u32,
        address: String,
    ) -> Result<Vec<Hash256>, BTCDataResolverError> {
        self.send_command("generatetoaddress", "1.0", (nblocks, address))
    }
    pub fn btc_mine_blocks(
        &self,
        nblocks: u32,
        address: Option<String>,
    ) -> Result<Vec<Hash256>, BTCDataResolverError> {
        self.btc_generate_to_address(nblocks, address.unwrap_or(self.btc_get_new_addresss(None)?))
    }
    pub fn btc_send_raw_transaction(&self, bytes: &[u8]) -> Result<Hash256, BTCDataResolverError> {
        self.send_command("sendrawtransaction", "1.0", (hex::encode(bytes),))
    }
    pub fn btc_get_utxos(&self, address: String) -> Result<Vec<BTCUTXO>, BTCDataResolverError> {
        self.get_electrs(format!("address/{}/utxo", address))
    }
    pub fn btc_estimate_smart_fee_rate(
        &self,
        n_blocks: u32,
    ) -> Result<BTCFeeRateEstimate, BTCDataResolverError> {
        self.send_command("estimatesmartfee", "1.0", (n_blocks,))
    }
    pub fn create_http_client(&self) -> reqwest::blocking::Client {
        if self.no_proxy {
            ClientBuilder::new()
                .no_proxy()
                .build()
                .expect("Failed to create HTTP client with no proxy")
        } else {
            ClientBuilder::new().build() .expect("Failed to create HTTP client")
        }
    }
}

impl QBitcoinAPISync for BTCLinkAPI {
    fn get_funding_transactions(
        &self,
        address: BTCAddress160,
    ) -> anyhow::Result<Vec<BTCTransaction>> {
        let utxos = self.btc_get_utxos(address.to_string())?;

        HashSet::<Hash256>::from_iter(utxos.iter().map(|x| x.txid))
            .into_iter()
            .map(|txid| {
                let raw = self.btc_get_raw_transaction(txid)?;
                BTCTransaction::from_bytes(&raw.0)
            })
            .collect::<anyhow::Result<Vec<BTCTransaction>>>()
    }

    fn get_utxos(&self, address: BTCAddress160) -> anyhow::Result<Vec<BTCUTXO>> {
        self.btc_get_utxos(address.to_address_string())
            .map_err(|e| anyhow::format_err!("{}", e.message))
    }

    fn get_funding_transactions_with_vout(
        &self,
        address: BTCAddress160,
        filter_fn: impl Fn(&BTCUTXO) -> bool
    ) -> anyhow::Result<Vec<BTCTransactionWithVout>> {
        let utxos = self.btc_get_utxos(address.to_string())?;
        let transactions = utxos
            .iter()
            .filter(|&utxo| filter_fn(utxo))
            .map(|utxo| {
                let txid = utxo.txid;
                let tx = self.btc_get_raw_transaction(txid)?;
                Ok(BTCTransactionWithVout {
                    transaction: BTCTransaction::from_bytes(&tx.0)?,
                    vout: utxo.vout,
                })
            })
            .collect::<anyhow::Result<Vec<BTCTransactionWithVout>>>()?;
        Ok(transactions)
    }

    fn get_transaction(&self, txid: Hash256) -> anyhow::Result<BTCTransaction> {
        let raw = self.btc_get_raw_transaction(txid)?;
        BTCTransaction::from_bytes(&raw.0)
    }

    fn send_transaction(&self, tx: &BTCTransaction) -> anyhow::Result<Hash256> {
        let bytes = tx.to_bytes();
        tracing::info!("send_transaction: {}", hex::encode(&bytes));
        let txid = self.btc_send_raw_transaction(&bytes)?;
        Ok(txid)
    }

    fn reset_cached_fee_rate(&mut self, n_blocks: u32) -> anyhow::Result<u64> {
        let fee_rate = self.btc_estimate_smart_fee_rate(n_blocks)?.to_feerate_u64();
        self.last_fee_rate = fee_rate;
        Ok(fee_rate)
    }

    fn get_cached_fee_rate(&self) -> anyhow::Result<u64> {
        if self.last_fee_rate != 0 {
            Ok(self.last_fee_rate)
        } else {
            self.estimate_fee_rate(1)
        }
    }

    fn estimate_fee_rate(&self, n_blocks: u32) -> anyhow::Result<u64> {
        Ok(self.btc_estimate_smart_fee_rate(n_blocks)?.to_feerate_u64())
    }

    fn get_confirmed_funding_transactions_with_vout(
        &self,
        address: BTCAddress160,
    ) -> anyhow::Result<Vec<BTCTransactionWithVout>> {
        Ok(self.get_funding_transactions_with_vout(address, |utxo| utxo.status.confirmed)?)
    }
}

impl QBitcoinAPIFunderSync for BTCLinkAPI {
    fn fund_address(&self, address: BTCAddress160, amount: u64) -> anyhow::Result<Hash256> {
        self.mine_blocks(100)?;

        let txid = self
            .btc_send_to_address_str(
                address.to_address_string(),
                format_u64_8_decimal_places(amount),
                None,
            )
            .map_err(|err| anyhow::format_err!("Failed to fund address: {}", err.message))?;

        self.mine_blocks(100)?;
        Ok(txid)
    }

    fn mine_blocks(&self, count: u32) -> anyhow::Result<Vec<Hash256>> {
        self.btc_mine_blocks(count, None)
            .map_err(|err| anyhow::format_err!("Failed to mine blocks: {}", err.message))
    }

    fn mine_blocks_to_address(&self, count: u32, address: BTCAddress160) -> anyhow::Result<()> {
        self.btc_mine_blocks(count, Some(address.to_address_string()))
            .map_err(|err| anyhow::format_err!("Failed to mine blocks: {}", err.message))?;
        todo!()
    }
}
