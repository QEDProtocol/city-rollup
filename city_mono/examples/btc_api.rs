use city_mono::btc::api::link_api::BTCLinkAPI;

fn main() {
    let link_api = BTCLinkAPI::new_str(
        "http://devnet:devnet@localhost:1337/bitcoin-rpc/?network=dogeRegtest",
        "http://localhost:1337/api",
    );
    let result = link_api
        .btc_get_raw_transaction(
            "d77869b510a1bca2853fd6abfa95bcd7be3de2b9f0fb661f10e19771c43056bd"
                .try_into()
                .unwrap(),
        )
        .unwrap();
    println!("got: {:?}", result);

    let result = link_api.btc_get_utxos("2N4UFch4vrRapGvqagtGqhBz2goy1thnU2A".into());

    println!("got: {:?}", result);
}
