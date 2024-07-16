use std::{collections::HashMap, sync::{mpsc, Arc, Mutex}, thread, time::Duration};

use city_crypto::hash::base_types::hash256::Hash256;
fn reverse_string(s: String) -> String {
    s.chars().rev().collect()
}
#[derive(Clone, Debug)]
struct UserProverWorkerStore {
    pub results: HashMap<Hash256, String>,
}
impl UserProverWorkerStore {
    pub fn new() -> Self {
        Self {
            results: HashMap::new(),
        }
    }
    pub fn get_result(&self, key: &Hash256) -> Option<&String> {
        self.results.get(key)
    }
    pub fn set_result(&mut self, key: Hash256, value: String) {
        self.results.insert(key, value);
    }
}

fn main() {
    let (tx_main, rx_main) = mpsc::channel::<Hash256>();
    let (tx_worker, rx_worker) = mpsc::channel::<String>();

    let store = Arc::new(Mutex::new(UserProverWorkerStore::new()));

    let tx_main_in_worker = tx_main.clone();
    let store_in_worker = store.clone();
    thread::spawn(move || {
        for recv in rx_worker {
            let new_msg = reverse_string(recv);
            let key = Hash256::rand();
            store_in_worker.lock().unwrap().set_result(key, new_msg);
            tx_main_in_worker.send(key).unwrap();
        }
    });

    let tx_worker_in_api = tx_worker.clone();
    thread::spawn(move || {
        let vals = vec![
            String::from("more"),
            String::from("messages"),
            String::from("for"),
            String::from("you"),
        ];

        for val in vals {
            tx_worker_in_api.send(val).unwrap();
            thread::sleep(Duration::from_secs(1));
        }
    });

    for received in rx_main {
        let result = store.lock().unwrap().get_result(&received).unwrap().to_string();
        println!("Got: {result}");
    }
}
