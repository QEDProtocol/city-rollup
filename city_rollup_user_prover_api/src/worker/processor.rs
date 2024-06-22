use std::sync::{mpsc::{self, Receiver, Sender}, Arc, Mutex};



use crate::common::{enc::SimpleEncryptionHelper, request::UPWJobRequest};

use super::{prover::UPWProver, store::UserProverWorkerStore};



pub struct UserProverWorker<E: SimpleEncryptionHelper> {
  store: Arc<Mutex<UserProverWorkerStore>>,
  rx: Receiver<UPWJobRequest>,
  encryption_helper: E,
  prover: UPWProver,
}

impl<E: SimpleEncryptionHelper + 'static> UserProverWorker<E> {
  pub fn new(store: Arc<Mutex<UserProverWorkerStore>>, rx: Receiver<UPWJobRequest>, encryption_helper: E) -> Self {
    let prover = UPWProver::new();
      Self { store, rx, encryption_helper, prover }
  }
  fn run_worker(&self) {
      for request in self.rx.iter() {
        println!("processing request: {}", request.request_id.to_hex_string());
        let result = self.prover.prove_request::<E>(&self.encryption_helper, &request);
        if result.is_ok() {
            self.store.lock().unwrap().set_result(request.request_id, result.unwrap().to_bytes().to_vec());
            println!("processed request: {}", request.request_id.to_hex_string());
        }else{
            println!("error processing request: {}, ({:?})", request.request_id.to_hex_string(), result.err());
        }
      }
  }
  pub fn start_worker(store: Arc<Mutex<UserProverWorkerStore>>, encryption_helper: &E) -> Sender<UPWJobRequest> {
      let (tx, rx) = mpsc::channel::<UPWJobRequest>();
      let helper = encryption_helper.clone();
      let worker = UserProverWorker::new(store.clone(), rx, helper);
      std::thread::spawn(move || {
          worker.run_worker();
      });
      tx
  }
}
