use std::collections::HashMap;

use city_common::logging::trace_timer::TraceTimer;
use city_common_circuit::circuits::traits::qstandard::QStandardCircuit;
use city_crypto::hash::qhashout::QHashOut;
use city_rollup_circuit::sighash_circuits::sighash::CRSigHashCircuit;
use city_rollup_common::introspection::rollup::introspection::{BlockSpendCoreConfig, BlockSpendIntrospectionGadgetConfig};
use city_store::store::sighash::SigHashMerkleTree;
use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig};
use serde::{Deserialize, Serialize};

type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
const D: usize = 2;

#[derive(Serialize, Deserialize, PartialEq, Copy, Clone, Debug, Hash, Eq, PartialOrd, Ord)]
pub struct MultiIndex {
    pub local_index: usize,
    pub global_index: usize,
}
impl MultiIndex {
  pub fn new(local_index: usize, global_index: usize) -> Self {
    Self {
      local_index,
      global_index,
    }
  }
  pub fn new_list(count: usize, local_index_offset: usize, global_index_offset: usize) -> Vec<Self> {
    (0..count).map(|i| Self{
      local_index: local_index_offset + i,
      global_index: global_index_offset + i,
    }).collect()
  }
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug, Hash, Eq, PartialOrd, Ord)]
pub struct SighashPermutationSet {
   pub existing_set: Vec<MultiIndex>,
   pub target_set: Vec<MultiIndex>,
   pub target_configs: Vec<BlockSpendIntrospectionGadgetConfig>,
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug, Hash, Eq)]
pub struct SighashPermutationSetResult {
   pub existing_set: Vec<MultiIndex>,
   pub target_set: Vec<MultiIndex>,
   pub result_hashes: Vec<QHashOut<F>>,
}

fn get_perm_set(prev_max_deposits: i32, prev_max_withdrawals: i32, target_max_deposits: usize, target_max_withdrawals: usize) -> SighashPermutationSet {
  if prev_max_deposits < 0 || prev_max_withdrawals < 0 {
    let target_configs = BlockSpendCoreConfig::standard_p2sh_p2pkh()
    .generate_permutations(target_max_deposits, target_max_withdrawals);
    let count = target_configs.len();
    SighashPermutationSet{
      existing_set: vec![],
      target_set: MultiIndex::new_list(count, 0, 0),
      target_configs,
    }

  }else{
    let existing_configs = BlockSpendCoreConfig::standard_p2sh_p2pkh()
      .generate_permutations(target_max_deposits, target_max_withdrawals);
    let all_target_configs = BlockSpendCoreConfig::standard_p2sh_p2pkh()
      .generate_permutations(target_max_deposits, target_max_withdrawals);
    let mut existing_index_map: HashMap<BlockSpendIntrospectionGadgetConfig, usize> = HashMap::new();
    for (i, config) in existing_configs.iter().enumerate() {
      existing_index_map.insert(config.clone(), i);
    }
    let mut target_index_map: HashMap<BlockSpendIntrospectionGadgetConfig, usize> = HashMap::new();
    for (i, config) in all_target_configs.iter().enumerate() {
      target_index_map.insert(config.clone(), i);
    }
    let target_configs = all_target_configs.into_iter().filter(|x| {
      !existing_index_map.contains_key(&x)
    }).collect::<Vec<_>>();

    let existing_set = existing_configs.iter().enumerate().map(|(i, c)|{
      MultiIndex {
        local_index: i,
        global_index: *target_index_map.get(c).unwrap(),
      }
    }).collect::<Vec<_>>();


    let target_set = target_configs.iter().enumerate().map(|(i, c)|{
      MultiIndex {
        local_index: i,
        global_index: *target_index_map.get(c).unwrap(),
      }
    }).collect::<Vec<_>>();
    
    SighashPermutationSet{
      existing_set,
      target_set,
      target_configs,
    }

  }
}
fn compute_permutations(perm_set: SighashPermutationSet) -> SighashPermutationSetResult {
  //println!("existing_set: {}", serde_json::to_string(&perm_set.existing_set).unwrap());
  //println!("target_set: {}", serde_json::to_string(&perm_set.target_set).unwrap());
  let mut timer = TraceTimer::new("config_permutations");
  timer.lap("start");
  let total = perm_set.target_configs.len();
  let average_time = 6500f64;
  println!("Circuits to Generate: {}", total);
  println!("Estimated completion time: {:.2} minutes", (total as f64)*average_time/(60_000f64));

  let mut fingerprints: Vec<QHashOut<F>> = Vec::new();
  for i in 0..perm_set.target_configs.len() {
      let circuit: CRSigHashCircuit<PoseidonGoldilocksConfig, 2> = CRSigHashCircuit::<C, D>::new(perm_set.target_configs[i].clone());
      let fingerprint = circuit.get_fingerprint();
      println!("[{}]: {}", i, fingerprint.to_string());
      fingerprints.push(fingerprint);
      timer.event(format!("generated fingerprint {}", i));
  }
  println!("Total permutations: {}", fingerprints.len());
  SighashPermutationSetResult {
    existing_set: perm_set.existing_set,
    target_set: perm_set.target_set,
    result_hashes: fingerprints,
  }




}
fn main() {
    let mt = SigHashMerkleTree::new();
    println!("root: {:?}", mt.root.0);
    let prev_max_deposits: i32 = 4;
    let prev_max_withdrawals: i32 = 4;
    let target_max_deposits = 5;
    let target_max_withdrawals = 5;

    let perm_set = get_perm_set(prev_max_deposits, prev_max_withdrawals, target_max_deposits, target_max_withdrawals);
    let result = compute_permutations(perm_set);
    println!("result:\n{}",serde_json::to_string(&result).unwrap());
}
