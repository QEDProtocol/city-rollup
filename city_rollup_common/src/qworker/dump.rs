use std::collections::HashMap;

use itertools::Itertools;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use super::{job_id::{QProvingJobDataID, QProvingJobDataIDSerialized}, proof_store::QProofStoreReaderSync};

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Eq, Hash, PartialOrd, Ord)]
pub struct QJobWithDependencies {
  pub id: QProvingJobDataID,
  pub dependencies: Vec<QJobWithDependencies>,
}
impl QJobWithDependencies {
  pub fn to_serialized(&self) -> QJobWithDependenciesSerialized {
    self.into()
  }
  pub fn to_job_id_list(&self) -> Vec<QProvingJobDataID> {
    let mut result = vec![self.id];
    for dep in self.dependencies.iter() {
      result.extend(dep.to_job_id_list());
    }
    result
  }
  pub fn get_all_dependencies(&self) -> Vec<QProvingJobDataID> {
    let mut result = vec![];
    for dep in self.dependencies.iter() {
      result.extend(dep.to_job_id_list());
    }
    result
  }
}
#[serde_as]
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Eq, Hash, PartialOrd, Ord)]
pub struct QJobWithDependenciesSerialized {
  #[serde_as(as = "serde_with::hex::Hex")]
  pub id: QProvingJobDataIDSerialized,
  pub dependencies: Vec<QJobWithDependenciesSerialized>,
}
impl From<&QJobWithDependencies> for QJobWithDependenciesSerialized {
    fn from(value: &QJobWithDependencies) -> Self {
        Self {
          id: value.id.to_fixed_bytes(),
          dependencies: value.dependencies.iter().map(|x|x.into()).collect(),
        }
    }
}
#[derive(Debug, Clone)]
pub struct QDependencyMap {
  pub dependencies: HashMap<QProvingJobDataID, Vec<QProvingJobDataID>>,
}
impl QDependencyMap {
  pub fn new() -> Self {
    Self {
      dependencies: HashMap::new(),
    }
  }
  pub fn print_all(&self) {
    for (key, value) in self.dependencies.iter() {
      println!("{} ({:?}) -> {:?}", key.to_hex_string(), key, value);
    }
  }
  pub fn add_dependency(&mut self, parent: QProvingJobDataID, dependency: QProvingJobDataID) {
    let base = self.dependencies.get_mut(&parent);
    if base.is_some() {
      let base = base.unwrap();
      if !base.contains(&dependency) {
        base.push(dependency)
      }
    }else{
      self.dependencies.insert(parent, vec![dependency]);
    }
  }
  pub fn add_dependencies(&mut self, parent: QProvingJobDataID, dependencies: &[QProvingJobDataID]) {
    let base = self.dependencies.get_mut(&parent);
    if base.is_some() {
      let base = base.unwrap();
      dependencies.into_iter().for_each(|dependency| {
        if !base.contains(&dependency) {
          base.push(*dependency)
        }
      })
    }else{
      self.dependencies.insert(parent, dependencies.to_vec());
    }
  }
  pub fn add_dependencies_multidimensional(&mut self, parents: &[QProvingJobDataID], dependencies: &[QProvingJobDataID]) {
    parents.into_iter().for_each(|parent| {
      self.add_dependencies(*parent, dependencies)
    })
  }
  pub fn get_dependencies(&self, id: QProvingJobDataID) -> Vec<QProvingJobDataID> {
    let result = self.dependencies.get(&id);
    if result.is_some() {
      result.unwrap().to_vec()
    }else{
      vec![]
    }
  }
  pub fn get_dependency_tree_for_block(&self, checkpoint_id: u64) -> QJobWithDependencies {
    self.get_dependency_tree(QProvingJobDataID::notify_block_complete(checkpoint_id))
  }
  pub fn get_dependency_tree(&self, root: QProvingJobDataID) -> QJobWithDependencies {
    let dependencies = self.get_dependencies(root).into_iter().map(|id| {
      self.get_dependency_tree(id)
    }).collect::<Vec<_>>();

    QJobWithDependencies {
      id: root,
      dependencies
    }
  }
  pub fn injest_leaf_jobs_from_store<PS: QProofStoreReaderSync>(&mut self, store: &PS, leaf_jobs: &[QProvingJobDataID]) -> anyhow::Result<()> {
    if leaf_jobs.len() == 1 && leaf_jobs[0].is_notify_orchestrator_complete() {
      Ok(())
    }else{
      let groups = leaf_jobs.iter().group_by(|x|x.get_sub_group_counter_goal_next_jobs_id()).into_iter().map(|(goal, group)|{
        let g = group.into_iter().map(|x| *x).collect::<Vec<QProvingJobDataID>>();
    
        (goal, g)
      }).collect::<Vec<_>>();
      
      for (goal, dependencies) in groups.iter() {
        let goal_next_counter = store.get_goal_by_job_id(dependencies[0])?;
        if goal_next_counter != 0 {
          let goal_next_jobs = store.get_next_jobs_by_job_id(*goal)?;
          self.add_dependencies_multidimensional(&goal_next_jobs, dependencies);
          self.injest_leaf_jobs_from_store(store, &goal_next_jobs)?;
        }
      }

      Ok(())
    }
  }
}

pub fn dump_job_dependencies_from_store<PS: QProofStoreReaderSync>(store: &PS, leaf_jobs: &[QProvingJobDataID]) -> anyhow::Result<QDependencyMap> {
  let mut dependency_map = QDependencyMap::new();
  dependency_map.injest_leaf_jobs_from_store(store, leaf_jobs)?;
  Ok(dependency_map)
}