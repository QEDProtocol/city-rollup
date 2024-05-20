use std::collections::HashMap;

use plonky2::plonk::{config::GenericConfig, proof::ProofWithPublicInputs};

use super::{
    job_id::QProvingJobDataID,
    proof_store::{QProofStoreReaderSync, QProofStoreWriterSync},
};

pub struct SimpleProofStoreMemory {
    pub proofs: HashMap<QProvingJobDataID, Vec<u8>>,
    pub counters: HashMap<QProvingJobDataID, u32>,
}
impl SimpleProofStoreMemory {
    pub fn new() -> Self {
        Self {
            proofs: HashMap::new(),
            counters: HashMap::new(),
        }
    }
}

impl QProofStoreReaderSync for SimpleProofStoreMemory {
    fn get_proof_by_id<C: GenericConfig<D>, const D: usize>(
        &self,
        id: QProvingJobDataID,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let data = self.proofs.get(&id).ok_or_else(|| {
            anyhow::anyhow!(
                "Proof not found. Wanted {}, Have: {:?}",
                hex::encode(id.to_fixed_bytes()),
                self.proofs
                    .keys()
                    .map(|k| hex::encode(k.to_fixed_bytes()))
                    .collect::<Vec<String>>()
            )
        })?;
        Ok(bincode::deserialize(data)?)
    }

    fn get_bytes_by_id(&self, id: QProvingJobDataID) -> anyhow::Result<Vec<u8>> {
        let data = self.proofs.get(&id).ok_or_else(|| {
            anyhow::anyhow!(
                "Data not found. Wanted {} ({:?}), Have: {:?}",
                hex::encode(id.to_fixed_bytes()),
                id,
                self.proofs
                    .keys()
                    .map(|k| hex::encode(k.to_fixed_bytes()))
                    .collect::<Vec<String>>()
            )
        })?;
        Ok(data.to_vec())
    }
}

impl QProofStoreWriterSync for SimpleProofStoreMemory {
    fn set_proof_by_id<C: GenericConfig<D>, const D: usize>(
        &mut self,
        id: QProvingJobDataID,
        proof: &ProofWithPublicInputs<C::F, C, D>,
    ) -> anyhow::Result<()> {
        self.proofs.insert(id, bincode::serialize(proof)?);
        Ok(())
    }

    fn inc_counter_by_id(&mut self, id: QProvingJobDataID) -> anyhow::Result<u32> {
        let zero = 0u32;
        let ctr = self.counters.get(&id);
        if ctr.is_none() {
            println!("ctr is none, {:?}", id);
        }
        let new_value = 1 + *(self.counters.get(&id).unwrap_or(&zero));
        self.counters.insert(id, new_value);
        Ok(new_value)
    }

    fn set_bytes_by_id(&mut self, id: QProvingJobDataID, data: &[u8]) -> anyhow::Result<()> {
        self.proofs.insert(id, data.to_vec());
        Ok(())
    }
}
