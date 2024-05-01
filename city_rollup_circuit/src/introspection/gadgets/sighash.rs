use city_common_circuit::vector_builder::ByteTargetVectorBuilder;
use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, iop::target::Target,
    plonk::circuit_builder::CircuitBuilder,
};

use super::transaction::BTCTransactionBytesGadget;

#[derive(Debug, Clone)]
pub struct SigHashPreimageBytesGadget {
    pub transaction: BTCTransactionBytesGadget,
    pub sighash_type: [Target; 4],
}
impl SigHashPreimageBytesGadget {
    pub fn add_virtual_to_from_tx<F: RichField + Extendable<D>, const D: usize>(
        _builder: &mut CircuitBuilder<F, D>,
        tx: BTCTransactionBytesGadget,
        sighash_type: [Target; 4],
    ) -> Self {
        Self {
            transaction: tx,
            sighash_type: sighash_type,
        }
    }
    pub fn to_byte_targets<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Vec<Target> {
        let mut vb = ByteTargetVectorBuilder::new();
        vb.write_slice(&self.transaction.to_byte_targets(builder));
        vb.write_slice(&self.sighash_type);
        vb.to_targets_vec()
    }
}
