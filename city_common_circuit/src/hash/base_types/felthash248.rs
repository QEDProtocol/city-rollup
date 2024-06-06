use plonky2::{
  field::extension::Extendable,
  hash::hash_types::{HashOutTarget, RichField},
  iop::target::{BoolTarget, Target},
  plonk::circuit_builder::CircuitBuilder,
};

use super::hash256bytes::Hash256BytesTarget;

pub trait CircuitBuilderFelt248Hash<F: RichField + Extendable<D>, const D: usize> {
  fn hash256_bytes_to_felt248_hashout(&mut self, value: Hash256BytesTarget) -> HashOutTarget;
  fn hashout_to_felt248_hashout(&mut self, value: HashOutTarget) -> HashOutTarget;
  fn felt248_hashout_to_hash256_bytes(&mut self, value: HashOutTarget) -> Hash256BytesTarget;
  fn connect_full_hashout_to_felt248_hashout(
      &mut self,
      standard_hashout: HashOutTarget,
      felt248_hashout: HashOutTarget,
  );
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderFelt248Hash<F, D>
  for CircuitBuilder<F, D>
{
  fn hash256_bytes_to_felt248_hashout(&mut self, value: Hash256BytesTarget) -> HashOutTarget {
      let bits = value[0..31]
          .iter()
          .flat_map(|v| self.split_le(*v, 8))
          .collect::<Vec<_>>();

          let a = self.le_sum(bits[0..64].iter());
          let b = self.le_sum(bits[64..128].iter());
          let c = self.le_sum(bits[128..192].iter());
          let d = self.le_sum(bits[192..248].iter());

      HashOutTarget {
          elements: [a,b,c,d]
      }
  }

  fn hashout_to_felt248_hashout(&mut self, value: HashOutTarget) -> HashOutTarget {
      let a = value.elements[0];
      let b = value.elements[1];
      let c = value.elements[2];
      let d = self.split_low_high(value.elements[3], 56, 64).0;
      HashOutTarget {
          elements: [a, b, c, d],
      }
  }

  fn felt248_hashout_to_hash256_bytes(&mut self, value: HashOutTarget) -> Hash256BytesTarget {
      let bytes = value
          .elements
          .iter()
          .flat_map(|e| self.split_le(*e, 64))
          .collect::<Vec<BoolTarget>>()
          .chunks(8)
          .map(|bits| self.le_sum(bits.iter()))
          .collect::<Vec<_>>();
      core::array::from_fn(|i| bytes[i])
  }

  fn connect_full_hashout_to_felt248_hashout(
      &mut self,
      standard_hashout: HashOutTarget,
      felt248_hashout: HashOutTarget,
  ) {
      let std = self.hashout_to_felt248_hashout(standard_hashout);
      self.connect_hashes(std, felt248_hashout);
      /*
      let subtracted: [Target; 4] = core::array::from_fn(|i| {
          self.sub(standard_hashout.elements[i], felt248_hashout.elements[i])
      });
      self.ensure_is_zero_or_top_bit(subtracted[0]);
      self.ensure_is_zero_or_top_bit(subtracted[1]);
      self.ensure_is_zero_or_top_bit(subtracted[2]);
      self.ensure_is_zero_or_top_bit(subtracted[3]);*/
  }
}
