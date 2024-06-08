use std::collections::HashSet;

use city_common::logging::debug_timer::DebugTimer;
use city_common_circuit::{builder::comparison::CircuitBuilderComparison, u32::multiple_comparison::list_lte_circuit};

use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField, types::{Field, PrimeField64, Sample}}, hash::hash_types::RichField, iop::{target::{BoolTarget, Target}, witness::{PartialWitness, Witness, WitnessWrite}}, plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig, config::PoseidonGoldilocksConfig}
};
use serde::{Deserialize, Serialize};
struct LEQComparisonTestGadget {
  pub x: Target,
  pub y: Target,
  pub _is_leq: BoolTarget,
  pub expected: BoolTarget,
  pub is_correct: BoolTarget,
}

#[derive(Copy, Clone, Serialize, Deserialize, Hash, PartialEq, Eq)]
struct NumberPair<F> {
  pub x: F,
  pub y: F,
}
impl<F: RichField> NumberPair<F> {
  pub fn rand() -> Self {
    Self {
      x: F::rand(),
      y: F::rand(),
    }
  }
  pub fn new_u64(x: u64, y: u64) -> Self {
    Self {
      x: F::from_noncanonical_u64(x),
      y: F::from_noncanonical_u64(y),
    }
  }
  pub fn rand_vec(count: usize) -> Vec<Self> {
    (0..count).map(|_|Self::rand()).collect()
  }
  fn _print_result(&self, is_leq: bool, is_correct: bool) {
    let is_really_leq = self.x.to_canonical_u64() <= self.y.to_canonical_u64();
    println!("{} <= {} (known: {}, is_leq: {}, is_correct: {})", self.x.to_canonical_u64(), self.y.to_canonical_u64(), is_really_leq, is_leq, is_correct);
  }
}
impl From<NumberPair<u64>> for NumberPair<GoldilocksField> {
    fn from(value: NumberPair<u64>) -> Self {
        Self::new_u64(value.x, value.y)
    }
}
impl LEQComparisonTestGadget {
  fn add_virtual_to<F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>, num_bits: usize) -> Self {
    let x = builder.add_virtual_target();
    let y = builder.add_virtual_target();
    let expected = builder.add_virtual_bool_target_safe();

    let is_leq = builder.is_less_than_or_equal_split(num_bits, x, y);
    let is_correct = builder.is_equal(expected.target, is_leq.target);
    /*
    builder.register_public_input(is_leq.target);
    builder.register_public_input(is_correct.target);
    */
    

    Self {
        x,
        y,
        _is_leq: is_leq,
        expected,
        is_correct,
    }
  }
  fn set_witness<F:RichField, W: Witness<F>>(&self, witness: &mut W, pair: &NumberPair<F>) {
    witness.set_target(self.x, pair.x);
    witness.set_target(self.y, pair.y);
    witness.set_bool_target(self.expected, pair.x.to_canonical_u64() <= pair.y.to_canonical_u64());
  }
}
struct BatchComparisonTestGadget {
  pub tests: Vec<LEQComparisonTestGadget>,
}
impl BatchComparisonTestGadget {
  fn add_virtual_to<F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>, count: usize, num_bits: usize) -> Self {
    let tests = (0..count).map(|_| LEQComparisonTestGadget::add_virtual_to(builder, num_bits)).collect();
    Self {
      tests,
    }
  }
  fn is_all_correct<F: RichField + Extendable<D>, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>) -> BoolTarget {
    let mut is_all_correct = builder._true();
    for test in self.tests.iter() {
      is_all_correct = builder.and(is_all_correct, test.is_correct);
    }
    is_all_correct
  }
  fn set_witness<F:RichField, W: Witness<F>>(&self, witness: &mut W, pairs: &[NumberPair<F>]) {
    assert_eq!(pairs.len(), self.tests.len(), "witness size must match gadget");
    self.tests.iter().zip(pairs.iter()).for_each(|(test, pair)|{
      test.set_witness(witness, pair)
    });
  }

}
fn generate_unique_arith_permutations(output: &mut HashSet<u64>) {
  let output_set = output.iter().map(|x|*x).collect::<Vec<_>>();
  let output_len = output_set.len();
  for x_ind in 0..output_len {
   for y_ind in 0..output_len {
    let x = output_set[x_ind];
    let y= output_set[y_ind];
      output.insert(x.wrapping_add(y));
      output.insert(x.wrapping_mul(y));
      //output.insert((*x).wrapping_sub(*y));
    }
  }
}

fn generate_interesting_combinations(interesting_numbers: &[u64], max_depth: usize) -> Vec<NumberPair<GoldilocksField>> {
  let mut output_set = HashSet::<u64>::new();
  output_set.extend(interesting_numbers.into_iter());
  
  for _ in 0..max_depth {
    generate_unique_arith_permutations(&mut output_set);
  }

  

  let mut pairs = HashSet::<NumberPair<GoldilocksField>>::new();
  let output_set_values = output_set.into_iter().collect::<Vec<_>>();
  let output_set_len = output_set_values.len();
  println!("output_set_len: {}",output_set_len);
  
  for x_ind in 0..output_set_len {
    for y_ind in 0..output_set_len {
      let x = output_set_values[x_ind];
      let y = output_set_values[y_ind];
      pairs.insert(NumberPair::new_u64(x,y));
    }
  }

  pairs.into_iter().collect()


}
fn comparison_test() -> anyhow::Result<()> {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = GoldilocksField;

    let interesting_numbers = [
      0,
      1,
      1u64<<32u64,
      1u64<<63u64,
      (1u64<<63u64)-1u64,
      18446744069414584320u64,
      18446744069414584319u64,
      //18446744069414584318u64,
      18446744069414584310u64,
      0xffffffffu64,
      0xfffffffffu64,
      0xffffffffffu64,
      0xfffffffffffu64,
      0xffffffffffffu64,
      F::rand().to_canonical_u64(),
      F::rand().to_canonical_u64(),

      /*
      0xfffffffffffffu64,
      0xffffffffffffffu64,
      0xfffffffffffffffu64,
      1337u64,
      13376969u64,
      17u64,
      F::rand().to_canonical_u64(),
      F::rand().to_canonical_u64(),
      F::rand().to_canonical_u64(),
      F::rand().to_canonical_u64(),
      F::rand().to_canonical_u64(),
      F::rand().to_canonical_u64(),
      F::rand().to_canonical_u64(),
      F::rand().to_canonical_u64(),*/
    ];
    let interesting_numbers_base_pairs: Vec<NumberPair<GoldilocksField>> = generate_interesting_combinations(&interesting_numbers, 1);

    //toolbox_circuits.print_op_common_data();

    let mut timer = DebugTimer::new("comparison_test");

    timer.lap("start");

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let random_tests = 128;
    let test_count = interesting_numbers_base_pairs.len()+random_tests;
    println!("test_count: {}", test_count);
    let num_bits = 64;
    let batch_test_gadget = BatchComparisonTestGadget::add_virtual_to(&mut builder, test_count, num_bits);
    let is_all_correct = batch_test_gadget.is_all_correct(&mut builder);
    builder.register_public_input(is_all_correct.target);

    let data = builder.build::<C>();


    

    let random_pairs = NumberPair::<F>::rand_vec(random_tests);
    let witness_values = [interesting_numbers_base_pairs, random_pairs].concat();
    

    let mut witness = PartialWitness::<F>::new();
    batch_test_gadget.set_witness(&mut witness, &witness_values);
    let proof = data.prove(witness)?;


    println!("public_inputs: {:?}", proof.public_inputs);
/* 
    proof.public_inputs.chunks_exact(2).zip(witness_values.iter()).for_each(|(results, pair)| {
      let is_leq = results[0].to_canonical_u64() == 1;
      let is_correct = results[1].to_canonical_u64() == 1;
      pair.print_result(is_leq, is_correct);
    });*/
    data.verify(proof)?;



    Ok(())
}
fn comparison_test_simple(x: u64, y: u64) -> anyhow::Result<()> {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = GoldilocksField;

    //toolbox_circuits.print_op_common_data();

    let mut timer = DebugTimer::new("comparison_test");

    timer.lap("start");

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let x_target = builder.add_virtual_target();
    let y_target = builder.add_virtual_target();

    let (x_low_target, x_high_target) = builder.split_low_high(x_target, 32, 64);
    let (y_low_target, y_high_target) = builder.split_low_high(y_target, 32, 64);
    // is_gt = (x_high > y_high) || (x_high == y_high && x_low > y_low)
    // is_leq = !is_gt

    // high_leq_target = (x_high <= y_high)
    let high_leq_target = list_lte_circuit(&mut builder, vec![x_high_target], vec![y_high_target], 32);

    // low_leq_target = (x_low <= y_low)
    let low_leq_target = list_lte_circuit(&mut builder, vec![x_low_target], vec![y_low_target], 32);

    // high_gt_target = (x_high > y_high) = !(x_high <= y_high)
    let high_gt_target = builder.not(high_leq_target);

    // low_gt_target = (x_low > y_low) = !(x_low <= y_low)
    let low_gt_target = builder.not(low_leq_target);

    // high_eq_target = x_high == y_high
    let high_eq_target = builder.is_equal(x_high_target, y_high_target);

    // equal_high_bits_case_target = (x_high == y_high && x_low > y_low)
    let equal_high_bits_case_target = builder.and(high_eq_target, low_gt_target);

    // is_gt = (x_high > y_high) || (x_high == y_high && x_low > y_low)

    let is_gt = builder.or(high_gt_target, equal_high_bits_case_target);

    // is_leq = !is_gt = !((x_high > y_high) || (x_high == y_high && x_low > y_low))
    let is_leq = builder.not(is_gt);


    builder.register_public_inputs(&[
      x_low_target, x_high_target,
      y_low_target, y_high_target,
      high_leq_target.target,
      low_leq_target.target,
      is_leq.target,
    ]);

    let data = builder.build::<C>();

    let x_value = F::from_noncanonical_u64(x);
    let y_value = F::from_noncanonical_u64(y);



    let mut witness = PartialWitness::<F>::new();
    witness.set_target(x_target, x_value);
    witness.set_target(y_target, y_value);
    
    let proof = data.prove(witness)?;

    let x_low_value = proof.public_inputs[0];
    let x_high_value = proof.public_inputs[1];
    let y_low_value = proof.public_inputs[2];
    let y_high_value = proof.public_inputs[3];
    let high_leq_value = proof.public_inputs[4];
    let low_leq_value = proof.public_inputs[5];
    let is_leq = proof.public_inputs[6];
    
    println!("x: {}, y: {}, x <= y: {}", x, y, x<=y);
    println!("x_low: {} (expected: {}),\nx_high: {} (expected: {}),\ny_low: {} (expected: {}),\ny_high: {} (expected: {}),\nhigh_leq: {} (expected: {}),\nlow_leq: {} (expected: {})\n,is_leq: {} (expected: {})", 
    x_low_value, x&0xffffffffu64,
    x_high_value, x>>32u64,
    y_low_value,  y&0xffffffffu64,
    y_high_value, y>>32u64,
    high_leq_value, (x>>32u64) <= (y>>32u64),
    low_leq_value, (x&0xffffffffu64) <= (y&0xffffffffu64),
    is_leq, x<=y,
  );

    data.verify(proof)?;



    Ok(())
}

fn main() {
  comparison_test().unwrap();
  comparison_test_simple(1, 0).unwrap();
  comparison_test_simple(10434664482235024811, 14631330953566294741).unwrap();
  comparison_test_simple(6460793046028424815, 4551021638599061072).unwrap();
    //tracing::info!("Proof: {:?}", proof);
}
