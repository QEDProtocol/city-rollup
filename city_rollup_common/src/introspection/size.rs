use city_common::data::varuint::varuint_size;
use serde::Deserialize;
use serde::Serialize;

pub fn varslice_size(len: usize) -> usize {
    varuint_size(len as u64) + len
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct BTCTransactionLayout {
    pub input_script_sizes: Vec<usize>,
    pub output_script_sizes: Vec<usize>,
}

impl BTCTransactionLayout {
    pub fn new(input_script_sizes: Vec<usize>, output_script_sizes: Vec<usize>) -> Self {
        Self {
            input_script_sizes,
            output_script_sizes,
        }
    }
    pub fn get_total_size(&self) -> usize {
        8 + varuint_size(self.input_script_sizes.len() as u64)
            + varuint_size(self.output_script_sizes.len() as u64)
            + self
                .input_script_sizes
                .iter()
                .fold(0, |sum, input| sum + 40 + varslice_size(*input))
            + self
                .output_script_sizes
                .iter()
                .fold(0, |sum, input| sum + 8 + varslice_size(*input))
    }
}

impl Default for BTCTransactionLayout {
    fn default() -> Self {
        Self::new(vec![], vec![])
    }
}
