use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::target::{BoolTarget, Target},
    plonk::circuit_builder::CircuitBuilder,
};

pub trait CircuitBuilderOptionalInputs<F: RichField + Extendable<D>, const D: usize> {
    fn add_virtual_target_if_none(&mut self, target: Option<Target>) -> Target;
    fn add_virtual_hash_if_none(&mut self, hash_target: Option<HashOutTarget>) -> HashOutTarget;
    fn add_virtual_bool_if_none(&mut self, bool_target: Option<BoolTarget>) -> BoolTarget;
    fn add_virtual_hashes_if_none(&mut self, hash_targets: Option<Vec<HashOutTarget>>, length: usize) -> Vec<HashOutTarget>;

    fn add_virtual_target_if_none_op(&mut self, target: Option<Target>, option_flags: &mut u64, flag: u64) -> Target;
    fn add_virtual_hash_if_none_op(&mut self, hash_target: Option<HashOutTarget>, option_flags: &mut u64, flag: u64) -> HashOutTarget;
    fn add_virtual_bool_if_none_op(&mut self, bool_target: Option<BoolTarget>, option_flags: &mut u64, flag: u64) -> BoolTarget;
    fn add_virtual_hashes_if_none_op(&mut self, hash_targets: Option<Vec<HashOutTarget>>, length: usize, option_flags: &mut u64, flag: u64) -> Vec<HashOutTarget>;

}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderOptionalInputs<F, D>
    for CircuitBuilder<F, D>
{
    fn add_virtual_target_if_none(&mut self, target: Option<Target>) -> Target {
        if target.is_some(){
            target.unwrap()
        }else{
            self.add_virtual_target()
        }
    }

    fn add_virtual_hash_if_none(&mut self, hash_target: Option<HashOutTarget>) -> HashOutTarget {
        if hash_target.is_some(){
            hash_target.unwrap()
        }else{
            self.add_virtual_hash()
        }
    }

    fn add_virtual_bool_if_none(&mut self, bool_target: Option<BoolTarget>) -> BoolTarget {
        if bool_target.is_some(){
            bool_target.unwrap()
        }else{
            self.add_virtual_bool_target_safe()
        }
    }

    fn add_virtual_hashes_if_none(&mut self, hash_targets: Option<Vec<HashOutTarget>>, length: usize) -> Vec<HashOutTarget> {
        if hash_targets.is_some(){
            hash_targets.unwrap()
        }else{
            (0..length).map(|_| self.add_virtual_hash()).collect()
        }
    }

    fn add_virtual_target_if_none_op(&mut self, target: Option<Target>, option_flags: &mut u64, flag: u64) -> Target {
        
        if target.is_some(){
            *option_flags |= flag;
            target.unwrap()
        }else{
            self.add_virtual_target()
        }
    }

    fn add_virtual_hash_if_none_op(&mut self, hash_target: Option<HashOutTarget>, option_flags: &mut u64, flag: u64) -> HashOutTarget {
        if hash_target.is_some(){
            *option_flags |= flag;
            hash_target.unwrap()
        }else{
            self.add_virtual_hash()
        }
    }

    fn add_virtual_bool_if_none_op(&mut self, bool_target: Option<BoolTarget>, option_flags: &mut u64, flag: u64) -> BoolTarget {
        if bool_target.is_some(){
            *option_flags |= flag;
            bool_target.unwrap()
        }else{
            self.add_virtual_bool_target_safe()
        }
    }

    fn add_virtual_hashes_if_none_op(&mut self, hash_targets: Option<Vec<HashOutTarget>>, length: usize, option_flags: &mut u64, flag: u64) -> Vec<HashOutTarget> {
        if hash_targets.is_some(){
            *option_flags |= flag;
            hash_targets.unwrap()
        }else{
            (0..length).map(|_| self.add_virtual_hash()).collect()
        }
    }
}