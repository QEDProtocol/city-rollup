use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::target::{BoolTarget, Target},
    plonk::circuit_builder::CircuitBuilder,
};

use crate::common::builder::select::CircuitBuilderSelectHelpers;

pub trait CircuitBuilderConnectHelpers<F: RichField + Extendable<D>, const D: usize> {
    fn connect_if_true(&mut self, condition: BoolTarget, x: Target, y: Target);
    fn connect_if_false(&mut self, condition: BoolTarget, x: Target, y: Target);
    fn connect_hashes_if_true(&mut self, condition: BoolTarget, x: HashOutTarget, y: HashOutTarget);
    fn connect_hashes_if_false(
        &mut self,
        condition: BoolTarget,
        x: HashOutTarget,
        y: HashOutTarget,
    );
    fn connect_hashes_switch(
        &mut self,
        switch: BoolTarget,
        value: HashOutTarget,
        on_hash: HashOutTarget,
        off_hash: HashOutTarget,
    );
    fn connect_hashes_enum(&mut self, value: HashOutTarget, allowed: &[HashOutTarget]);

    fn connect_hashes_switch_on_enum(
        &mut self,
        switch: BoolTarget,
        value: HashOutTarget,
        on_hashes: &[HashOutTarget],
        off_hash: HashOutTarget,
    );
    fn connect_hashes_switch_off_enum(
        &mut self,
        switch: BoolTarget,
        value: HashOutTarget,
        on_hash: HashOutTarget,
        off_hashes: &[HashOutTarget],
    );
    fn connect_hashes_if_true_enum(
        &mut self,
        condition: BoolTarget,
        value: HashOutTarget,
        allowed: &[HashOutTarget],
    );
    fn connect_hashes_if_false_enum(
        &mut self,
        condition: BoolTarget,
        value: HashOutTarget,
        allowed: &[HashOutTarget],
    );
    fn connect_vec(&mut self, x: &[Target], y: &[Target]);
    fn connect_templated_array(
        &mut self,
        template_start: &[u64],
        template_middle: &[Target],
        template_end: &[u64],
        target_array: &[Target],
    );
    fn connect_constant(&mut self, x: Target, value: u64);
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderConnectHelpers<F, D>
    for CircuitBuilder<F, D>
{
    fn connect_if_true(&mut self, condition: BoolTarget, x: Target, y: Target) {
        let tmp = self.select(condition, y, x);
        self.connect(x, tmp);
    }

    fn connect_if_false(&mut self, condition: BoolTarget, x: Target, y: Target) {
        let tmp = self.select(condition, x, y);
        self.connect(x, tmp);
    }

    fn connect_hashes_if_true(
        &mut self,
        condition: BoolTarget,
        x: HashOutTarget,
        y: HashOutTarget,
    ) {
        let tmp = self.select_hash(condition, y, x);
        self.connect_hashes(x, tmp);
    }

    fn connect_hashes_if_false(
        &mut self,
        condition: BoolTarget,
        x: HashOutTarget,
        y: HashOutTarget,
    ) {
        let tmp = self.select_hash(condition, x, y);
        self.connect_hashes(x, tmp);
    }

    fn connect_hashes_switch(
        &mut self,
        switch: BoolTarget,
        value: HashOutTarget,
        on_hash: HashOutTarget,
        off_hash: HashOutTarget,
    ) {
        let tmp = self.select_hash(switch, on_hash, off_hash);
        self.connect_hashes(value, tmp);
    }

    fn connect_hashes_enum(&mut self, value: HashOutTarget, allowed: &[HashOutTarget]) {
        let enum_hash = self.pick_from_hashes(value, allowed);
        self.connect_hashes(value, enum_hash);
    }

    fn connect_hashes_switch_on_enum(
        &mut self,
        switch: BoolTarget,
        value: HashOutTarget,
        on_hashes: &[HashOutTarget],
        off_hash: HashOutTarget,
    ) {
        let on_hash = self.pick_from_hashes(value, on_hashes);

        let actual_hash_target = HashOutTarget {
            elements: core::array::from_fn(|i| {
                self.select(switch, on_hash.elements[i], off_hash.elements[i])
            }),
        };
        self.connect_hashes(value, actual_hash_target);
    }
    fn connect_hashes_switch_off_enum(
        &mut self,
        switch: BoolTarget,
        value: HashOutTarget,
        on_hash: HashOutTarget,
        off_hashes: &[HashOutTarget],
    ) {
        let off_hash = self.pick_from_hashes(value, off_hashes);

        let actual_hash_target = HashOutTarget {
            elements: core::array::from_fn(|i| {
                self.select(switch, on_hash.elements[i], off_hash.elements[i])
            }),
        };
        self.connect_hashes(value, actual_hash_target);
    }
    fn connect_hashes_if_true_enum(
        &mut self,
        condition: BoolTarget,
        value: HashOutTarget,
        allowed: &[HashOutTarget],
    ) {
        self.connect_hashes_switch_on_enum(condition, value, allowed, value);
    }

    fn connect_hashes_if_false_enum(
        &mut self,
        condition: BoolTarget,
        value: HashOutTarget,
        allowed: &[HashOutTarget],
    ) {
        self.connect_hashes_switch_off_enum(condition, value, value, allowed);
    }

    fn connect_vec(&mut self, x: &[Target], y: &[Target]) {
        assert_eq!(x.len(), y.len());

        for i in 0..x.len() {
            self.connect(x[i], y[i]);
        }
    }

    fn connect_constant(&mut self, x: Target, value: u64) {
        let val = self.constant(F::from_noncanonical_u64(value));
        self.connect(x, val);
    }

    fn connect_templated_array(
        &mut self,
        template_start: &[u64],
        template_middle: &[Target],
        template_end: &[u64],
        target_array: &[Target],
    ) {
        let tpl_start = template_start
            .iter()
            .map(|v| self.constant(F::from_noncanonical_u64(*v)))
            .collect::<Vec<_>>();
        let tpl_end = template_end
            .iter()
            .map(|v| self.constant(F::from_noncanonical_u64(*v)))
            .collect::<Vec<_>>();
        let combined = [tpl_start, template_middle.to_vec(), tpl_end].concat();
        self.connect_vec(target_array, &combined);
    }
}
