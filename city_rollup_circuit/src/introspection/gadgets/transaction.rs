use city_common_circuit::builder::core::CircuitBuilderHelpersCore;
use city_common_circuit::builder::core::WitnessHelpersCore;
use city_common_circuit::hash::accelerator::sha256::planner::Sha256AcceleratorDomain;
use city_common_circuit::hash::base_types::hash256bytes::CircuitBuilderHash256Bytes;
use city_common_circuit::hash::base_types::hash256bytes::Hash256BytesTarget;
use city_common_circuit::hash::base_types::hash256bytes::WitnessHash256Bytes;
use city_common_circuit::vector_builder::ByteTargetVectorBuilder;
use city_rollup_common::introspection::size::BTCTransactionLayout;
use city_rollup_common::introspection::transaction::BTCTransaction;
use city_rollup_common::introspection::transaction::BTCTransactionInput;
use city_rollup_common::introspection::transaction::BTCTransactionOutput;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::iop::witness::Witness;
use plonky2::plonk::circuit_builder::CircuitBuilder;

#[derive(Debug, Clone)]
pub struct BTCTransactionBytesInputGadget {
    pub hash: Hash256BytesTarget,
    pub index: [Target; 4],
    pub script: Vec<Target>,
    pub sequence: [Target; 4],
}
impl BTCTransactionBytesInputGadget {
    pub fn add_virtual_to<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        script: Vec<Target>,
    ) -> Self {
        Self {
            hash: builder.add_virtual_hash256_bytes_target(),
            index: builder.add_virtual_target_arr(),
            script,
            sequence: builder.add_virtual_target_arr(),
        }
    }
    pub fn set_witness<W: Witness<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        witness: &mut W,
        tx_in: &BTCTransactionInput,
    ) {
        witness.set_hash256_bytes_target(&self.hash, &tx_in.hash.0);
        witness.set_u32_bytes_le_target(&self.index, tx_in.index);
        witness.set_byte_targets(&self.script, &tx_in.script);
        witness.set_u32_bytes_le_target(&self.sequence, tx_in.sequence);
    }
}

#[derive(Debug, Clone)]
pub struct BTCTransactionBytesOutputGadget {
    pub value: [Target; 8],
    pub script: Vec<Target>,
}
impl BTCTransactionBytesOutputGadget {
    pub fn add_virtual_to<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        script: Vec<Target>,
    ) -> Self {
        Self {
            value: builder.add_virtual_target_arr(),
            script,
        }
    }
    pub fn get_value_target_u64<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Target {
        builder.le_bytes_to_u64_u56_target(&self.value)
    }
    pub fn set_witness<W: Witness<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        witness: &mut W,
        tx_out: &BTCTransactionOutput,
    ) {
        witness.set_u64_bytes_le_target(&self.value, tx_out.value);
        witness.set_byte_targets(&self.script, &tx_out.script);
    }
}
#[derive(Debug, Clone)]
pub struct BTCTransactionBytesGadget {
    pub layout: BTCTransactionLayout,
    pub version: [Target; 4],
    pub inputs: Vec<BTCTransactionBytesInputGadget>,
    pub outputs: Vec<BTCTransactionBytesOutputGadget>,
    pub locktime: [Target; 4],
    pub last_hash: Option<Hash256BytesTarget>,
    pub enable_der_pad: bool,
}

impl BTCTransactionBytesGadget {
    pub fn add_virtual_to_fixed_locktime_version<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        layout: BTCTransactionLayout,
        version: u32,
        locktime: u32,
        same_script: bool,
    ) -> Self {
        Self::add_virtual_to_fixed_locktime_version_with_der(
            builder,
            layout,
            version,
            locktime,
            same_script,
            false,
        )
    }
    pub fn add_virtual_to_complex<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        layout: BTCTransactionLayout,
        version: Option<u32>,
        locktime: Option<u32>,
        input_scripts: Option<Vec<Vec<Target>>>,
    ) -> Self {
        Self::add_virtual_to_complex_with_der(
            builder,
            layout,
            version,
            locktime,
            input_scripts,
            false,
        )
    }
    pub fn add_virtual_to_fixed_locktime_version_with_der<
        F: RichField + Extendable<D>,
        const D: usize,
    >(
        builder: &mut CircuitBuilder<F, D>,
        layout: BTCTransactionLayout,
        version: u32,
        locktime: u32,
        same_script: bool,
        enable_der_pad: bool,
    ) -> Self {
        let scripts = if same_script {
            let script = builder.add_virtual_targets(layout.input_script_sizes[0]);
            vec![script; layout.input_script_sizes.len()]
        } else {
            if enable_der_pad
                && layout.input_script_sizes.len() == 1
                && layout.input_script_sizes[0] == 107
            {
                vec![builder.add_virtual_targets(106)]
            } else {
                layout
                    .input_script_sizes
                    .iter()
                    .map(|s| builder.add_virtual_targets(*s))
                    .collect()
            }
        };
        let version_t = builder.constant_u32_bytes_le(version);
        let locktime_t = builder.constant_u32_bytes_le(locktime);
        let inputs = scripts
            .into_iter()
            .map(|scr| BTCTransactionBytesInputGadget::add_virtual_to(builder, scr))
            .collect();
        let outputs = layout
            .output_script_sizes
            .iter()
            .map(|s| {
                let scr = builder.add_virtual_targets(*s);
                BTCTransactionBytesOutputGadget::add_virtual_to(builder, scr)
            })
            .collect();
        Self {
            layout,
            version: version_t,
            inputs,
            outputs,
            locktime: locktime_t,
            last_hash: None,
            enable_der_pad,
        }
    }
    pub fn add_virtual_to_complex_with_der<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        layout: BTCTransactionLayout,
        version: Option<u32>,
        locktime: Option<u32>,
        input_scripts: Option<Vec<Vec<Target>>>,
        enable_der_pad: bool,
    ) -> Self {
        assert!(
            !enable_der_pad,
            "enable_der_pad not implemented for add_virtual_to_complex"
        );
        let version_t: [Target; 4] = if version.is_some() {
            builder.constant_u32_bytes_le(version.unwrap())
        } else {
            builder.add_virtual_target_arr()
        };
        let locktime_t: [Target; 4] = if locktime.is_some() {
            builder.constant_u32_bytes_le(version.unwrap())
        } else {
            builder.add_virtual_target_arr()
        };
        let inputs: Vec<BTCTransactionBytesInputGadget> = if input_scripts.is_some() {
            input_scripts
                .unwrap()
                .iter()
                .map(|script| {
                    BTCTransactionBytesInputGadget::add_virtual_to(builder, script.clone())
                })
                .collect()
        } else {
            layout
                .input_script_sizes
                .iter()
                .map(|s| {
                    let scr = builder.add_virtual_targets(*s);
                    BTCTransactionBytesInputGadget::add_virtual_to(builder, scr)
                })
                .collect()
        };
        let outputs = layout
            .output_script_sizes
            .iter()
            .map(|s| {
                let scr = builder.add_virtual_targets(*s);
                BTCTransactionBytesOutputGadget {
                    value: builder.add_virtual_target_arr(),
                    script: scr,
                }
            })
            .collect();
        Self {
            layout,
            version: version_t,
            inputs,
            outputs,
            locktime: locktime_t,
            last_hash: None,
            enable_der_pad,
        }
    }

    pub fn connect_to_hash_deposit<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        domain: &mut Sha256AcceleratorDomain,
        hash: Hash256BytesTarget,
        enable_der_pad: bool,
    ) {
        let base_bytes = self.to_byte_targets(builder);
        let base_hash = domain.btc_hash256(builder, &base_bytes);
        if enable_der_pad
            && self.enable_der_pad
            && self.inputs.len() == 1
            && self.outputs.len() == 1
            && self.inputs[0].script.len() == 106
        {
            let mut clone_with_107 = self.clone();
            clone_with_107.inputs[0].script = [
                self.inputs[0].script[0..5].to_vec(),
                vec![builder.zero()],
                self.inputs[0].script[5..106].to_vec(),
            ]
            .concat();
            let bytes = clone_with_107.to_byte_targets(builder);
            let secondary_hash = domain.btc_hash256(builder, &bytes);
            builder.connect_one_of_hash256_bytes(hash, base_hash, secondary_hash);
        } else {
            builder.connect_hash256_bytes(hash, base_hash);
        }
    }

    pub fn to_byte_targets<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Vec<Target> {
        let mut vb = ByteTargetVectorBuilder::new();

        vb.write_slice(&self.version);

        // inputs
        vb.write_constant_varuint(builder, self.inputs.len() as u64);
        for input in &self.inputs {
            vb.write_slice(&input.hash);
            vb.write_slice(&input.index);
            vb.write_var_slice(builder, &input.script);
            vb.write_slice(&input.sequence);
        }

        // outputs
        vb.write_constant_varuint(builder, self.outputs.len() as u64);
        for output in &self.outputs {
            vb.write_slice(&output.value);
            vb.write_var_slice(builder, &output.script);
        }

        vb.write_slice(&self.locktime);

        vb.to_targets_vec()
    }
    pub fn get_hash(&self) -> Hash256BytesTarget {
        self.last_hash.unwrap()
    }
    pub fn compute_hash<F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        hash_domain: &mut Sha256AcceleratorDomain,
    ) -> Hash256BytesTarget {
        if self.last_hash.is_some() {
            return self.last_hash.unwrap();
        }
        let result = self.compute_hash_immutable(builder, hash_domain);
        self.last_hash = Some(result.clone());
        result
    }
    pub fn compute_hash_immutable<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        hash_domain: &mut Sha256AcceleratorDomain,
    ) -> Hash256BytesTarget {
        if self.last_hash.is_some() {
            return self.last_hash.unwrap();
        }
        let bytes = self.to_byte_targets(builder);
        hash_domain.btc_hash256(builder, &bytes)
    }
    pub fn set_witness<W: Witness<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        witness: &mut W,
        tx: &BTCTransaction,
    ) {
        witness.set_u32_bytes_le_target(&self.version, tx.version);
        if self.enable_der_pad
            && self.inputs.len() == 1
            && self.outputs.len() == 1
            && self.inputs[0].script.len() == 106
            &&tx.inputs[0].script.len() == 107
        {
            let mut tx_in = tx.inputs[0].clone();
            tx_in.script = [tx_in.script[0..5].to_vec(), tx_in.script[6..107].to_vec()].concat();
            self.inputs[0].set_witness(witness, &tx_in);
        } else {
            for (input, tx_in) in self.inputs.iter().zip(tx.inputs.iter()) {
                input.set_witness(witness, tx_in);
            }
        }
        for (output, tx_out) in self.outputs.iter().zip(tx.outputs.iter()) {
            output.set_witness(witness, tx_out);
        }
        witness.set_u32_bytes_le_target(&self.locktime, tx.locktime);
    }
}
