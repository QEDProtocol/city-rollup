use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::proof::OpeningSetTarget;
use plonky2::plonk::proof::ProofTarget;
use plonky2::plonk::proof::ProofWithPublicInputsTarget;

use super::circuit_template::QEDCircuitVerifyTemplate;

pub trait QEDVerifyTemplateCircuitBuilder<F: RichField + Extendable<D>, const D: usize> {
    fn add_virtual_opening_set_vt(
        &mut self,
        template: &QEDCircuitVerifyTemplate,
    ) -> OpeningSetTarget<D>;
    fn add_virtual_proof_vt(&mut self, template: &QEDCircuitVerifyTemplate) -> ProofTarget<D>;
    fn add_virtual_proof_with_pis_vt(
        &mut self,
        template: &QEDCircuitVerifyTemplate,
    ) -> ProofWithPublicInputsTarget<D>;
}

impl<F: RichField + Extendable<D>, const D: usize> QEDVerifyTemplateCircuitBuilder<F, D>
    for CircuitBuilder<F, D>
{
    fn add_virtual_opening_set_vt(
        &mut self,
        template: &QEDCircuitVerifyTemplate,
    ) -> OpeningSetTarget<D> {
        OpeningSetTarget {
            constants: self.add_virtual_extension_targets(template.num_constants),
            plonk_sigmas: self.add_virtual_extension_targets(template.num_routed_wires),
            wires: self.add_virtual_extension_targets(template.num_wires),
            plonk_zs: self.add_virtual_extension_targets(template.num_challenges),
            plonk_zs_next: self.add_virtual_extension_targets(template.num_challenges),
            lookup_zs: self.add_virtual_extension_targets(template.num_lookups),
            next_lookup_zs: self.add_virtual_extension_targets(template.num_lookups),
            partial_products: self.add_virtual_extension_targets(template.total_partial_products),
            quotient_polys: self.add_virtual_extension_targets(template.num_quotient_polys),
        }
    }

    fn add_virtual_proof_vt(&mut self, template: &QEDCircuitVerifyTemplate) -> ProofTarget<D> {
        ProofTarget {
            wires_cap: self.add_virtual_cap(template.fri_cap_height),
            plonk_zs_partial_products_cap: self.add_virtual_cap(template.fri_cap_height),
            quotient_polys_cap: self.add_virtual_cap(template.fri_cap_height),
            openings: self.add_virtual_opening_set_vt(&template),
            opening_proof: self.add_virtual_fri_proof(
                &template.num_leaves_per_oracle,
                &template.vt_fri_params.clone().into(),
            ),
        }
    }

    fn add_virtual_proof_with_pis_vt(
        &mut self,
        template: &QEDCircuitVerifyTemplate,
    ) -> ProofWithPublicInputsTarget<D> {
        let public_inputs = self.add_virtual_targets(template.num_public_inputs);
        let proof = self.add_virtual_proof_vt(template);
        ProofWithPublicInputsTarget {
            proof,
            public_inputs,
        }
    }
}
