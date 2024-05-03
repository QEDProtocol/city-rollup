use std::marker::PhantomData;

use super::ecdsa::gadgets::{
    biguint::BigUintTarget,
    curve::CircuitBuilderCurve,
    curve_fixed_base::fixed_base_curve_mul_circuit,
    ecdsa::{ECDSAPublicKeyTarget, ECDSASignatureTarget},
    glv::CircuitBuilderGlv,
    nonnative::{CircuitBuilderNonNative, NonNativeTarget},
};
use crate::{
    builder::hash::core::CircuitBuilderHashCore,
    crypto::secp256k1::ecdsa::gadgets::biguint::WitnessBigUint,
};
use city_crypto::{
    field::conversions::bytes33_to_public_key,
    signature::secp256k1::curve::{
        curve_types::Curve,
        ecdsa::{ECDSAPublicKey, ECDSASignature},
        secp256k1::Secp256K1,
    },
};
use num::BigUint;
use plonky2::{
    field::{extension::Extendable, secp256k1_scalar::Secp256K1Scalar},
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::{target::Target, witness::Witness},
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};
fn biguint_from_array(arr: [u64; 4]) -> BigUint {
    BigUint::from_slice(&[
        arr[0] as u32,
        (arr[0] >> 32) as u32,
        arr[1] as u32,
        (arr[1] >> 32) as u32,
        arr[2] as u32,
        (arr[2] >> 32) as u32,
        arr[3] as u32,
        (arr[3] >> 32) as u32,
    ])
}
pub fn verify_message_circuit_v2<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    msg: &NonNativeTarget<Secp256K1Scalar>,
    sig: &ECDSASignatureTarget<Secp256K1>,
    pk: &ECDSAPublicKeyTarget<Secp256K1>,
) {
    let ECDSASignatureTarget { r, s } = sig;

    builder.curve_assert_valid(&pk.0);

    let c = builder.inv_nonnative(&s);
    let u1 = builder.mul_nonnative(&msg, &c);
    let u2 = builder.mul_nonnative(&r, &c);

    let point1 = fixed_base_curve_mul_circuit(builder, Secp256K1::GENERATOR_AFFINE, &u1);
    let point2 = builder.glv_mul(&pk.0, &u2);
    let point = builder.curve_add(&point1, &point2);

    let x_value = builder.nonnative_to_canonical_biguint(&point.x);

    let x: NonNativeTarget<Secp256K1Scalar> = builder.biguint_to_nonnative(&x_value);
    builder.connect_nonnative(&r, &x);
}
pub struct Secp256K1CircuitGadget {
    pub msg_biguint_target: BigUintTarget,
    pub public_key_x_target: BigUintTarget,
    pub public_key_y_target: BigUintTarget,
    pub signature_r_target: BigUintTarget,
    pub signature_s_target: BigUintTarget,
    pub combined_hash: HashOutTarget,
}

impl Secp256K1CircuitGadget {
    /* see
     */
    pub fn add_virtual_to<F: RichField + Extendable<D>, const D: usize, H: AlgebraicHasher<F>>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        type CURVE = Secp256K1;
        let msg_target = builder.add_virtual_nonnative_target::<Secp256K1Scalar>();
        let public_key_target =
            ECDSAPublicKeyTarget::<CURVE>(builder.add_virtual_affine_point_target::<CURVE>());
        let r = builder.add_virtual_nonnative_target::<Secp256K1Scalar>();
        let s = builder.add_virtual_nonnative_target::<Secp256K1Scalar>();
        let signature_r_target = builder.nonnative_to_canonical_biguint(&r);
        let signature_s_target = builder.nonnative_to_canonical_biguint(&s);

        let signature_target = ECDSASignatureTarget::<Secp256K1> { r: r, s: s };

        let bigint_msg_target = builder.nonnative_to_canonical_biguint(&msg_target);
        let public_key_x_target = builder.nonnative_to_canonical_biguint(&public_key_target.0.x);
        let public_key_y_target = builder.nonnative_to_canonical_biguint(&public_key_target.0.y);

        let msg_data_targets = bigint_msg_target
            .limbs
            .iter()
            .map(|x| x.0)
            .collect::<Vec<_>>();
        let public_key_x_data_targets = public_key_x_target
            .limbs
            .iter()
            .map(|x| x.0)
            .collect::<Vec<_>>();
        let public_key_y_data_targets = public_key_y_target
            .limbs
            .iter()
            .map(|x| x.0)
            .collect::<Vec<_>>();
        let pub_key_hash = builder.hash_n_to_hash_no_pad::<H>(
            [public_key_x_data_targets, public_key_y_data_targets].concat(),
        );
        let msg_data_hash = builder.hash_n_to_hash_no_pad::<H>(msg_data_targets);
        let combined_hash = builder
            .hash_n_to_hash_no_pad::<H>([pub_key_hash.elements, msg_data_hash.elements].concat());
        verify_message_circuit_v2::<F, D>(
            builder,
            &msg_target,
            &signature_target,
            &public_key_target,
        );
        Self {
            msg_biguint_target: bigint_msg_target,
            public_key_x_target,
            public_key_y_target,
            signature_r_target,
            signature_s_target,
            combined_hash,
        }
    }

    pub fn set_witness_public_keys_update<F: RichField>(
        &self,
        witness: &mut impl Witness<F>,
        public_key: &ECDSAPublicKey<Secp256K1>,
        signature: &ECDSASignature<Secp256K1>,
        msg: &Secp256K1Scalar,
    ) {
        witness.set_biguint_target(&self.msg_biguint_target, &biguint_from_array(msg.0));
        witness.set_biguint_target(
            &self.public_key_x_target,
            &biguint_from_array(public_key.0.x.0),
        );
        witness.set_biguint_target(
            &self.public_key_y_target,
            &biguint_from_array(public_key.0.y.0),
        );
        witness.set_biguint_target(&self.signature_r_target, &biguint_from_array(signature.r.0));
        witness.set_biguint_target(&self.signature_s_target, &biguint_from_array(signature.s.0));
    }
}

#[derive(Debug, Clone, Copy)]
pub struct DogeQEDSignatureCombinedHashGadget {
    pub compressed_public_key: [Target; 9],
    pub message_hash: HashOutTarget,
    pub combined_hash: HashOutTarget,
}
impl DogeQEDSignatureCombinedHashGadget {
    pub fn add_virtual_to<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let compressed_public_key = builder.add_virtual_target_arr();
        let message_hash = builder.add_virtual_hash();
        Self::add_virtual_to_known::<H, F, D>(builder, compressed_public_key, message_hash)
    }

    pub fn add_virtual_to_known<
        H: AlgebraicHasher<F>,
        F: RichField + Extendable<D>,
        const D: usize,
    >(
        builder: &mut CircuitBuilder<F, D>,
        compressed_public_key: [Target; 9],
        message_hash: HashOutTarget,
    ) -> Self {
        let hash_public_key = builder.hash_n_to_hash_no_pad::<H>(compressed_public_key.to_vec());
        let combined_hash = builder
            .hash_n_to_hash_no_pad::<H>([hash_public_key.elements, message_hash.elements].concat());

        Self {
            compressed_public_key,
            message_hash,
            combined_hash,
        }
    }

    pub fn set_witness<F: RichField>(
        &self,
        witness: &mut impl Witness<F>,
        public_key: &[F; 9],
        message_hash: HashOut<F>,
    ) {
        witness.set_hash_target(self.message_hash, message_hash);
        witness.set_target_arr(&self.compressed_public_key, public_key);
    }

    pub fn set_witness_bytes<F: RichField>(
        &self,
        witness: &mut impl Witness<F>,
        public_key: &[u8; 33],
        message_hash: HashOut<F>,
    ) {
        let public_key_felts = bytes33_to_public_key(public_key);
        self.set_witness(witness, &public_key_felts, message_hash);
    }
}

#[derive(Debug, Clone)]
pub struct DogeQEDSignatureGadget {
    pub msg_hash_target: HashOutTarget,
    pub msg_biguint_target: BigUintTarget,
    pub public_key_x_target: BigUintTarget,
    pub public_key_y_target: BigUintTarget,
    pub signature_r_target: BigUintTarget,
    pub signature_s_target: BigUintTarget,
    pub combined_hash: HashOutTarget,
}

impl DogeQEDSignatureGadget {
    pub fn add_virtual_to<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        type CURVE = Secp256K1;
        let msg_hash_target = builder.add_virtual_hash();
        let msg_biguint_target = BigUintTarget {
            limbs: builder.hashout_to_hash256_le(msg_hash_target).to_vec(),
        };
        let msg_target = NonNativeTarget {
            value: msg_biguint_target,
            _phantom: PhantomData::default(),
        };

        let public_key_target =
            ECDSAPublicKeyTarget::<CURVE>(builder.add_virtual_affine_point_target::<CURVE>());
        let r = builder.add_virtual_nonnative_target::<Secp256K1Scalar>();
        let s = builder.add_virtual_nonnative_target::<Secp256K1Scalar>();
        let signature_r_target = builder.nonnative_to_canonical_biguint(&r);
        let signature_s_target = builder.nonnative_to_canonical_biguint(&s);

        let signature_target = ECDSASignatureTarget::<Secp256K1> { r: r, s: s };

        let bigint_msg_target = builder.nonnative_to_canonical_biguint(&msg_target);
        let public_key_x_target = builder.nonnative_to_canonical_biguint(&public_key_target.0.x);
        let public_key_y_target = builder.nonnative_to_canonical_biguint(&public_key_target.0.y);
        /*
        let msg_data_targets = bigint_msg_target
            .limbs
            .iter()
            .map(|x| x.0)
            .collect::<Vec<_>>();*/
        let public_key_x_data_targets = public_key_x_target
            .limbs
            .iter()
            .map(|x| x.0)
            .collect::<Vec<_>>();
        let public_key_y_data_targets = public_key_y_target
            .limbs
            .iter()
            .map(|x| x.0)
            .collect::<Vec<_>>();

        verify_message_circuit_v2::<F, D>(
            builder,
            &msg_target,
            &signature_target,
            &public_key_target,
        );

        let y_low_32_bits = builder.split_le(public_key_y_data_targets[0], 32);
        let y_parity = y_low_32_bits[0];
        let two_target = builder.constant(F::from_canonical_u64(2));

        // a compressed public key is a 33 byte array, where the first byte is the parity of the y coordinate
        // if y is even then the parity byte is 0x02.
        // if y is odd, the the parity byte is 0x03
        let parity_byte = builder.add(two_target, y_parity.target);
        let compressed_public_key = core::array::from_fn(|i| {
            if i == 0 {
                parity_byte
            } else {
                public_key_x_data_targets[i - 1]
            }
        });

        let combo_gadget = DogeQEDSignatureCombinedHashGadget::add_virtual_to_known::<H, F, D>(
            builder,
            compressed_public_key,
            msg_hash_target,
        );
        /*
        let pub_key_hash = builder
            .hash_n_to_hash_no_pad::<H>([vec![parity_byte], public_key_x_data_targets].concat());

        let combined_hash = builder
            .hash_n_to_hash_no_pad::<H>([pub_key_hash.elements, msg_hash_target.elements].concat());*/

        Self {
            msg_hash_target,
            msg_biguint_target: bigint_msg_target,
            public_key_x_target,
            public_key_y_target,
            signature_r_target,
            signature_s_target,
            combined_hash: combo_gadget.combined_hash,
        }
    }

    pub fn set_witness_public_keys_update<F: RichField>(
        &self,
        witness: &mut impl Witness<F>,
        public_key: &ECDSAPublicKey<Secp256K1>,
        signature: &ECDSASignature<Secp256K1>,
        msg: HashOut<F>,
    ) {
        witness.set_hash_target(self.msg_hash_target, msg);
        witness.set_biguint_target(
            &self.public_key_x_target,
            &biguint_from_array(public_key.0.x.0),
        );
        witness.set_biguint_target(
            &self.public_key_y_target,
            &biguint_from_array(public_key.0.y.0),
        );
        witness.set_biguint_target(&self.signature_r_target, &biguint_from_array(signature.r.0));
        witness.set_biguint_target(&self.signature_s_target, &biguint_from_array(signature.s.0));
    }
}

#[cfg(test)]
mod tests {

    use anyhow::Result;
    use city_crypto::signature::secp256k1::curve::curve_types::{Curve, CurveScalar};
    use city_crypto::signature::secp256k1::curve::ecdsa::{
        sign_message, ECDSAPublicKey, ECDSASecretKey, ECDSASignature,
    };
    use city_crypto::signature::secp256k1::curve::secp256k1::Secp256K1;
    use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
    use plonky2::field::types::Sample;
    use plonky2::hash::poseidon::PoseidonHash;
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

    use crate::crypto::secp256k1::ecdsa::gadgets::curve::CircuitBuilderCurve;
    use crate::crypto::secp256k1::ecdsa::gadgets::ecdsa::{
        verify_message_circuit, ECDSAPublicKeyTarget, ECDSASignatureTarget,
    };
    use crate::crypto::secp256k1::ecdsa::gadgets::nonnative::CircuitBuilderNonNative;
    use crate::crypto::secp256k1::gadget::Secp256K1CircuitGadget;

    fn test_ecdsa_circuit_with_config(config: CircuitConfig) -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        type Curve = Secp256K1;

        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let msg = Secp256K1Scalar::rand();
        let msg_target = builder.constant_nonnative(msg);

        let sk = ECDSASecretKey::<Curve>(Secp256K1Scalar::rand());
        let pk = ECDSAPublicKey((CurveScalar(sk.0) * Curve::GENERATOR_PROJECTIVE).to_affine());

        let pk_target = ECDSAPublicKeyTarget(builder.constant_affine_point(pk.0));

        let sig = sign_message(msg, sk);

        let ECDSASignature { r, s } = sig;
        let r_target = builder.constant_nonnative(r);
        let s_target = builder.constant_nonnative(s);
        let sig_target = ECDSASignatureTarget {
            r: r_target,
            s: s_target,
        };

        verify_message_circuit(&mut builder, msg_target, sig_target, pk_target);

        dbg!(builder.num_gates());
        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        data.verify(proof)
    }

    fn test_ecdsa_circuit_with_config_v2(config: CircuitConfig) -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        type Curve = Secp256K1;

        let mut builder = CircuitBuilder::<F, D>::new(config);
        let sig_gadget = Secp256K1CircuitGadget::add_virtual_to::<F, D, PoseidonHash>(&mut builder);
        builder.register_public_inputs(&sig_gadget.combined_hash.elements);
        let data = builder.build::<C>();

        let mut pw = PartialWitness::new();
        let msg = Secp256K1Scalar::rand();

        let sk = ECDSASecretKey::<Curve>(Secp256K1Scalar::rand());
        let pk = ECDSAPublicKey((CurveScalar(sk.0) * Curve::GENERATOR_PROJECTIVE).to_affine());

        let sig = sign_message(msg, sk);
        sig_gadget.set_witness_public_keys_update(&mut pw, &pk, &sig, &msg);
        let proof = data.prove(pw).unwrap();
        data.verify(proof)
    }

    #[test]
    #[ignore]
    fn test_ecdsa_circuit_narrow() -> Result<()> {
        test_ecdsa_circuit_with_config(CircuitConfig::standard_ecc_config())
    }

    #[test]
    #[ignore]
    fn test_ecdsa_circuit_narrow_v2() -> Result<()> {
        test_ecdsa_circuit_with_config_v2(CircuitConfig::standard_ecc_config())
    }

    #[test]
    #[ignore]
    fn test_ecdsa_circuit_wide() -> Result<()> {
        test_ecdsa_circuit_with_config(CircuitConfig::wide_ecc_config())
    }
}
