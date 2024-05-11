use core::marker::PhantomData;

use city_crypto::signature::secp256k1::curve::curve_types::Curve;
use city_crypto::signature::secp256k1::curve::secp256k1::Secp256K1;
use plonky2::field::extension::Extendable;
use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use super::super::gadgets::curve::AffinePointTarget;
use super::super::gadgets::curve::CircuitBuilderCurve;
use super::super::gadgets::curve_fixed_base::fixed_base_curve_mul_circuit;
use super::super::gadgets::glv::CircuitBuilderGlv;
use super::super::gadgets::nonnative::CircuitBuilderNonNative;
use super::super::gadgets::nonnative::NonNativeTarget;

#[derive(Clone, Debug)]
pub struct ECDSASecretKeyTarget<C: Curve>(pub NonNativeTarget<C::ScalarField>);

#[derive(Clone, Debug)]
pub struct ECDSAPublicKeyTarget<C: Curve>(pub AffinePointTarget<C>);

#[derive(Clone, Debug)]
pub struct ECDSASignatureTarget<C: Curve> {
    pub r: NonNativeTarget<C::ScalarField>,
    pub s: NonNativeTarget<C::ScalarField>,
}

pub fn verify_message_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    msg_target: NonNativeTarget<Secp256K1Scalar>,
    sig_target: ECDSASignatureTarget<Secp256K1>,
    pk_target: ECDSAPublicKeyTarget<Secp256K1>,
) {
    let r_target = sig_target.r;
    let s_target = sig_target.s;

    builder.curve_assert_valid(&pk_target.0);

    let c_target = builder.inv_nonnative(&s_target);
    let u1_target = builder.mul_nonnative(&msg_target, &c_target);
    let u2_target = builder.mul_nonnative(&r_target, &c_target);

    let point1_target =
        fixed_base_curve_mul_circuit(builder, Secp256K1::GENERATOR_AFFINE, &u1_target);
    let point2_target = builder.glv_mul(&pk_target.0, &u2_target);
    let point_target = builder.curve_add(&point1_target, &point2_target);

    let x_target = NonNativeTarget::<Secp256K1Scalar> {
        value: point_target.x.value,
        _phantom: PhantomData,
    };
    builder.connect_nonnative(&r_target, &x_target);
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use city_common::logging::debug_timer::DebugTimer;
    use city_crypto::signature::secp256k1::curve::curve_types::CurveScalar;
    use city_crypto::signature::secp256k1::curve::ecdsa::sign_message;
    use city_crypto::signature::secp256k1::curve::ecdsa::ECDSAPublicKey;
    use city_crypto::signature::secp256k1::curve::ecdsa::ECDSASecretKey;
    use city_crypto::signature::secp256k1::curve::ecdsa::ECDSASignature;
    use plonky2::field::types::PrimeField64;
    use plonky2::field::types::Sample;
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::GenericConfig;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    use serde::Deserialize;
    use serde::Serialize;

    use super::*;

    fn test_ecdsa_circuit_with_config(config: CircuitConfig) -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        type Curve = Secp256K1;

        let mut timer = DebugTimer::new("test_ecdsa_circuit_with_config");
        timer.lap("start");

        let msg_value = Secp256K1Scalar::rand();
        let sk_value = ECDSASecretKey::<Curve>(Secp256K1Scalar::rand());
        let pk_value =
            ECDSAPublicKey((CurveScalar(sk_value.0) * Curve::GENERATOR_PROJECTIVE).to_affine());
        let sig_value = sign_message(msg_value, sk_value);
        let r_value = sig_value.r;
        let s_value = sig_value.s;

        // start circuit

        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let msg_target = builder.constant_nonnative(msg_value);

        let pk_target = ECDSAPublicKeyTarget(builder.constant_affine_point(pk_value.0));
        let r_target = builder.constant_nonnative(r_value);
        let s_target = builder.constant_nonnative(s_value);
        let sig_target = ECDSASignatureTarget {
            r: r_target,
            s: s_target,
        };

        verify_message_circuit(&mut builder, msg_target, sig_target, pk_target);

        dbg!(builder.num_gates());
        timer.lap("start build");
        let data = builder.build::<C>();
        timer.lap("finish build");
        timer.lap("start prove");
        let proof = data.prove(pw).unwrap();

        timer.lap("finish prove");
        data.verify(proof)
    }

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct SimpleStructField<T> {
        pub name: String,
        pub value: Vec<T>,
    }
    struct SimpleStructBuilder {
        pub sizes: Vec<usize>,
        pub labels: Vec<String>,
    }

    impl SimpleStructBuilder {
        pub fn new() -> Self {
            SimpleStructBuilder {
                sizes: Vec::new(),
                labels: Vec::new(),
            }
        }
        pub fn add_field(&mut self, name: &str, size: usize) {
            self.sizes.push(size);
            self.labels.push(name.to_string());
        }
        /*
        pub fn add_field_string(&mut self, name: String, size: usize) {
            self.sizes.push(size);
            self.labels.push(name);
        }*/
        pub fn generate<T: Clone>(&self, value: Vec<T>) -> Vec<SimpleStructField<T>> {
            let mut result = Vec::new();
            let mut start = 0;
            for i in 0..self.sizes.len() {
                let end = start + self.sizes[i];
                result.push(SimpleStructField {
                    name: self.labels[i].clone(),
                    value: value[start..end].to_vec(),
                });
                start = end;
            }
            result
        }
    }

    fn print_all(
        pk_value: &ECDSAPublicKey<Secp256K1>,
        sig_value: &ECDSASignature<Secp256K1>,
        msg_value: &Secp256K1Scalar,
    ) -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let mut timer = DebugTimer::new("test_ecdsa_circuit_with_config");
        timer.lap("start");

        let r_value = sig_value.r;
        let s_value = sig_value.s;

        // start circuit

        let config = CircuitConfig::standard_ecc_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // start inputs
        let pk_target = ECDSAPublicKeyTarget(builder.constant_affine_point(pk_value.0));
        let msg_target = builder.constant_nonnative(*msg_value);
        let r_target = builder.constant_nonnative(r_value);
        let s_target = builder.constant_nonnative(s_value);
        // end inputs

        // start struct builder
        let mut sb = SimpleStructBuilder::new();
        let pk_target_x_dec = pk_target
            .0
            .x
            .value
            .limbs
            .iter()
            .map(|x| x.0)
            .collect::<Vec<_>>();
        let pk_target_y_dec = pk_target
            .0
            .y
            .value
            .limbs
            .iter()
            .map(|x| x.0)
            .collect::<Vec<_>>();
        let msg_target_dec = msg_target
            .value
            .limbs
            .iter()
            .map(|x| x.0)
            .collect::<Vec<_>>();
        let r_target_dec = msg_target
            .value
            .limbs
            .iter()
            .map(|x| x.0)
            .collect::<Vec<_>>();
        let s_target_dec = msg_target
            .value
            .limbs
            .iter()
            .map(|x| x.0)
            .collect::<Vec<_>>();
        // start register fields
        sb.add_field("pk_target_x", pk_target_x_dec.len());
        builder.register_public_inputs(&pk_target_x_dec);

        sb.add_field("pk_target_y", pk_target_y_dec.len());
        builder.register_public_inputs(&pk_target_y_dec);

        sb.add_field("msg_target", msg_target_dec.len());
        builder.register_public_inputs(&msg_target_dec);

        sb.add_field("r_target", r_target_dec.len());
        builder.register_public_inputs(&r_target_dec);

        sb.add_field("s_target", s_target_dec.len());
        builder.register_public_inputs(&s_target_dec);

        // end register fields

        // end struct builder

        let sig_target = ECDSASignatureTarget::<Secp256K1> {
            r: r_target,
            s: s_target,
        };

        let r_target = sig_target.r;
        let s_target = sig_target.s;

        builder.curve_assert_valid(&pk_target.0);

        let c_target = builder.inv_nonnative(&s_target);
        let u1_target = builder.mul_nonnative(&msg_target, &c_target);
        let u2_target = builder.mul_nonnative(&r_target, &c_target);

        let point1_target =
            fixed_base_curve_mul_circuit(&mut builder, Secp256K1::GENERATOR_AFFINE, &u1_target);
        let point2_target = builder.glv_mul(&pk_target.0, &u2_target);
        let point_target = builder.curve_add(&point1_target, &point2_target);

        let x_target = NonNativeTarget::<Secp256K1Scalar> {
            value: point_target.x.value,
            _phantom: PhantomData,
        };
        builder.connect_nonnative(&r_target, &x_target);

        dbg!(builder.num_gates());
        timer.lap("start build");
        let data = builder.build::<C>();
        timer.lap("finish build");
        timer.lap("start prove");
        let pw = PartialWitness::new();
        let proof = data.prove(pw).unwrap();
        let pubs = proof
            .public_inputs
            .to_vec()
            .iter()
            .map(|x| x.to_canonical_u64())
            .collect::<Vec<u64>>();
        let result = sb.generate::<u64>(pubs);
        println!("result:\n{}", serde_json::to_string(&result).unwrap());

        timer.lap("finish prove");
        data.verify(proof)
    }

    #[test]
    #[ignore]
    fn test_random_sig_print() {
        let msg_value = Secp256K1Scalar::rand();
        let sk_value = ECDSASecretKey::<Secp256K1>(Secp256K1Scalar::rand());
        let pk_value = ECDSAPublicKey::<Secp256K1>(
            (CurveScalar(sk_value.0) * Curve::GENERATOR_PROJECTIVE).to_affine(),
        );
        println!("priv_key: {}", serde_json::to_string(&sk_value).unwrap());
        println!("pub_key: {}", serde_json::to_string(&pk_value).unwrap());
        println!("msg: {}", serde_json::to_string(&msg_value).unwrap());
        let sig_value = sign_message(msg_value, sk_value);
        print_all(&pk_value, &sig_value, &msg_value).unwrap();
    }

    #[test]
    #[ignore]
    fn test_ecdsa_circuit_narrow() -> Result<()> {
        test_ecdsa_circuit_with_config(CircuitConfig::standard_ecc_config())
    }

    #[test]
    #[ignore]
    fn test_ecdsa_circuit_wide() -> Result<()> {
        test_ecdsa_circuit_with_config(CircuitConfig::wide_ecc_config())
    }
}
