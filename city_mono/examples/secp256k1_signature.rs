use std::marker::PhantomData;

use plonky2::{
    field::{
        extension::Extendable,
        secp256k1_scalar::Secp256K1Scalar,
        types::{PrimeField, Sample},
    },
    hash::hash_types::{HashOutTarget, RichField},
    iop::{target::Target, witness::PartialWitness},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::CircuitConfig,
        config::{GenericConfig, PoseidonGoldilocksConfig},
    },
};
use city_mono::{
    common::{
        generic::HashableTarget,
        secp256k1::ecdsa::{
            curve::{
                curve_types::{Curve, CurveScalar},
                ecdsa::{sign_message, ECDSAPublicKey, ECDSASecretKey, ECDSASignature},
                secp256k1::Secp256K1,
            },
            gadgets::{
                curve::CircuitBuilderCurve,
                curve_fixed_base::fixed_base_curve_mul_circuit,
                ecdsa::{ECDSAPublicKeyTarget, ECDSASignatureTarget},
                glv::CircuitBuilderGlv,
                nonnative::{CircuitBuilderNonNative, NonNativeTarget},
            },
        },
    },
    debug::circuit_tracer::DebugCircuitTracer,
    logging::debug_timer::DebugTimer,
};
use serde::{Deserialize, Serialize};
const QED_REGTEST_SIG_MAGIC: u64 = 0x1337CF514544FF69u64;
const QED_SIG_TYPE_DEPOSIT: u64 = 0x5449534F504544FFu64;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Secp256K1SignatureInfo {
    pk_value: ECDSAPublicKey<Secp256K1>,
    sig_value: ECDSASignature<Secp256K1>,
    msg_value: Secp256K1Scalar,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Secp256K1SignatureInfoWithPrivateKey {
    signature_info: Secp256K1SignatureInfo,
    private_key: ECDSASecretKey<Secp256K1>,
}

impl Secp256K1SignatureInfoWithPrivateKey {
    pub fn rand() -> Self {
        let msg_value = Secp256K1Scalar::rand();
        let sk_value = ECDSASecretKey::<Secp256K1>(Secp256K1Scalar::rand());
        let pk_value = ECDSAPublicKey::<Secp256K1>(
            (CurveScalar(sk_value.0) * Curve::GENERATOR_PROJECTIVE).to_affine(),
        );
        let sig_value = sign_message(msg_value, sk_value);
        Self {
            signature_info: Secp256K1SignatureInfo {
                pk_value,
                sig_value,
                msg_value,
            },
            private_key: sk_value,
        }
    }
    pub fn print(&self) {
        println!(
            "private_key: {}",
            self.private_key.0.to_canonical_biguint().to_string()
        );
        println!(
            "public_key_x: {}",
            self.signature_info
                .pk_value
                .0
                .x
                .to_canonical_biguint()
                .to_string()
        );
        println!(
            "public_key_y: {}",
            self.signature_info
                .pk_value
                .0
                .y
                .to_canonical_biguint()
                .to_string()
        );

        println!(
            "sig_r: {}",
            self.signature_info
                .sig_value
                .r
                .to_canonical_biguint()
                .to_string()
        );
        println!(
            "sig_s: {}",
            self.signature_info
                .sig_value
                .r
                .to_canonical_biguint()
                .to_string()
        );
        println!(
            "msg: {}",
            self.signature_info
                .msg_value
                .to_canonical_biguint()
                .to_string()
        );
    }
    pub fn sign(private_key: ECDSASecretKey<Secp256K1>, msg: Secp256K1Scalar) -> Self {
        let pk_value = ECDSAPublicKey::<Secp256K1>(
            (CurveScalar(private_key.0) * Curve::GENERATOR_PROJECTIVE).to_affine(),
        );
        let sig_value = sign_message(msg, private_key);
        Self {
            signature_info: Secp256K1SignatureInfo {
                pk_value,
                sig_value,
                msg_value: msg,
            },
            private_key,
        }
    }
}
fn prove_signature(
    pk_value: &ECDSAPublicKey<Secp256K1>,
    sig_value: &ECDSASignature<Secp256K1>,
    msg_value: &Secp256K1Scalar,
) {
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
    let mut tb = DebugCircuitTracer::new();
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
    tb.trace_vec("pk_target_x", &pk_target_x_dec);
    tb.trace_vec("pk_target_y", &pk_target_y_dec);
    tb.trace_vec("msg_target", &msg_target_dec);
    tb.trace_vec("r_target", &r_target_dec);
    tb.trace_vec("s_target", &s_target_dec);

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

    let targets_to_constants = builder.get_targets_to_constants_map();
    let data = builder.build::<C>();

    timer.lap("finish build");

    timer.lap("start prove");

    let pw = PartialWitness::new();

    let result = tb.resolve_u64(&pw, targets_to_constants);

    println!("result:\n{}", serde_json::to_string(&result).unwrap());

    // finish proof
    //let proof = data.prove(pw).unwrap();
    //data.verify(proof).unwrap();
    timer.lap("finish prove");
}

fn print_random() {
    let key = Secp256K1SignatureInfoWithPrivateKey::rand();
    key.print();
    prove_signature(
        &key.signature_info.pk_value,
        &key.signature_info.sig_value,
        &key.signature_info.msg_value,
    );
}

fn main() {
    print_random();
}
