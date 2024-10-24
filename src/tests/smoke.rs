// Copyright © Aptos Foundation

use crate::tests::common::get_test_circuit_config;
use crate::tests::common::{
    convert_prove_and_verify,
    types::{ProofTestCase, TestJWTPayload},
};
use serial_test::serial;
use rust_rapidsnark::FullProver;
use crate::load_vk::prepared_vk;
use crate::handlers::encode_proof;

#[tokio::test]
#[serial]
async fn default_request() {
    let testcase = ProofTestCase::default_with_payload(TestJWTPayload::default())
        .compute_nonce(&get_test_circuit_config());

    convert_prove_and_verify(&testcase).await.unwrap();
}

#[tokio::test]
#[serial]
async fn request_with_email() {
    let jwt_payload = TestJWTPayload {
        ..TestJWTPayload::default()
    };

    let testcase = ProofTestCase {
        uid_key: String::from("email"),
        ..ProofTestCase::default_with_payload(jwt_payload)
    }
    .compute_nonce(&get_test_circuit_config());
    convert_prove_and_verify(&testcase).await.unwrap();
}

#[tokio::test]
#[serial]
async fn request_with_no_extra_field() {
    let jwt_payload = TestJWTPayload {
        ..TestJWTPayload::default()
    };

    let testcase = ProofTestCase {
        extra_field: None,
        ..ProofTestCase::default_with_payload(jwt_payload)
    }
    .compute_nonce(&get_test_circuit_config());
    convert_prove_and_verify(&testcase).await.unwrap();
}

#[tokio::test]
#[serial]
async fn request_with_aud_recovery() {
    let jwt_payload = TestJWTPayload {
        ..TestJWTPayload::default()
    };

    let testcase = ProofTestCase {
        idc_aud: Some(String::from("original")),
        ..ProofTestCase::default_with_payload(jwt_payload)
    }
    .compute_nonce(&get_test_circuit_config());
    convert_prove_and_verify(&testcase).await.unwrap();
}

#[tokio::test]
#[serial]
#[should_panic]
async fn request_sub_is_required_in_jwt() {
    let jwt_payload = TestJWTPayload {
        sub: None,
        ..TestJWTPayload::default()
    };

    let testcase = ProofTestCase {
        uid_key: String::from("email"),
        ..ProofTestCase::default_with_payload(jwt_payload)
    }
    .compute_nonce(&get_test_circuit_config());
    convert_prove_and_verify(&testcase).await.unwrap();
}

#[tokio::test]
#[serial]
async fn request_with_sub() {
    let jwt_payload = TestJWTPayload {
        email: None,
        ..TestJWTPayload::default()
    };

    let testcase = ProofTestCase {
        uid_key: String::from("sub"),
        ..ProofTestCase::default_with_payload(jwt_payload)
    }
    .compute_nonce(&get_test_circuit_config());
    convert_prove_and_verify(&testcase).await.unwrap();
}

#[tokio::test]
#[serial]
async fn request_with_sub_no_email_verified() {
    let jwt_payload = TestJWTPayload {
        email: None,
        email_verified: None,
        ..TestJWTPayload::default()
    };

    let testcase = ProofTestCase {
        uid_key: String::from("sub"),
        ..ProofTestCase::default_with_payload(jwt_payload)
    }
    .compute_nonce(&get_test_circuit_config());
    convert_prove_and_verify(&testcase).await.unwrap();
}

#[tokio::test]
#[serial]
#[should_panic]
async fn request_with_wrong_uid_key() {
    let jwt_payload = TestJWTPayload {
        email: None,
        ..TestJWTPayload::default()
    };

    let testcase = ProofTestCase {
        uid_key: String::from("email"),
        ..ProofTestCase::default_with_payload(jwt_payload)
    }
    .compute_nonce(&get_test_circuit_config());

    convert_prove_and_verify(&testcase).await.unwrap();
}

#[tokio::test]
#[serial]
#[should_panic]
async fn request_with_invalid_exp_date() {
    let jwt_payload = TestJWTPayload {
        ..TestJWTPayload::default()
    };

    let testcase = ProofTestCase {
        epk_expiry_horizon_secs: 100,
        epk_expiry_time_secs: 200,
        ..ProofTestCase::default_with_payload(jwt_payload)
    }
    .compute_nonce(&get_test_circuit_config());

    convert_prove_and_verify(&testcase).await.unwrap();
}

#[tokio::test]
#[serial]
async fn request_jwt_exp_field_does_not_matter() {
    let jwt_payload = TestJWTPayload {
        exp: 234342342428348284,
        ..TestJWTPayload::default()
    };

    let testcase = ProofTestCase {
        ..ProofTestCase::default_with_payload(jwt_payload)
    }
    .compute_nonce(&get_test_circuit_config());

    convert_prove_and_verify(&testcase).await.unwrap();
}

#[tokio::test]
#[serial]
#[should_panic]
async fn request_with_incorrect_nonce() {
    let jwt_payload = TestJWTPayload {
        nonce: String::from(""),
        ..TestJWTPayload::default()
    };

    let testcase = ProofTestCase {
        uid_key: String::from("email"),
        ..ProofTestCase::default_with_payload(jwt_payload)
    };
    convert_prove_and_verify(&testcase).await.unwrap();
}

#[tokio::test]
#[serial]
#[ignore]
async fn request_all_sub_lengths() {
    // to catch the "capacity overflow" bug (fixed). Disabled right now because it takes a long
    // time to finish.
    for i in 0..65 {
        let jwt_payload = TestJWTPayload {
            sub: Some("a".repeat(i)),
            ..TestJWTPayload::default()
        };

        let testcase = ProofTestCase::default_with_payload(jwt_payload)
            .compute_nonce(&get_test_circuit_config());

        convert_prove_and_verify(&testcase).await.unwrap();
    }
}

#[test]
fn dummy_circuit_load_test() {
    let prover = FullProver::new("./resources/toy_circuit/toy_1.zkey").unwrap();

    for _i in 0..1000 {
        let (proof_json, _) = prover.prove("./resources/toy_circuit/toy.wtns").unwrap();

        let proof = encode_proof(
            &serde_json::from_str(proof_json).unwrap()
        ).unwrap();
        let g16vk = prepared_vk("./resources/toy_circuit/toy_vk.json");
        proof.verify_proof(2.into(), &g16vk).unwrap();
    }
}
