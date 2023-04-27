//! Test suite for the Nodejs.

extern crate group_threshold_cryptography as tpke;
extern crate wasm_bindgen_test;

use ferveo_wasm::{test_common::*, *};
use itertools::zip_eq;
use wasm_bindgen::JsValue;
use wasm_bindgen_test::*;

#[wasm_bindgen_test]
fn tdec_simple() {
    let (
        tau,
        shares_num,
        security_threshold,
        validator_keypairs,
        validators,
        validators_js,
        dkg,
        messages_js,
        msg,
        aad,
        ciphertext,
    ) = setup_dkg();

    // Having aggregated the transcripts, the validators can now create decryption shares
    let decryption_shares = zip_eq(validators, validator_keypairs)
        .map(|(validator, keypair)| {
            let mut dkg = Dkg::new(
                tau,
                shares_num as u32,
                security_threshold as u32,
                validators_js.clone(),
                &validator,
            )
            .unwrap();
            let aggregate =
                dkg.aggregate_transcripts(messages_js.clone()).unwrap();
            let is_valid = aggregate
                .clone()
                .verify(shares_num, messages_js.clone())
                .unwrap();
            assert!(is_valid);

            aggregate
                .create_decryption_share_simple(
                    &dkg,
                    &ciphertext,
                    &aad,
                    &keypair,
                )
                .unwrap()
        })
        .collect::<Vec<DecryptionShareSimple>>();
    let decryption_shares_js =
        serde_wasm_bindgen::to_value(&decryption_shares).unwrap();

    // Now, the decryption share can be used to decrypt the ciphertext
    // This part is in the client API

    let shared_secret = combine_decryption_shares_simple(
        decryption_shares_js,
        &dkg.public_params(),
    )
    .unwrap();

    // The client should have access to the public parameters of the DKG
    let plaintext = decrypt_with_shared_secret(
        &ciphertext,
        &aad,
        &shared_secret,
        &dkg.public_params(),
    )
    .unwrap();
    assert_eq!(msg, plaintext);
}

#[wasm_bindgen_test]
fn tdec_precomputed() {
    let (
        tau,
        shares_num,
        security_threshold,
        validator_keypairs,
        validators,
        validators_js,
        dkg,
        messages_js,
        msg,
        aad,
        ciphertext,
    ) = setup_dkg();

    // Having aggregated the transcripts, the validators can now create decryption shares
    let decryption_shares = zip_eq(validators, validator_keypairs)
        .map(|(validator, keypair)| {
            let mut dkg = Dkg::new(
                tau,
                shares_num as u32,
                security_threshold as u32,
                validators_js.clone(),
                &validator,
            )
            .unwrap();
            let aggregate =
                dkg.aggregate_transcripts(messages_js.clone()).unwrap();
            let is_valid = aggregate
                .clone()
                .verify(shares_num, messages_js.clone())
                .unwrap();
            assert!(is_valid);

            aggregate
                .create_decryption_share_precomputed(
                    &dkg,
                    &ciphertext,
                    &aad,
                    &keypair,
                )
                .unwrap()
        })
        .collect::<Vec<DecryptionSharePrecomputed>>();
    let decryption_shares_js =
        serde_wasm_bindgen::to_value(&decryption_shares).unwrap();

    // Now, the decryption share can be used to decrypt the ciphertext
    // This part is in the client API

    let shared_secret =
        combine_decryption_shares_precomputed(decryption_shares_js).unwrap();

    // The client should have access to the public parameters of the DKG
    let plaintext = decrypt_with_shared_secret(
        &ciphertext,
        &aad,
        &shared_secret,
        &dkg.public_params(),
    )
    .unwrap();
    assert_eq!(msg, plaintext);
}

type TestSetup = (
    u32,
    usize,
    usize,
    Vec<Keypair>,
    Vec<Validator>,
    JsValue,
    Dkg,
    JsValue,
    Vec<u8>,
    Vec<u8>,
    Ciphertext,
);

fn setup_dkg() -> TestSetup {
    let tau = 1;
    let shares_num = 16;
    let security_threshold = shares_num * 2 / 3;

    let validator_keypairs =
        (0..shares_num).map(gen_keypair).collect::<Vec<Keypair>>();
    let validators = validator_keypairs
        .iter()
        .enumerate()
        .map(|(i, keypair)| gen_validator(i, keypair))
        .collect::<Vec<Validator>>();
    let validators_js = serde_wasm_bindgen::to_value(&validators).unwrap();

    // Each validator holds their own DKG instance and generates a transcript every
    // validator, including themselves
    let messages = validators.iter().map(|sender| {
        let dkg = Dkg::new(
            tau,
            shares_num as u32,
            security_threshold as u32,
            validators_js.clone(),
            sender,
        )
        .unwrap();
        let transcript = dkg.generate_transcript().unwrap();

        ValidatorMessage::new(sender.clone(), transcript).unwrap()
    });

    // Now that every validator holds a dkg instance and a transcript for every other validator,
    // every validator can aggregate the transcripts

    let mut dkg = Dkg::new(
        tau,
        shares_num as u32,
        security_threshold as u32,
        validators_js.clone(),
        &validators[0],
    )
    .unwrap();

    // Let's say that we've only received `security_threshold` transcripts
    let messages: Vec<_> =
        messages.into_iter().take(security_threshold).collect();
    let messages_js = serde_wasm_bindgen::to_value(&messages).unwrap();

    // Server can aggregate the transcripts and verify them
    let server_aggregate =
        dkg.aggregate_transcripts(messages_js.clone()).unwrap();
    let is_valid = server_aggregate
        .verify(shares_num, messages_js.clone())
        .unwrap();
    assert!(is_valid);

    // Client can also aggregate the transcripts and verify them
    let client_aggregate =
        AggregatedTranscript::new(messages_js.clone()).unwrap();
    let is_valid = client_aggregate
        .verify(shares_num, messages_js.clone())
        .unwrap();
    assert!(is_valid);

    // In the meantime, the client creates a ciphertext and decryption request
    let msg = "my-msg".as_bytes().to_vec();
    let aad = "my-aad".as_bytes().to_vec();
    let ciphertext = encrypt(&msg, &aad, &dkg.final_key()).unwrap();

    (
        tau,
        shares_num,
        security_threshold,
        validator_keypairs,
        validators,
        validators_js,
        dkg,
        messages_js,
        msg,
        aad,
        ciphertext,
    )
}
