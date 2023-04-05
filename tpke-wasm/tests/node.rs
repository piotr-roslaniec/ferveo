//! Test suite for the Nodejs.

extern crate group_threshold_cryptography as tpke;
extern crate wasm_bindgen_test;

use tpke_wasm::{test_common::*, *};
use wasm_bindgen_test::*;

#[test]
#[wasm_bindgen_test]
fn tdec_simple() {
    let shares_num = 16;
    let threshold = shares_num * 2 / 3;
    let msg = "my-msg".as_bytes().to_vec();
    let aad = "my-aad".as_bytes().to_vec();

    let dkg = Dkg::new(threshold, shares_num);

    //
    // On the client side
    //

    // Encrypt the message
    let ciphertext = encrypt(&msg, &aad, &dkg.public_key).unwrap();

    // Serialize and send to validators
    let ciphertext_bytes = ciphertext.to_bytes().unwrap();

    //
    // On the server side
    //

    let ciphertext2 = Ciphertext::from_bytes(&ciphertext_bytes).unwrap();
    assert_eq!(ciphertext, ciphertext2);

    // Create decryption shares

    let decryption_shares = (0..threshold)
        .map(|i| {
            dkg.make_decryption_share_simple(&ciphertext, &aad, i)
                .unwrap()
        })
        .collect::<Vec<DecryptionShareSimple>>();

    let domain_points = (0..threshold)
        .map(|i| dkg.get_domain_point(i))
        .collect::<Vec<DomainPoint>>();

    // Serialize and send back to client
    let decryption_shares_bytes = decryption_shares
        .iter()
        .map(|s| s.to_bytes().unwrap())
        .collect::<Vec<Vec<u8>>>();

    //
    // On the client side
    //

    let decryption_shares_2: Vec<DecryptionShareSimple> =
        decryption_shares_bytes
            .iter()
            .map(|s| DecryptionShareSimple::from_bytes(s).unwrap())
            .collect();
    assert_eq!(decryption_shares, decryption_shares_2);

    // Combine shares into a shared secret
    let mut ss_builder = SharedSecretSimpleBuilder::new(threshold);
    for share in decryption_shares {
        ss_builder.add_decryption_share(&share);
    }
    for domain_point in domain_points {
        ss_builder.add_domain_point(&domain_point);
    }
    let shared_secret = ss_builder.build();

    // Decrypt the message
    let plaintext = decrypt_with_shared_secret(
        &ciphertext,
        &aad,
        &shared_secret,
        &dkg.g_inv(),
    )
    .unwrap();

    assert_eq!(msg, plaintext)
}

#[test]
#[wasm_bindgen_test]
fn tdec_simple_precomputed() {
    let shares_num = 16;
    let threshold = shares_num * 2 / 3;
    let msg = "abc".as_bytes().to_vec();
    let aad = "my-aad".as_bytes().to_vec();

    let dkg = Dkg::new(threshold, shares_num);
    let dkg_pk = dkg.public_key;

    //
    // On the client side
    //

    // Encrypt the message
    let ciphertext = encrypt(&msg, &aad, &dkg_pk).unwrap();

    // Serialize and send to validators
    let ciphertext_bytes = ciphertext.to_bytes().unwrap();

    //
    // On the server side
    //

    let ciphertext2 = Ciphertext::from_bytes(&ciphertext_bytes).unwrap();
    assert_eq!(ciphertext, ciphertext2);

    // Create decryption shares

    // Note that in this variant, if we use less than `share_num` shares, we will get a
    // decryption error.

    let decryption_shares = (0..shares_num)
        .map(|i| {
            dkg.make_decryption_share_precomputed(&ciphertext, &aad, i)
                .unwrap()
        })
        .collect::<Vec<DecryptionShareSimplePrecomputed>>();

    // Serialize and send back to client
    let decryption_shares_bytes = decryption_shares
        .iter()
        .map(|s| s.to_bytes().unwrap())
        .collect::<Vec<Vec<u8>>>();

    //
    // On the client side
    //

    let decryption_shares_2: Vec<DecryptionShareSimplePrecomputed> =
        decryption_shares_bytes
            .iter()
            .map(|s| DecryptionShareSimplePrecomputed::from_bytes(s).unwrap())
            .collect();
    assert_eq!(decryption_shares, decryption_shares_2);

    // Combine shares into a shared secret
    let mut ss_builder = SharedSecretPrecomputedBuilder::new(threshold);
    for share in decryption_shares {
        ss_builder.add_decryption_share(&share);
    }
    let shared_secret = ss_builder.build();

    // Decrypt the message
    let plaintext = decrypt_with_shared_secret(
        &ciphertext,
        &aad,
        &shared_secret,
        &dkg.g_inv(),
    )
    .unwrap();

    assert_eq!(msg, plaintext)
}

#[test]
#[wasm_bindgen_test]
fn encrypts_and_decrypts() {
    let shares_num = 16;
    let threshold = shares_num * 2 / 3;
    let message = "my-secret-message".as_bytes().to_vec();
    let aad = "my-aad".as_bytes().to_vec();

    let dkg = Dkg::new(threshold, shares_num);

    let ciphertext = encrypt(&message, &aad, &dkg.public_key).unwrap();
    let plaintext = decrypt_with_private_key(
        &ciphertext,
        &aad,
        &dkg.private_key,
        &dkg.g_inv(),
    )
    .unwrap();

    // TODO: Plaintext is padded to 32 bytes. Fix this.
    assert_eq!(message, plaintext[..message.len()])
}
