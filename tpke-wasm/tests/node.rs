//! Test suite for the Nodejs.

extern crate group_threshold_cryptography as tpke;
extern crate wasm_bindgen_test;

use tpke_wasm::test_common::*;
use tpke_wasm::*;
use wasm_bindgen_test::*;

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
    let ciphertext = encrypt(&msg, &aad, &dkg_pk);

    // Serialize and send to validators
    let ciphertext_bytes = ciphertext.to_bytes();

    //
    // On the server side
    //

    let ciphertext2 = Ciphertext::from_bytes(&ciphertext_bytes);
    assert_eq!(ciphertext, ciphertext2);

    // Create decryption shares

    // Note that in this variant, if we use less than `share_num` shares, we will get a
    // decryption error.

    let decryption_shares = (0..shares_num)
        .map(|i| dkg.make_decryption_share(&ciphertext, &aad, i))
        .collect::<Vec<DecryptionShare>>();

    // Serialize and send back to client
    let decryption_shares_bytes = decryption_shares
        .iter()
        .map(|s| s.to_bytes())
        .collect::<Vec<Vec<u8>>>();

    //
    // On the client side
    //

    let decryption_shares_2: Vec<DecryptionShare> = decryption_shares_bytes
        .iter()
        .map(|s| DecryptionShare::from_bytes(s))
        .collect();
    assert_eq!(decryption_shares, decryption_shares_2);

    // Combine shares into a shared secret
    let mut ss_builder = SharedSecretBuilder::new(threshold);
    for share in decryption_shares {
        ss_builder.add_decryption_share(&share);
    }
    let shared_secret = ss_builder.build();

    // Decrypt the message
    let plaintext =
        decrypt_with_shared_secret(&ciphertext, &aad, &shared_secret);

    assert_eq!(msg, plaintext)
}

#[test]
#[wasm_bindgen_test]
fn encrypts_and_decrypts() {
    let shares_num = 16;
    let threshold = shares_num * 2 / 3;
    let message = "my-secret-message".as_bytes().to_vec();
    let aad = "my-aad".as_bytes().to_vec();

    let setup = Dkg::new(threshold, shares_num);

    let ciphertext = encrypt(&message, &aad, &setup.public_key);
    let plaintext =
        decrypt_with_private_key(&ciphertext, &aad, &setup.private_key);

    // TODO: Plaintext is padded to 32 bytes. Fix this.
    assert_eq!(message, plaintext[..message.len()])
}
