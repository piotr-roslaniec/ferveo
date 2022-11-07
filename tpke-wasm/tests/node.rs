//! Test suite for the Nodejs.

extern crate wasm_bindgen_test;
use tpke_wasm::*;
use wasm_bindgen_test::*;

#[test]
#[wasm_bindgen_test]
fn symmetric_encryption() {
    let threshold = 3;
    let shares_num = 5;
    let num_entities = 5;
    let message = "my-secret-message".as_bytes().to_vec();

    let setup_result = setup(threshold, shares_num, num_entities);
    let public_key = setup_result.public_key().to_vec();
    let private_key = setup_result.private_key().to_vec();

    let ciphertext = encrypt(message.clone(), public_key);
    let plaintext = decrypt(ciphertext, private_key);

    // TODO: Plaintext is padded to 32 bytes. Fix this.
    assert!(message == plaintext[..message.len()])
}

#[test]
#[wasm_bindgen_test]
fn threshold_encryption() {
    let threshold = 16 * 2 / 3;
    let shares_num = 16;
    let num_entities = 5;
    let message = "my-secret-message".as_bytes().to_vec();

    let setup_result = setup(threshold, shares_num, num_entities);
    let public_key = setup_result.public_key().to_vec();
    let private_key = setup_result.private_key().to_vec();

    let mut shares: Vec<DecryptionShare<E>> = vec![];
    for context in contexts.iter() {
        shares.push(context.create_share(&ciphertext));
    }
    let prepared_blinded_key_shares = contexts[0].prepare_combine(&shares);
    let s = contexts[0].share_combine(&shares, &prepared_blinded_key_shares);

    let plaintext = decrypt_with_shared_secret(&ciphertext, &s);
    assert!(plaintext == msg)
}
