//! Test suite for the Nodejs.

extern crate wasm_bindgen_test;
use tpke_wasm::*;
use wasm_bindgen_test::*;

#[test]
#[wasm_bindgen_test]
fn encrypts_and_decrypts() {
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
