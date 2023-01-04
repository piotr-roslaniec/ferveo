//! Test suite for the Nodejs.

extern crate wasm_bindgen_test;

use tpke_wasm::*;
use wasm_bindgen_test::*;

extern crate group_threshold_cryptography as tpke;

#[test]
#[wasm_bindgen_test]
pub fn participant_payload_serialization() {
    // Taking a shortcut here to generate a ciphertext
    // TODO: Build a ciphertext from scratch
    let threshold = 3;
    let shares_num = 5;
    let num_entities = 5;
    let message = "my-secret-message".as_bytes().to_vec();
    let aad = "my-aad".as_bytes().to_vec();
    let setup = Setup::new(threshold, shares_num, num_entities);
    let ciphertext = encrypt(&message, &aad, &setup.public_key);

    let participant_payload =
        ParticipantPayload::new(&setup.private_context_at(0), &ciphertext);
    let serialized = participant_payload.to_bytes();
    let deserialized: ParticipantPayload =
        ParticipantPayload::from_bytes(&serialized);

    assert_eq!(serialized, deserialized.to_bytes())
}

#[test]
#[wasm_bindgen_test]
fn encrypts_and_decrypts() {
    let threshold = 3;
    let shares_num = 5;
    let num_entities = 5;
    let message = "my-secret-message".as_bytes().to_vec();
    let aad = "my-aad".as_bytes().to_vec();

    let setup = Setup::new(threshold, shares_num, num_entities);

    let ciphertext = encrypt(&message, &aad, &setup.public_key);
    let plaintext = decrypt(&ciphertext, &setup.private_key);

    // TODO: Plaintext is padded to 32 bytes. Fix this.
    assert_eq!(message, plaintext[..message.len()])
}

#[test]
#[wasm_bindgen_test]
fn threshold_encryption() {
    let threshold = 16 * 2 / 3;
    let shares_num = 16;
    let num_entities = 5;
    let message = "my-secret-message".as_bytes().to_vec();
    let aad = "my-aad".as_bytes().to_vec();

    //
    // On the client side
    //

    // Initialize the DKG setup
    let setup = Setup::new(threshold, shares_num, num_entities);

    // Encrypt the message
    let ciphertext = encrypt(&message, &aad, &setup.public_key);

    // Craete and serialize participant payloads for transport
    let participant_payloads_bytes: Vec<Vec<u8>> = setup
        .decrypter_indexes()
        .iter()
        .map(|index| {
            ParticipantPayload::new(
                &setup.private_context_at(*index),
                &ciphertext,
            )
            .to_bytes()
        })
        .collect();

    // Now, deal the payloads to participants

    // ================================================

    //
    // On the participants side
    //

    // Deserialize from transport
    let participant_payloads: Vec<ParticipantPayload> =
        participant_payloads_bytes
            .iter()
            .map(|p| ParticipantPayload::from_bytes(p))
            .collect();

    // Create decryption shares
    let decryption_shares: Vec<DecryptionShare> = participant_payloads
        .iter()
        .map(|p| p.to_decryption_share())
        .collect();

    // Serialize for transport
    let decryption_shares_bytes: Vec<Vec<u8>> =
        decryption_shares.iter().map(|s| s.to_bytes()).collect();

    // Now, we send the shares back to the client

    // ================================================

    //
    // On the client side
    //

    // Deserialize from transport
    let decryption_shares: Vec<DecryptionShare> = decryption_shares_bytes
        .iter()
        .map(|s| DecryptionShare::from_bytes(s))
        .collect();

    // Combine shares into a shared secret
    let mut ss_builder = SharedSecretBuilder::new(&setup);
    for share in decryption_shares {
        ss_builder.add_decryption_share(&share);
    }
    let shared_secret = ss_builder.build();

    // Decrypt the message
    let plaintext = decrypt_with_shared_secret(&ciphertext, &shared_secret);
    assert_eq!(message, plaintext)
}
