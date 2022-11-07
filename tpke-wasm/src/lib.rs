mod utils;

extern crate group_threshold_cryptography as tpke;

use ark_ff::{FromBytes, ToBytes};
use serde::{Deserialize, Serialize};
use utils::set_panic_hook;
use wasm_bindgen::prelude::*;

extern crate alloc;
// Use `wee_alloc` as the global allocator.
extern crate wee_alloc;

type E = ark_bls12_381::Bls12_381;
type PublicKey = ark_bls12_381::G1Affine;
type PrivateKey = ark_bls12_381::G2Affine;
type Ciphertext = tpke::Ciphertext<E>;

#[wasm_bindgen]
pub struct SetupResult {
    public_key: Box<[u8]>,
    private_key: Box<[u8]>,
    private_contexts: Vec<Box<[u8]>>,
}

#[wasm_bindgen]
impl SetupResult {
    // wasm_bindgen requires public fields to implement the `Clone` trait.
    // Instead, we provide getters.
    #[wasm_bindgen(getter, js_name = "publicKey")]
    pub fn public_key(&self) -> Box<[u8]> {
        self.public_key.clone()
    }

    #[wasm_bindgen(getter, js_name = "privateKey")]
    pub fn private_key(&self) -> Box<[u8]> {
        self.private_key.clone()
    }
}

#[wasm_bindgen]
pub fn setup(
    threshold: usize,
    shares_num: usize,
    num_entities: usize,
) -> SetupResult {
    set_panic_hook();

    let (public_key, private_key, private_contexts) =
        tpke::setup::<E>(threshold, shares_num, num_entities);
    let mut public_key_bytes = Vec::new();
    public_key.write(&mut public_key_bytes).unwrap();
    let mut private_key_bytes = Vec::new();
    private_key.write(&mut private_key_bytes).unwrap();

    let private_contexts_vec = private_contexts
        .iter()
        .map(|context| {
            let mut bytes = Vec::new();
            context.write(&mut bytes).unwrap();
            bytes.into_boxed_slice()
        })
        .collect::<Vec<_>>();

    SetupResult {
        public_key: public_key_bytes.into_boxed_slice(),
        private_key: private_key_bytes.into_boxed_slice(),
        private_contexts,
    }
}

// #[wasm_bindgen]
// pub fn create_shares(
//     private_contexts: Vec<u8>,
//     ciphertext: Vec<u8>,
// ) -> Vec<Box<[u8]>> {
//     set_panic_hook();

//     let ciphertext = Ciphertext::read(ciphertext.as_slice()).unwrap();

//     let mut shares: Vec<tpke::DecryptionShare<E>> = vec![];
//     for context in private_contexts.iter() {
//         shares.push(context.create_share(&ciphertext));
//     }
//     private_contexts
//         .iter()
//         .map(|private_context| {
//             let share = private_context.create_share(&ciphertext);
//             let share_bytes = Vec::new();
//             share.write(&mut share_bytes).unwrap();
//             share_bytes.into_boxed_slice()
//         })
//         .collect()
// }

#[wasm_bindgen]
pub fn encrypt(message: Vec<u8>, pubkey: Vec<u8>) -> Vec<u8> {
    set_panic_hook();

    let mut rng = rand::thread_rng();
    let pubkey: PublicKey = PublicKey::read(&pubkey[..]).unwrap();
    tpke::encrypt::<_, E>(&message, pubkey, &mut rng).to_bytes()
}

#[wasm_bindgen]
pub fn decrypt(ciphertext: Vec<u8>, privkey: Vec<u8>) -> Vec<u8> {
    set_panic_hook();

    let privkey: PrivateKey = PrivateKey::read(&privkey[..]).unwrap();
    let ciphertext: Ciphertext = Ciphertext::from_bytes(&ciphertext[..]);
    tpke::decrypt(&ciphertext, privkey)
}
