extern crate group_threshold_cryptography as tpke;

mod utils;

use utils::*;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use wasm_bindgen::prelude::*;

extern crate wee_alloc;

#[wasm_bindgen]
#[derive(Clone, Debug, PartialEq)]
pub struct DecryptionShare(tpke::api::DecryptionShare);

#[wasm_bindgen]
impl DecryptionShare {
    #[wasm_bindgen]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    #[wasm_bindgen]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let share = tpke::api::DecryptionShare::from_bytes(bytes);
        Self(share)
    }
}

#[serde_as]
#[wasm_bindgen]
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct PublicKey(
    #[serde_as(as = "tpke::serialization::SerdeAs")]
    pub(crate)  tpke::api::TpkeDkgPublicKey,
);

#[wasm_bindgen]
impl PublicKey {
    #[wasm_bindgen]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut reader = bytes;
        let pk =
            tpke::api::TpkeDkgPublicKey::deserialize_uncompressed(&mut reader)
                .unwrap();
        PublicKey(pk)
    }

    #[wasm_bindgen]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.0.serialize_uncompressed(&mut bytes).unwrap();
        bytes
    }
}

#[serde_as]
#[wasm_bindgen]
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct PrivateKey(
    #[serde_as(as = "tpke::serialization::SerdeAs")]
    pub(crate)  tpke::api::TpkePrivateKey,
);

#[wasm_bindgen]
impl PrivateKey {
    #[wasm_bindgen]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut reader = bytes;
        let pk =
            tpke::api::TpkePrivateKey::deserialize_uncompressed(&mut reader)
                .unwrap();
        PrivateKey(pk)
    }

    #[wasm_bindgen]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.0.serialize_uncompressed(&mut bytes).unwrap();
        bytes
    }
}

#[wasm_bindgen]
#[derive(Clone, Debug, PartialEq)]
pub struct Ciphertext(tpke::api::Ciphertext);

#[wasm_bindgen]
impl Ciphertext {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Ciphertext(tpke::api::Ciphertext::from_bytes(bytes))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }
}

#[wasm_bindgen]
pub fn encrypt(
    message: &[u8],
    aad: &[u8],
    public_key: &PublicKey,
) -> Ciphertext {
    set_panic_hook();
    Ciphertext(tpke::api::encrypt(message, aad, &public_key.0))
}

#[wasm_bindgen]
pub fn decrypt_with_private_key(
    ciphertext: &Ciphertext,
    aad: &[u8],
    private_key: &PrivateKey,
) -> Vec<u8> {
    set_panic_hook();

    tpke::api::decrypt_symmetric(&ciphertext.0, aad, private_key.0)
}

#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct SharedSecret(tpke::api::TpkeSharedSecret);

#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct SharedSecretBuilder {
    shares: Vec<tpke::api::TpkeDecryptionShare>,
    threshold: usize,
}

#[wasm_bindgen]
impl SharedSecretBuilder {
    #[wasm_bindgen(constructor)]
    pub fn new(threshold: usize) -> Self {
        SharedSecretBuilder {
            shares: vec![],
            threshold,
        }
    }

    #[wasm_bindgen]
    pub fn add_decryption_share(&mut self, share: &DecryptionShare) {
        self.shares.push(share.0 .0.clone());
    }

    #[wasm_bindgen]
    pub fn build(&self) -> SharedSecret {
        set_panic_hook();

        if self.shares.len() < self.threshold {
            panic!("Number of shares below threshold");
        }

        SharedSecret(tpke::share_combine_simple_precomputed(&self.shares))
    }
}

#[wasm_bindgen]
pub fn decrypt_with_shared_secret(
    ciphertext: &Ciphertext,
    aad: &[u8],
    shared_secret: &SharedSecret,
) -> Vec<u8> {
    set_panic_hook();

    tpke::api::decrypt_with_shared_secret(&ciphertext.0, aad, &shared_secret.0)
        .unwrap()
}

/// Factory functions for testing
#[cfg(any(test, feature = "test-common"))]
pub mod test_common {
    use super::*;

    #[wasm_bindgen]
    #[derive(Clone, Debug)]
    pub struct Dkg {
        pub public_key: PublicKey,
        pub private_key: PrivateKey,
        private_contexts: Vec<tpke::api::TpkePrivateDecryptionContext>,
    }

    #[wasm_bindgen]
    impl Dkg {
        #[wasm_bindgen(constructor)]
        pub fn new(threshold: usize, shares_num: usize) -> Self {
            set_panic_hook();

            let mut rng = rand::thread_rng();
            let (public_key, private_key, private_contexts) =
                tpke::test_common::setup_simple::<tpke::api::E>(
                    threshold, shares_num, &mut rng,
                );
            Self {
                public_key: PublicKey(public_key),
                private_key: PrivateKey(private_key),
                private_contexts,
            }
        }

        #[wasm_bindgen]
        pub fn make_decryption_share(
            &self,
            ciphertext: &Ciphertext,
            aad: &[u8],
            validator_index: usize,
        ) -> DecryptionShare {
            set_panic_hook();
            DecryptionShare(tpke::api::DecryptionShare(
                self.private_contexts[validator_index]
                    .create_share_precomputed(&ciphertext.0 .0, aad)
                    .unwrap(),
            ))
        }
    }
}
