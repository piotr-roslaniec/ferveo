mod utils;

extern crate group_threshold_cryptography as tpke;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use utils::set_panic_hook;
use wasm_bindgen::prelude::*;

extern crate wee_alloc;

pub type E = ark_bls12_381::Bls12_381;
pub type TpkePublicKey = ark_bls12_381::G1Affine;
pub type TpkePrivateKey = ark_bls12_381::G2Affine;
pub type TpkeCiphertext = tpke::Ciphertext<E>;
pub type TpkeDecryptionShare = tpke::DecryptionShare<E>;
pub type TpkePublicDecryptionContext = tpke::PublicDecryptionContext<E>;
pub type TpkeSharedSecret =
    <ark_bls12_381::Bls12_381 as ark_ec::PairingEngine>::Fqk;

#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct PrivateDecryptionContext(tpke::api::PrivateDecryptionContext);
#[wasm_bindgen]
impl PrivateDecryptionContext {
    pub(crate) fn serialized_size() -> usize {
        tpke::api::PrivateDecryptionContext::serialized_size()
    }

    #[wasm_bindgen]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    #[wasm_bindgen]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(tpke::api::PrivateDecryptionContext::from_bytes(bytes))
    }
}

#[wasm_bindgen]
#[derive(Clone, Debug)]
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

#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct ParticipantPayload(tpke::api::ParticipantPayload);

#[wasm_bindgen]
impl ParticipantPayload {
    #[wasm_bindgen(constructor)]
    pub fn new(
        decryption_context: &PrivateDecryptionContext,
        ciphertext: &Ciphertext,
    ) -> Self {
        Self(tpke::api::ParticipantPayload::new(
            &decryption_context.0,
            &ciphertext.ciphertext,
        ))
    }

    #[wasm_bindgen]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.0.decryption_context.to_bytes();
        bytes.extend(&self.0.ciphertext.to_bytes());
        bytes
    }

    #[wasm_bindgen]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let decryption_context_bytes =
            &bytes[0..PrivateDecryptionContext::serialized_size()];
        let decryption_context =
            PrivateDecryptionContext::from_bytes(decryption_context_bytes);

        let ciphertext_bytes =
            bytes[PrivateDecryptionContext::serialized_size()..].to_vec();
        let ciphertext = tpke::Ciphertext::from_bytes(&ciphertext_bytes);

        Self(tpke::api::ParticipantPayload {
            decryption_context: decryption_context.0,
            ciphertext,
        })
    }

    #[wasm_bindgen]
    pub fn to_decryption_share(&self) -> DecryptionShare {
        DecryptionShare(self.0.to_decryption_share())
    }
}

#[serde_as]
#[wasm_bindgen]
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct PublicKey(
    #[serde_as(as = "tpke::serialization::SerdeAs")] pub(crate) TpkePublicKey,
);

#[wasm_bindgen]
impl PublicKey {
    #[wasm_bindgen]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut reader = bytes;
        let pk = TpkePublicKey::deserialize_uncompressed(&mut reader).unwrap();
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
    #[serde_as(as = "tpke::serialization::SerdeAs")] pub(crate) TpkePrivateKey,
);

#[wasm_bindgen]
impl PrivateKey {
    #[wasm_bindgen]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut reader = bytes;
        let pk = TpkePrivateKey::deserialize_uncompressed(&mut reader).unwrap();
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
#[derive(Clone, Debug)]
pub struct Setup {
    pub public_key: PublicKey,
    pub private_key: PrivateKey,
    private_contexts: Vec<PrivateDecryptionContext>,
    public_contexts: Vec<TpkePublicDecryptionContext>,
}

#[wasm_bindgen]
impl Setup {
    #[wasm_bindgen(constructor)]
    pub fn new(
        threshold: usize,
        shares_num: usize,
        num_entities: usize,
    ) -> Self {
        set_panic_hook();

        let mut rng = rand::thread_rng();
        let (public_key, private_key, contexts) =
            tpke::setup::<E>(threshold, shares_num, num_entities, &mut rng);
        let private_contexts = contexts
            .clone()
            .into_iter()
            .map(|x| {
                PrivateDecryptionContext(
                    tpke::api::PrivateDecryptionContext::new(&x.b_inv, x.index),
                )
            })
            .collect();
        let public_contexts = contexts[0].public_decryption_contexts.to_vec();

        Self {
            public_key: PublicKey(public_key),
            private_key: PrivateKey(private_key),
            private_contexts,
            public_contexts,
        }
    }

    // Using `private_context_at` and `decrypter_indexes` instead of making `private_context` public
    // as a workaround for wasm-bindgen not supporting `Vec` with a custom defined types without serde
    // serialization.

    #[wasm_bindgen]
    pub fn private_context_at(&self, index: usize) -> PrivateDecryptionContext {
        set_panic_hook();
        let context = self.private_contexts[index].clone();
        assert_eq!(context.0.decrypter_index, index);
        context
    }

    #[wasm_bindgen]
    pub fn decrypter_indexes(&self) -> Vec<usize> {
        set_panic_hook();
        self.private_contexts
            .iter()
            .map(|x| x.0.decrypter_index)
            .collect()
    }

    // TODO: Add `decryptorShares` helper method
}

#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct Ciphertext {
    pub(crate) ciphertext: TpkeCiphertext,
    pub(crate) aad: Vec<u8>,
}

#[wasm_bindgen]
pub fn encrypt(
    message: &[u8],
    aad: &[u8],
    public_key: &PublicKey,
) -> Ciphertext {
    set_panic_hook();

    let mut rng = rand::thread_rng();
    let ciphertext =
        tpke::encrypt::<_, E>(message, aad, &public_key.0, &mut rng);
    Ciphertext {
        ciphertext,
        aad: aad.to_vec(),
    }
}

#[wasm_bindgen]
pub fn decrypt(ciphertext: &Ciphertext, private_key: &PrivateKey) -> Vec<u8> {
    set_panic_hook();

    tpke::checked_decrypt(
        &ciphertext.ciphertext,
        &ciphertext.aad,
        private_key.0,
    )
}

#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct SharedSecret(TpkeSharedSecret);

#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct SharedSecretBuilder {
    shares: Vec<TpkeDecryptionShare>,
    contexts: Vec<TpkePublicDecryptionContext>,
}

#[wasm_bindgen]
impl SharedSecretBuilder {
    #[wasm_bindgen(constructor)]
    pub fn new(setup: &Setup) -> Self {
        SharedSecretBuilder {
            shares: vec![],
            contexts: setup.public_contexts.clone(),
        }
    }

    #[wasm_bindgen]
    pub fn add_decryption_share(&mut self, share: &DecryptionShare) {
        self.shares.push(share.0 .0.clone());
    }

    #[wasm_bindgen]
    pub fn build(&self) -> SharedSecret {
        set_panic_hook();

        if self.shares.len() != self.contexts.len() {
            panic!("Number of shares and contexts must be equal");
        }

        let prepared_blinded_key_shares =
            tpke::prepare_combine(&self.contexts, &self.shares);
        let shared_secret =
            tpke::share_combine(&self.shares, &prepared_blinded_key_shares);
        SharedSecret(shared_secret)
    }
}

#[wasm_bindgen]
pub fn decrypt_with_shared_secret(
    ciphertext: &Ciphertext,
    shared_secret: &SharedSecret,
) -> Vec<u8> {
    set_panic_hook();

    tpke::checked_decrypt_with_shared_secret(
        &ciphertext.ciphertext,
        &ciphertext.aad,
        &shared_secret.0,
    )
}
