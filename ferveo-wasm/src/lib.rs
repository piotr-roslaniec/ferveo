extern crate group_threshold_cryptography as tpke;

mod utils;

use std::str::FromStr;

use rand::thread_rng;
use serde::{Deserialize, Serialize};
use tpke::{api::E, SecretBox};
pub use utils::into_js_array;
use utils::*;
use wasm_bindgen::prelude::*;
use wasm_bindgen_derive::TryFromJsValue;

extern crate alloc;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "ValidatorMessage[]")]
    pub type ValidatorMessageArray;

    #[wasm_bindgen(typescript_type = "Validator[]")]
    pub type ValidatorArray;

    #[wasm_bindgen(typescript_type = "DecryptionShareSimple[]")]
    pub type DecryptionShareSimpleArray;

    #[wasm_bindgen(typescript_type = "DecryptionSharePrecomputed[]")]
    pub type DecryptionSharePrecomputedArray;
}

fn unwrap_messages_js(
    messages: &ValidatorMessageArray,
) -> JsResult<Vec<(ferveo::api::Validator<E>, ferveo::api::Transcript<E>)>> {
    let messages = try_from_js_array::<ValidatorMessage>(messages)?;
    let messages = messages
        .iter()
        .map(|m| m.to_inner())
        .collect::<JsResult<Vec<_>>>()?;
    Ok(messages)
}

#[derive(TryFromJsValue)]
#[wasm_bindgen]
#[derive(Clone, Debug, derive_more::AsRef, derive_more::From)]
pub struct DecryptionShareSimple(ferveo::api::DecryptionShareSimple);

#[wasm_bindgen]
impl DecryptionShareSimple {
    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> JsResult<Vec<u8>> {
        to_js_bytes(&self.0)
    }

    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(bytes: &[u8]) -> JsResult<DecryptionShareSimple> {
        from_js_bytes(bytes).map(Self)
    }
}

#[derive(TryFromJsValue)]
#[wasm_bindgen]
#[derive(Clone, Debug, derive_more::AsRef, derive_more::From)]
pub struct DecryptionSharePrecomputed(tpke::api::DecryptionSharePrecomputed);

#[wasm_bindgen]
impl DecryptionSharePrecomputed {
    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> JsResult<Vec<u8>> {
        to_js_bytes(&self.0)
    }

    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(bytes: &[u8]) -> JsResult<DecryptionSharePrecomputed> {
        from_js_bytes(bytes).map(Self)
    }
}

#[wasm_bindgen]
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct PublicKey(pub(crate) ferveo::api::PublicKey<E>);

#[wasm_bindgen]
impl PublicKey {
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(bytes: &[u8]) -> JsResult<PublicKey> {
        ferveo::api::PublicKey::from_bytes(bytes)
            .map_err(map_js_err)
            .map(Self)
    }

    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> JsResult<Box<[u8]>> {
        let bytes = self.0.to_bytes().map_err(map_js_err)?;
        let bytes: &[u8] = bytes.as_ref();
        Ok(bytes.into())
    }

    #[wasm_bindgen]
    pub fn equals(&self, other: &PublicKey) -> bool {
        self.0 == other.0
    }
}

#[wasm_bindgen]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ciphertext(tpke::api::Ciphertext);

#[wasm_bindgen]
impl Ciphertext {
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(bytes: &[u8]) -> JsResult<Ciphertext> {
        from_js_bytes(bytes).map(Self)
    }

    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> JsResult<Vec<u8>> {
        to_js_bytes(&self.0)
    }
}

#[wasm_bindgen]
pub fn encrypt(
    message: &[u8],
    aad: &[u8],
    dkg_public_key: &DkgPublicKey,
) -> JsResult<Ciphertext> {
    set_panic_hook();
    let rng = &mut thread_rng();
    let ciphertext = tpke::api::encrypt(
        SecretBox::new(message.to_vec()),
        aad,
        &dkg_public_key.0 .0,
        rng,
    )
    .map_err(map_js_err)?;
    Ok(Ciphertext(ciphertext))
}

#[wasm_bindgen]
pub struct DkgPublicParameters(ferveo::api::DkgPublicParameters);

#[wasm_bindgen]
impl DkgPublicParameters {
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(bytes: &[u8]) -> JsResult<DkgPublicParameters> {
        from_js_bytes(bytes).map(Self)
    }

    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> JsResult<Vec<u8>> {
        to_js_bytes(&self.0)
    }
}

#[wasm_bindgen]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SharedSecret(ferveo::api::SharedSecret);

#[wasm_bindgen]
impl SharedSecret {
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(bytes: &[u8]) -> JsResult<SharedSecret> {
        from_js_bytes(bytes).map(Self)
    }

    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> JsResult<Vec<u8>> {
        to_js_bytes(&self.0)
    }
}

#[wasm_bindgen(js_name = "combineDecryptionSharesSimple")]
pub fn combine_decryption_shares_simple(
    decryption_shares_js: &DecryptionShareSimpleArray,
) -> JsResult<SharedSecret> {
    let shares =
        try_from_js_array::<DecryptionShareSimple>(decryption_shares_js)?;
    let shares: Vec<_> = shares.iter().map(|share| share.0.clone()).collect();
    let shared_secret = ferveo::api::combine_shares_simple(&shares[..]);
    Ok(SharedSecret(shared_secret))
}

#[wasm_bindgen(js_name = "combineDecryptionSharesPrecomputed")]
pub fn combine_decryption_shares_precomputed(
    decryption_shares_js: &DecryptionSharePrecomputedArray,
) -> JsResult<SharedSecret> {
    let shares =
        try_from_js_array::<DecryptionSharePrecomputed>(decryption_shares_js)?;
    let shares = shares
        .iter()
        .map(|share| share.0.clone())
        .collect::<Vec<_>>();
    let shared_secret = ferveo::api::share_combine_precomputed(&shares[..]);
    Ok(SharedSecret(ferveo::api::SharedSecret(shared_secret)))
}

#[wasm_bindgen(js_name = "decryptWithSharedSecret")]
pub fn decrypt_with_shared_secret(
    ciphertext: &Ciphertext,
    aad: &[u8],
    shared_secret: &SharedSecret,
    dkg_public_params: &DkgPublicParameters,
) -> JsResult<Vec<u8>> {
    set_panic_hook();
    tpke::api::decrypt_with_shared_secret(
        &ciphertext.0,
        aad,
        &shared_secret.0 .0,
        &dkg_public_params.0.g1_inv,
    )
    .map_err(map_js_err)
}

#[wasm_bindgen]
pub struct DkgPublicKey(ferveo::api::DkgPublicKey);

#[wasm_bindgen]
impl DkgPublicKey {
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(bytes: &[u8]) -> JsResult<DkgPublicKey> {
        from_js_bytes(bytes).map(Self)
    }

    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> JsResult<Vec<u8>> {
        to_js_bytes(&self.0)
    }
}

#[wasm_bindgen]
pub struct Dkg(ferveo::api::Dkg);

#[wasm_bindgen]
impl Dkg {
    #[wasm_bindgen(constructor)]
    pub fn new(
        tau: u32,
        shares_num: u32,
        security_threshold: u32,
        validators_js: &ValidatorArray,
        me: &Validator,
    ) -> JsResult<Dkg> {
        let validators = try_from_js_array::<Validator>(validators_js)?;
        let validators = validators
            .into_iter()
            .map(|v| v.to_inner())
            .collect::<JsResult<Vec<_>>>()?;
        let dkg = ferveo::api::Dkg::new(
            tau,
            shares_num,
            security_threshold,
            &validators,
            &me.to_inner()?,
        )
        .map_err(map_js_err)?;
        Ok(Self(dkg))
    }

    #[wasm_bindgen(js_name = "publicKey")]
    pub fn public_key(&self) -> DkgPublicKey {
        DkgPublicKey(self.0.public_key())
    }

    #[wasm_bindgen(js_name = "generateTranscript")]
    pub fn generate_transcript(&self) -> JsResult<Transcript> {
        let rng = &mut thread_rng();
        let transcript = self.0.generate_transcript(rng).map_err(map_js_err)?;
        Ok(Transcript(transcript))
    }

    #[wasm_bindgen(js_name = "aggregateTranscript")]
    pub fn aggregate_transcripts(
        &mut self,
        messages_js: &ValidatorMessageArray,
    ) -> JsResult<AggregatedTranscript> {
        let messages = unwrap_messages_js(messages_js)?;
        let aggregated_transcript = self
            .0
            .aggregate_transcripts(&messages)
            .map_err(map_js_err)?;
        Ok(AggregatedTranscript(aggregated_transcript))
    }

    #[wasm_bindgen(js_name = "publicParams")]
    pub fn public_params(&self) -> DkgPublicParameters {
        DkgPublicParameters(self.0.public_params())
    }
}

#[wasm_bindgen]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Transcript(pub(crate) ferveo::api::Transcript<E>);

#[wasm_bindgen]
impl Transcript {
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(bytes: &[u8]) -> JsResult<Transcript> {
        from_js_bytes(bytes).map(Self)
    }

    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> JsResult<Vec<u8>> {
        to_js_bytes(&self.0)
    }
}

#[wasm_bindgen(js_name = EthereumAddress)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EthereumAddress(ferveo::api::EthereumAddress);

#[wasm_bindgen]
impl EthereumAddress {
    #[wasm_bindgen(js_name = "fromString")]
    pub fn from_string(address: &str) -> JsResult<EthereumAddress> {
        set_panic_hook();
        Ok(Self(
            ferveo::api::EthereumAddress::from_str(address)
                .map_err(map_js_err)?,
        ))
    }

    #[wasm_bindgen(js_name = "toString")]
    pub fn to_string(&self) -> JsResult<String> {
        set_panic_hook();
        Ok(self.0.to_string())
    }
}

// Using a separate Validator struct for WASM bindings to avoid issues with serialization of
// `ark_ec::models::bls12::Bls12<ark_bls12_381::curves::Config>`, i.e. G2Affine public key
#[derive(TryFromJsValue)]
#[wasm_bindgen]
#[derive(Clone, Debug, derive_more::AsRef, derive_more::From)]
pub struct Validator {
    address: EthereumAddress,
    public_key: PublicKey,
}

#[wasm_bindgen]
impl Validator {
    #[wasm_bindgen(constructor)]
    pub fn new(
        address: &EthereumAddress,
        public_key: &PublicKey,
    ) -> JsResult<Validator> {
        set_panic_hook();
        Ok(Self {
            address: address.clone(),
            public_key: *public_key,
        })
    }

    pub(crate) fn to_inner(&self) -> JsResult<ferveo::api::Validator<E>> {
        set_panic_hook();
        Ok(ferveo::api::Validator {
            address: self.address.0.clone(),
            public_key: self.public_key.0,
        })
    }

    #[wasm_bindgen(getter, js_name = "publicKey")]
    pub fn public_key(&self) -> PublicKey {
        self.public_key
    }

    #[wasm_bindgen(getter)]
    pub fn address(&self) -> EthereumAddress {
        self.address.clone()
    }
}

// TODO: Consider removing and replacing with tuple
#[derive(TryFromJsValue)]
#[wasm_bindgen]
#[derive(Clone, Debug, derive_more::AsRef, derive_more::From)]
pub struct ValidatorMessage(Validator, Transcript);

#[wasm_bindgen]
impl ValidatorMessage {
    #[wasm_bindgen(constructor)]
    pub fn new(
        validator: &Validator,
        transcript: &Transcript,
    ) -> JsResult<ValidatorMessage> {
        Ok(Self(validator.clone(), transcript.clone()))
    }

    pub(crate) fn to_inner(
        &self,
    ) -> JsResult<(ferveo::api::Validator<E>, ferveo::api::Transcript<E>)> {
        Ok((self.0.to_inner()?, self.1 .0.clone()))
    }

    #[wasm_bindgen(getter)]
    pub fn validator(&self) -> Validator {
        self.0.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn transcript(&self) -> Transcript {
        self.1.clone()
    }
}

#[wasm_bindgen]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AggregatedTranscript(ferveo::api::AggregatedTranscript);

#[wasm_bindgen]
impl AggregatedTranscript {
    #[wasm_bindgen(constructor)]
    pub fn new(
        messages: &ValidatorMessageArray,
    ) -> JsResult<AggregatedTranscript> {
        set_panic_hook();
        let messages = unwrap_messages_js(messages)?;
        let aggregated_transcript =
            ferveo::api::AggregatedTranscript::new(&messages);
        Ok(AggregatedTranscript(aggregated_transcript))
    }

    #[wasm_bindgen]
    pub fn verify(
        &self,
        shares_num: usize,
        messages: &ValidatorMessageArray,
    ) -> JsResult<bool> {
        set_panic_hook();
        let messages = unwrap_messages_js(messages)?;
        let is_valid = self
            .0
            .verify(shares_num as u32, &messages)
            .map_err(map_js_err)?;
        Ok(is_valid)
    }

    #[wasm_bindgen(js_name = "createDecryptionSharePrecomputed")]
    pub fn create_decryption_share_precomputed(
        &self,
        dkg: &Dkg,
        ciphertext: &Ciphertext,
        aad: &[u8],
        validator_keypair: &Keypair,
    ) -> JsResult<DecryptionSharePrecomputed> {
        set_panic_hook();
        let decryption_share = self
            .0
            .create_decryption_share_precomputed(
                &dkg.0,
                &ciphertext.0,
                aad,
                &validator_keypair.0,
            )
            .map_err(map_js_err)?;
        Ok(DecryptionSharePrecomputed(decryption_share))
    }

    #[wasm_bindgen(js_name = "createDecryptionShareSimple")]
    pub fn create_decryption_share_simple(
        &self,
        dkg: &Dkg,
        ciphertext: &Ciphertext,
        aad: &[u8],
        validator_keypair: &Keypair,
    ) -> JsResult<DecryptionShareSimple> {
        set_panic_hook();
        let decryption_share = self
            .0
            .create_decryption_share_simple(
                &dkg.0,
                &ciphertext.0,
                aad,
                &validator_keypair.0,
            )
            .map_err(map_js_err)?;
        Ok(DecryptionShareSimple(decryption_share))
    }

    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(bytes: &[u8]) -> JsResult<AggregatedTranscript> {
        from_js_bytes(bytes).map(Self)
    }

    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> JsResult<Vec<u8>> {
        to_js_bytes(&self.0)
    }
}

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct Keypair(ferveo::api::Keypair<E>);

#[wasm_bindgen]
impl Keypair {
    #[wasm_bindgen(getter, js_name = "secureRandomnessSize")]
    pub fn secure_randomness_size() -> usize {
        ferveo::api::Keypair::<E>::secure_randomness_size()
    }

    #[wasm_bindgen(getter, js_name = "publicKey")]
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.public())
    }

    #[wasm_bindgen]
    pub fn random() -> Self {
        Self(ferveo::api::Keypair::new(&mut thread_rng()))
    }

    #[wasm_bindgen(js_name = "fromSecureRandomness")]
    pub fn from_secure_randomness(bytes: &[u8]) -> JsResult<Keypair> {
        set_panic_hook();
        let keypair = ferveo::api::Keypair::<E>::from_secure_randomness(bytes)
            .map_err(map_js_err)?;
        Ok(Self(keypair))
    }

    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> JsResult<Vec<u8>> {
        to_js_bytes(&self.0)
    }

    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(bytes: &[u8]) -> JsResult<Keypair> {
        from_js_bytes(bytes).map(Self)
    }
}

/// Factory functions for testing
pub mod test_common {
    use crate::*;

    pub fn gen_keypair(i: usize) -> Keypair {
        Keypair::from_secure_randomness(&[i as u8; 32]).unwrap()
    }

    pub fn gen_address(i: usize) -> EthereumAddress {
        EthereumAddress::from_string(&format!("0x{:040}", i)).unwrap()
    }

    pub fn gen_validator(i: usize, keypair: &Keypair) -> Validator {
        Validator {
            address: gen_address(i),
            public_key: keypair.public_key(),
        }
    }
}
