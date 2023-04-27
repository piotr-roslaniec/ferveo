extern crate group_threshold_cryptography as tpke;

mod utils;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ferveo::EthereumAddress;
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use tpke::api::E;
use utils::*;
use wasm_bindgen::prelude::*;

extern crate wee_alloc;

type Result<T> = std::result::Result<T, js_sys::Error>;

fn unwrap_messages_js(
    messages: JsValue,
) -> Result<Vec<(ferveo::api::Validator<E>, ferveo::api::Transcript<E>)>> {
    let messages: Vec<ValidatorMessage> =
        serde_wasm_bindgen::from_value(messages).map_err(map_js_err)?;
    let messages = messages
        .iter()
        .map(|m| m.to_inner())
        .collect::<Result<Vec<_>>>()?;
    Ok(messages)
}

#[wasm_bindgen]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecryptionShareSimple(tpke::api::DecryptionShareSimple);

#[wasm_bindgen]
impl DecryptionShareSimple {
    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        to_js_bytes(&self.0)
    }

    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(bytes: &[u8]) -> Result<DecryptionShareSimple> {
        from_js_bytes(bytes).map(Self)
    }
}

#[wasm_bindgen]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecryptionSharePrecomputed(tpke::api::DecryptionSharePrecomputed);

#[wasm_bindgen]
impl DecryptionSharePrecomputed {
    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        to_js_bytes(&self.0)
    }

    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(bytes: &[u8]) -> Result<DecryptionSharePrecomputed> {
        from_js_bytes(bytes).map(Self)
    }
}

#[wasm_bindgen]
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct PublicKey(pub(crate) ferveo::api::PublicKey<E>);

#[wasm_bindgen]
impl PublicKey {
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(bytes: &[u8]) -> Result<PublicKey> {
        ferveo::api::PublicKey::from_bytes(bytes)
            .map_err(map_js_err)
            .map(Self)
    }

    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.0.to_bytes().map_err(map_js_err)
    }
}

#[serde_as]
#[wasm_bindgen]
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct PrivateKey(
    #[serde_as(as = "ferveo_common::serialization::SerdeAs")]
    pub(crate)  tpke::api::PrivateKey,
);

#[wasm_bindgen]
impl PrivateKey {
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(bytes: &[u8]) -> Result<PrivateKey> {
        let mut reader = bytes;
        let pk = tpke::api::PrivateKey::deserialize_compressed(&mut reader)
            .map_err(map_js_err)?;
        Ok(PrivateKey(pk))
    }

    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        self.0
            .serialize_compressed(&mut bytes)
            .map_err(map_js_err)?;
        Ok(bytes)
    }
}

#[wasm_bindgen]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ciphertext(tpke::api::Ciphertext);

#[wasm_bindgen]
impl Ciphertext {
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(bytes: &[u8]) -> Result<Ciphertext> {
        from_js_bytes(bytes).map(Self)
    }

    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        to_js_bytes(&self.0)
    }
}

#[wasm_bindgen]
pub fn encrypt(
    message: &[u8],
    aad: &[u8],
    dkg_public_key: &DkgPublicKey,
) -> Result<Ciphertext> {
    set_panic_hook();
    let rng = &mut thread_rng();
    let ciphertext =
        tpke::api::encrypt(message, aad, &dkg_public_key.0 .0, rng)
            .map_err(map_js_err)?;
    Ok(Ciphertext(ciphertext))
}

#[wasm_bindgen]
pub struct DkgPublicParameters(ferveo::api::DkgPublicParameters);

#[wasm_bindgen]
impl DkgPublicParameters {
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(bytes: &[u8]) -> Result<DkgPublicParameters> {
        from_js_bytes(bytes).map(Self)
    }

    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        to_js_bytes(&self.0)
    }
}

#[wasm_bindgen]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SharedSecret(tpke::api::SharedSecret);

#[wasm_bindgen]
impl SharedSecret {
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(bytes: &[u8]) -> Result<SharedSecret> {
        from_js_bytes(bytes).map(Self)
    }

    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        to_js_bytes(&self.0)
    }
}

#[wasm_bindgen(js_name = "combineDecryptionSharesSimple")]
pub fn combine_decryption_shares_simple(
    decryption_shares_js: JsValue,
    dkg_public_params: &DkgPublicParameters,
) -> Result<SharedSecret> {
    let shares: Vec<DecryptionShareSimple> =
        serde_wasm_bindgen::from_value(decryption_shares_js)
            .map_err(map_js_err)?;
    let shares = shares
        .iter()
        .map(|share| share.0.clone())
        .collect::<Vec<_>>();
    let domain_points = &dkg_public_params.0.domain_points;
    let lagrange_coefficients =
        ferveo::api::prepare_combine_simple::<E>(&domain_points[..]);
    let shared_secret = ferveo::api::share_combine_simple(
        &shares[..],
        &lagrange_coefficients[..],
    );
    Ok(SharedSecret(ferveo::api::SharedSecret(shared_secret)))
}

#[wasm_bindgen(js_name = "combineDecryptionSharesPrecomputed")]
pub fn combine_decryption_shares_precomputed(
    decryption_shares_js: JsValue,
) -> Result<SharedSecret> {
    let shares: Vec<DecryptionSharePrecomputed> =
        serde_wasm_bindgen::from_value(decryption_shares_js)
            .map_err(map_js_err)?;
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
) -> Result<Vec<u8>> {
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
    pub fn from_bytes(bytes: &[u8]) -> Result<DkgPublicKey> {
        from_js_bytes(bytes).map(Self)
    }

    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        to_js_bytes(&self.0)
    }
}

#[wasm_bindgen]
pub struct Dkg(ferveo::api::Dkg);

#[wasm_bindgen]
impl Dkg {
    #[wasm_bindgen(constructor)]
    pub fn new(
        tau: u64,
        shares_num: u32,
        security_threshold: u32,
        validators: JsValue, // Vec<Validator>
        me: &Validator,
    ) -> Result<Dkg> {
        let validators: Vec<Validator> =
            serde_wasm_bindgen::from_value(validators).map_err(map_js_err)?;
        let validators = validators
            .into_iter()
            .map(|v| v.to_inner())
            .collect::<Result<Vec<_>>>()?;
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

    pub fn final_key(&self) -> DkgPublicKey {
        DkgPublicKey(self.0.final_key())
    }

    pub fn generate_transcript(&self) -> Result<Transcript> {
        let rng = &mut thread_rng();
        let transcript = self.0.generate_transcript(rng).map_err(map_js_err)?;
        Ok(Transcript(transcript))
    }

    pub fn aggregate_transcripts(
        &mut self,
        messages: JsValue, // Vec<ValidatorMessage>
    ) -> Result<AggregatedTranscript> {
        let messages = unwrap_messages_js(messages)?;
        let aggregated_transcript = self
            .0
            .aggregate_transcripts(&messages)
            .map_err(map_js_err)?;
        Ok(AggregatedTranscript(aggregated_transcript))
    }

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
    pub fn from_bytes(bytes: &[u8]) -> Result<Transcript> {
        from_js_bytes(bytes).map(Self)
    }

    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        to_js_bytes(&self.0)
    }
}

// Using a separate Validator struct for WASM bindings to avoid issues with serialization of
// `ark_ec::models::bls12::Bls12<ark_bls12_381::curves::Config>`, i.e. G2Affine public key
#[wasm_bindgen]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Validator {
    address: EthereumAddress,
    public_key: Vec<u8>,
}

impl Validator {
    pub fn new(
        address: EthereumAddress,
        public_key: PublicKey,
    ) -> Result<Self> {
        Ok(Self {
            address,
            public_key: public_key.to_bytes()?,
        })
    }

    pub(crate) fn to_inner(&self) -> Result<ferveo::api::Validator<E>> {
        Ok(ferveo::api::Validator {
            address: self.address.clone(),
            public_key: ferveo::api::PublicKey::from_bytes(&self.public_key)
                .map_err(map_js_err)?,
        })
    }
}

#[wasm_bindgen]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorMessage(Validator, Transcript);

#[wasm_bindgen]
impl ValidatorMessage {
    #[wasm_bindgen(constructor)]
    pub fn new(
        validator: Validator,
        transcript: Transcript,
    ) -> Result<ValidatorMessage> {
        Ok(Self(validator, transcript))
    }

    pub(crate) fn to_inner(
        &self,
    ) -> Result<(ferveo::api::Validator<E>, ferveo::api::Transcript<E>)> {
        Ok((self.0.to_inner()?, self.1 .0.clone()))
    }
}

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct AggregatedTranscript(pub(crate) ferveo::api::AggregatedTranscript);

#[wasm_bindgen]
impl AggregatedTranscript {
    #[wasm_bindgen(constructor)]
    pub fn new(messages: JsValue) -> Result<AggregatedTranscript> {
        let messages = unwrap_messages_js(messages)?;
        let aggregated_transcript =
            ferveo::api::AggregatedTranscript::new(&messages);
        Ok(AggregatedTranscript(aggregated_transcript))
    }

    #[wasm_bindgen]
    pub fn verify(self, shares_num: usize, messages: JsValue) -> Result<bool> {
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
    ) -> Result<DecryptionSharePrecomputed> {
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
    ) -> Result<DecryptionShareSimple> {
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
    pub fn from_bytes(bytes: &[u8]) -> Result<AggregatedTranscript> {
        from_js_bytes(bytes).map(Self)
    }

    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        to_js_bytes(&self.0)
    }
}

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct Keypair(ferveo::api::Keypair<E>);

#[wasm_bindgen]
impl Keypair {
    #[wasm_bindgen]
    pub fn random() -> Self {
        Self(ferveo::api::Keypair::new(&mut thread_rng()))
    }

    #[wasm_bindgen(js_name = "fromSecureRandomness")]
    pub fn from_secure_randomness(bytes: &[u8]) -> Result<Keypair> {
        let keypair = ferveo::api::Keypair::<E>::from_secure_randomness(bytes)
            .map_err(map_js_err)?;
        Ok(Self(keypair))
    }

    #[wasm_bindgen(js_name = "secureRandomnessSize")]
    pub fn secure_randomness_size() -> usize {
        ferveo::api::Keypair::<E>::secure_randomness_size()
    }

    #[wasm_bindgen(js_name = "publicKey")]
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.public())
    }

    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        to_js_bytes(&self.0)
    }

    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(bytes: &[u8]) -> Result<Keypair> {
        from_js_bytes(bytes).map(Self)
    }
}

/// Factory functions for testing
pub mod test_common {
    use std::str::FromStr;

    use crate::*;

    pub fn gen_keypair(i: usize) -> Keypair {
        Keypair::from_secure_randomness(&[i as u8; 32]).unwrap()
    }

    pub fn gen_validator(i: usize, keypair: &Keypair) -> Validator {
        Validator {
            address: EthereumAddress::from_str(&format!("0x{:040}", i))
                .unwrap(),
            public_key: keypair.public_key().to_bytes().unwrap(),
        }
    }
}
