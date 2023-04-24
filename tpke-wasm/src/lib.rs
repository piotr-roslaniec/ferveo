extern crate group_threshold_cryptography as tpke;

mod utils;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use js_sys::Error;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use utils::*;
use wasm_bindgen::prelude::*;

extern crate wee_alloc;

#[wasm_bindgen]
#[derive(Clone, Debug, PartialEq)]
pub struct G1Prepared(tpke::api::G1Prepared);

#[wasm_bindgen]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecryptionShareSimple(tpke::api::DecryptionShareSimple);

#[wasm_bindgen]
impl DecryptionShareSimple {
    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        to_js_bytes(&self.0)
    }

    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(bytes: &[u8]) -> Result<DecryptionShareSimple, Error> {
        from_js_bytes(bytes).map(Self)
    }
}

#[wasm_bindgen]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecryptionShareSimplePrecomputed(
    tpke::api::DecryptionSharePrecomputed,
);

#[wasm_bindgen]
impl DecryptionShareSimplePrecomputed {
    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        to_js_bytes(&self.0)
    }

    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(
        bytes: &[u8],
    ) -> Result<DecryptionShareSimplePrecomputed, Error> {
        from_js_bytes(bytes).map(Self)
    }
}

#[wasm_bindgen]
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct PublicKey(pub(crate) ferveo::api::DkgPublicKey);

#[wasm_bindgen]
impl PublicKey {
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(bytes: &[u8]) -> Result<PublicKey, Error> {
        ferveo::api::DkgPublicKey::from_bytes(bytes)
            .map_err(map_js_err)
            .map(Self)
    }

    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
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
    pub fn from_bytes(bytes: &[u8]) -> Result<PrivateKey, Error> {
        let mut reader = bytes;
        let pk = tpke::api::PrivateKey::deserialize_uncompressed(&mut reader)
            .map_err(map_js_err)?;
        Ok(PrivateKey(pk))
    }

    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut bytes = Vec::new();
        self.0
            .serialize_uncompressed(&mut bytes)
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
    pub fn from_bytes(bytes: &[u8]) -> Result<Ciphertext, Error> {
        from_js_bytes(bytes).map(Self)
    }

    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        to_js_bytes(&self.0)
    }
}

#[wasm_bindgen]
pub fn encrypt(
    message: &[u8],
    aad: &[u8],
    public_key: &PublicKey,
) -> Result<Ciphertext, Error> {
    set_panic_hook();
    let rng = &mut rand::thread_rng();
    let ciphertext = tpke::api::encrypt(message, aad, &public_key.0 .0, rng)
        .map_err(map_js_err)?;
    Ok(Ciphertext(ciphertext))
}

#[wasm_bindgen(js_name = "decryptWithPrivateKey")]
pub fn decrypt_with_private_key(
    ciphertext: &Ciphertext,
    aad: &[u8],
    private_key: &PrivateKey,
    g_inv: &G1Prepared,
) -> Result<Vec<u8>, Error> {
    set_panic_hook();
    tpke::api::decrypt_symmetric(&ciphertext.0, aad, &private_key.0, &g_inv.0)
        .map_err(map_js_err)
}

#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct DomainPoint(tpke::api::DomainPoint);

#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct SharedSecret(tpke::api::SharedSecret);

#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct SharedSecretPrecomputedBuilder {
    shares: Vec<tpke::api::DecryptionSharePrecomputed>,
    threshold: usize,
}

#[wasm_bindgen]
impl SharedSecretPrecomputedBuilder {
    #[wasm_bindgen(constructor)]
    pub fn new(threshold: usize) -> Self {
        Self {
            shares: vec![],
            threshold,
        }
    }

    #[wasm_bindgen(js_name = "addDecryptionShare")]
    pub fn add_decryption_share(
        &mut self,
        share: &DecryptionShareSimplePrecomputed,
    ) {
        self.shares.push(share.0.clone());
    }

    #[wasm_bindgen]
    pub fn build(&self) -> SharedSecret {
        set_panic_hook();
        if self.shares.len() < self.threshold {
            panic!("Number of shares below threshold");
        }
        let shared_secret = tpke::api::share_combine_precomputed(&self.shares);
        SharedSecret(tpke::api::SharedSecret(shared_secret))
    }
}

#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct SharedSecretSimpleBuilder {
    shares: Vec<tpke::api::DecryptionShareSimple>,
    domain_points: Vec<tpke::api::DomainPoint>,
    threshold: usize,
}

#[wasm_bindgen]
impl SharedSecretSimpleBuilder {
    #[wasm_bindgen(constructor)]
    pub fn new(threshold: usize) -> Self {
        Self {
            shares: vec![],
            domain_points: vec![],
            threshold,
        }
    }

    #[wasm_bindgen(js_name = "addDecryptionShare")]
    pub fn add_decryption_share(&mut self, share: &DecryptionShareSimple) {
        self.shares.push(share.0.clone());
    }

    #[wasm_bindgen(js_name = "addDomainPoint")]
    pub fn add_domain_point(&mut self, domain_point: &DomainPoint) {
        self.domain_points.push(domain_point.0);
    }

    #[wasm_bindgen]
    pub fn build(&self) -> SharedSecret {
        set_panic_hook();
        if self.shares.len() < self.threshold {
            panic!("Number of shares below threshold");
        }
        let domain_points: Vec<_> =
            self.domain_points.iter().map(|x| x.0).collect();
        let lagrange_coeffs =
            tpke::prepare_combine_simple::<tpke::api::E>(&domain_points);
        let shared_secret =
            tpke::share_combine_simple(&self.shares, &lagrange_coeffs);
        SharedSecret(tpke::api::SharedSecret(shared_secret))
    }
}

#[wasm_bindgen(js_name = "decryptWithSharedSecret")]
pub fn decrypt_with_shared_secret(
    ciphertext: &Ciphertext,
    aad: &[u8],
    shared_secret: &SharedSecret,
    g_inv: &G1Prepared,
) -> Result<Vec<u8>, Error> {
    set_panic_hook();
    tpke::api::decrypt_with_shared_secret(
        &ciphertext.0,
        aad,
        &shared_secret.0 .0,
        &g_inv.0,
    )
    .map_err(map_js_err)
}

/// Factory functions for testing
pub mod test_common {
    use super::*;

    #[wasm_bindgen]
    #[derive(Clone, Debug)]
    pub struct Dkg {
        pub public_key: PublicKey,
        pub private_key: PrivateKey,
        private_contexts: Vec<tpke::api::PrivateDecryptionContextSimple>,
    }

    #[wasm_bindgen]
    impl Dkg {
        // TODO: Consider removing threshold from precomputed variant parameters
        #[wasm_bindgen(constructor)]
        pub fn new(threshold: usize, shares_num: usize) -> Self {
            set_panic_hook();
            let mut rng = rand::thread_rng();
            let (public_key, private_key, private_contexts) =
                tpke::test_common::setup_simple::<tpke::api::E>(
                    threshold, shares_num, &mut rng,
                );
            Self {
                public_key: PublicKey(ferveo::api::DkgPublicKey(public_key)),
                private_key: PrivateKey(private_key),
                private_contexts,
            }
        }

        #[wasm_bindgen(js_name = "makeDecryptionShareSimple")]
        pub fn make_decryption_share_simple(
            &self,
            ciphertext: &Ciphertext,
            aad: &[u8],
            validator_index: usize,
        ) -> Result<DecryptionShareSimple, Error> {
            set_panic_hook();
            Ok(DecryptionShareSimple(
                self.private_contexts[validator_index]
                    .create_share(&ciphertext.0, aad)
                    .map_err(map_js_err)?,
            ))
        }

        #[wasm_bindgen(js_name = "makeDecryptionSharePrecomputed")]
        pub fn make_decryption_share_precomputed(
            &self,
            ciphertext: &Ciphertext,
            aad: &[u8],
            validator_index: usize,
        ) -> Result<DecryptionShareSimplePrecomputed, Error> {
            set_panic_hook();
            Ok(DecryptionShareSimplePrecomputed(
                self.private_contexts[validator_index]
                    .create_share_precomputed(&ciphertext.0, aad)
                    .map_err(map_js_err)?,
            ))
        }

        #[wasm_bindgen(js_name = "getDomainPoint")]
        pub fn get_domain_point(&self, validator_index: usize) -> DomainPoint {
            set_panic_hook();
            DomainPoint(tpke::api::DomainPoint(
                self.private_contexts[0].public_decryption_contexts
                    [validator_index]
                    .domain,
            ))
        }

        #[wasm_bindgen(getter, js_name = "gInv")]
        pub fn g_inv(&self) -> G1Prepared {
            set_panic_hook();
            G1Prepared(self.private_contexts[0].setup_params.g_inv.clone())
        }
    }
}
