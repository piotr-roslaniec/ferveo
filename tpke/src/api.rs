//! Contains the public API of the library.

#![allow(dead_code)]

// TODO: Refactor this module to deduplicate shared code from tpke-wasm and tpke-wasm.

pub type E = ark_bls12_381::Bls12_381;
pub type TpkeDkgPublicKey = ark_bls12_381::G1Affine;
pub type TpkePrivateKey = ark_bls12_381::G2Affine;
pub type TpkeUnblindingKey = ark_bls12_381::Fr;
pub type TpkeCiphertext = crate::Ciphertext<E>;
pub type TpkeDecryptionShare = crate::DecryptionShareSimplePrecomputed<E>;
pub type TpkePublicDecryptionContext = crate::PublicDecryptionContextSimple<E>;
pub type TpkeSharedSecret = <E as ark_ec::PairingEngine>::Fqk;
pub type TpkeResult<T> = crate::Result<T>;
pub type TpkePrivateDecryptionContext =
    crate::PrivateDecryptionContextSimple<E>;

pub fn encrypt(
    message: &[u8],
    aad: &[u8],
    pubkey: &TpkeDkgPublicKey,
) -> Ciphertext {
    // TODO: Should rng be a parameter?
    let rng = &mut rand::thread_rng();
    Ciphertext(crate::encrypt(message, aad, pubkey, rng))
}

pub fn decrypt_with_shared_secret(
    ciphertext: &Ciphertext,
    aad: &[u8],
    shared_secret: &TpkeSharedSecret,
) -> TpkeResult<Vec<u8>> {
    crate::decrypt_with_shared_secret(&ciphertext.0, aad, shared_secret)
}

pub fn decrypt_symmetric(
    ciphertext: &Ciphertext,
    aad: &[u8],
    private_key: TpkePrivateKey,
) -> Vec<u8> {
    crate::decrypt_symmetric(&ciphertext.0, aad, private_key).unwrap()
}

#[derive(Clone, Debug, PartialEq)]
pub struct DecryptionShare(pub TpkeDecryptionShare);

impl DecryptionShare {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(TpkeDecryptionShare::from_bytes(bytes).unwrap())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Ciphertext(pub TpkeCiphertext);

impl Ciphertext {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Ciphertext(TpkeCiphertext::from_bytes(bytes))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }
}
