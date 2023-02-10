//! Contains the public API of the library.

#![allow(dead_code)]

// TODO: Refactor this module to deduplicate shared code from tpke-wasm and tpke-wasm.

use ark_serialize::*;

pub type E = ark_bls12_381::Bls12_381;
pub type TpkeDkgPublicKey = ark_bls12_381::G1Affine;
pub type TpkePrivateKey = ark_bls12_381::G2Affine;
pub type TpkeUnblindingKey = ark_bls12_381::Fr;
pub type TpkeDomainPoint = ark_bls12_381::Fr;
pub type TpkeCiphertext = crate::Ciphertext<E>;
pub type TpkeDecryptionShareSimplePrecomputed =
    crate::DecryptionShareSimplePrecomputed<E>;
pub type TpkeDecryptionShareSimple = crate::DecryptionShareSimple<E>;
pub type TpkePublicDecryptionContext = crate::PublicDecryptionContextSimple<E>;
pub type TpkeSharedSecret = <E as ark_ec::PairingEngine>::Fqk;
pub type TpkeResult<T> = crate::Result<T>;
pub type TpkePrivateDecryptionContext =
    crate::PrivateDecryptionContextSimple<E>;

pub fn encrypt(
    message: &[u8],
    aad: &[u8],
    public_key: &TpkeDkgPublicKey,
) -> Ciphertext {
    // TODO: Should rng be a parameter?
    let rng = &mut rand::thread_rng();
    Ciphertext(crate::encrypt(message, aad, public_key, rng))
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

#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct DomainPoint(pub TpkeDomainPoint);

impl DomainPoint {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        CanonicalSerialize::serialize(&self.0, &mut bytes[..]).unwrap();
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut reader = bytes;
        let domain_point =
            CanonicalDeserialize::deserialize(&mut reader).unwrap();
        Self(domain_point)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct DecryptionShareSimple(pub TpkeDecryptionShareSimple);

impl DecryptionShareSimple {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(TpkeDecryptionShareSimple::from_bytes(bytes))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct DecryptionShareSimplePrecomputed(
    pub TpkeDecryptionShareSimplePrecomputed,
);

impl DecryptionShareSimplePrecomputed {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(TpkeDecryptionShareSimplePrecomputed::from_bytes(bytes).unwrap())
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
