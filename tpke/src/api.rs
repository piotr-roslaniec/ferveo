//! Contains the public API of the library.

// TODO: Refactor this module to deduplicate shared code from tpke-wasm and tpke-wasm.

use std::convert::TryInto;

use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{BigInteger256, ToBytes};

// Fixing some of the types here on our target engine
// TODO: Consider fixing on crate::api level instead of bindings level
type E = ark_bls12_381::Bls12_381;
type TpkePublicKey = ark_bls12_381::G1Affine;
type TpkePrivateKey = ark_bls12_381::G2Affine;
type TpkeCiphertext = crate::Ciphertext<E>;
type TpkeDecryptionShare = crate::DecryptionShare<E>;
type TpkePublicDecryptionContext = crate::PublicDecryptionContext<E>;
type TpkeSharedSecret =
    <ark_bls12_381::Bls12_381 as ark_ec::PairingEngine>::Fqk;

#[derive(Clone, Debug)]
pub struct PrivateDecryptionContext {
    pub b_inv: ark_bls12_381::Fr,
    pub decrypter_index: usize,
}

impl PrivateDecryptionContext {
    const B_INV_LEN: usize = 32;
    const DECRYPTER_INDEX_LEN: usize = 8;

    pub fn new(b_inv: &ark_bls12_381::Fr, decrypter_index: usize) -> Self {
        Self {
            b_inv: *b_inv,
            decrypter_index,
        }
    }

    pub fn serialized_size() -> usize {
        Self::B_INV_LEN + Self::DECRYPTER_INDEX_LEN
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.b_inv.0.write(&mut bytes).unwrap();

        let decrypter_index =
            bincode::serialize(&self.decrypter_index).unwrap();
        bytes.extend(decrypter_index);

        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let b_inv_bytes = &bytes[0..Self::B_INV_LEN];
        // Chunking bytes to u64s to construct a BigInteger256.
        let b_inv = b_inv_bytes
            .chunks(8)
            .map(|x| {
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(x);
                u64::from_le_bytes(bytes)
            })
            .collect::<Vec<u64>>();
        let b_inv: [u64; 4] = b_inv.try_into().unwrap();
        let b_inv = ark_bls12_381::Fr::new(BigInteger256::new(b_inv));

        let decrypter_index_bytes = &bytes
            [Self::B_INV_LEN..Self::B_INV_LEN + Self::DECRYPTER_INDEX_LEN];
        let decrypter_index =
            bincode::deserialize(decrypter_index_bytes).unwrap();

        Self {
            b_inv,
            decrypter_index,
        }
    }
}

#[derive(Clone, Debug)]
pub struct DecryptionShare(pub TpkeDecryptionShare);

impl DecryptionShare {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let share = TpkeDecryptionShare::from_bytes(bytes);
        Self(share)
    }
}

#[derive(Clone, Debug)]
pub struct ParticipantPayload {
    pub decryption_context: PrivateDecryptionContext,
    pub ciphertext: TpkeCiphertext,
}
impl ParticipantPayload {
    pub fn new(
        decryption_context: &PrivateDecryptionContext,
        ciphertext: &TpkeCiphertext,
    ) -> Self {
        Self {
            decryption_context: decryption_context.clone(),
            ciphertext: ciphertext.clone(),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.decryption_context.to_bytes();
        bytes.extend(&self.ciphertext.to_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let decryption_context_bytes =
            &bytes[0..PrivateDecryptionContext::serialized_size()];
        let decryption_context =
            PrivateDecryptionContext::from_bytes(decryption_context_bytes);

        let ciphertext_bytes =
            bytes[PrivateDecryptionContext::serialized_size()..].to_vec();
        let ciphertext: crate::Ciphertext<E> =
            crate::Ciphertext::from_bytes(&ciphertext_bytes);

        Self {
            decryption_context,
            ciphertext,
        }
    }

    pub fn to_decryption_share(&self) -> DecryptionShare {
        // TODO: Add verification steps
        let decryption_share = self
            .ciphertext
            .commitment
            .mul(self.decryption_context.b_inv)
            .into_affine();

        DecryptionShare(TpkeDecryptionShare {
            decrypter_index: self.decryption_context.decrypter_index,
            decryption_share,
        })
    }
}
