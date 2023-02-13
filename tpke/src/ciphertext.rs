use ark_ec::{AffineCurve, PairingEngine};
use ark_ff::{One, ToBytes, UniformRand};
use ark_serialize::CanonicalSerialize;
use chacha20poly1305::{
    aead::{generic_array::GenericArray, Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use crypto::{digest::Digest, sha2::Sha256};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::serialization;
use crate::{htp_bls12381_g2, Result, ThresholdEncryptionError};

#[serde_as]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Ciphertext<E: PairingEngine> {
    #[serde_as(as = "serialization::SerdeAs")]
    pub commitment: E::G1Affine,
    // U
    #[serde_as(as = "serialization::SerdeAs")]
    pub auth_tag: E::G2Affine,
    // W
    pub ciphertext: Vec<u8>, // V
}

impl<E: PairingEngine> Ciphertext<E> {
    pub fn check(&self, g_inv: &E::G1Prepared) -> bool {
        let hash_g2 = E::G2Prepared::from(self.construct_tag_hash());

        E::product_of_pairings(&[
            (E::G1Prepared::from(self.commitment), hash_g2),
            (g_inv.clone(), E::G2Prepared::from(self.auth_tag)),
        ]) == E::Fqk::one()
    }

    fn construct_tag_hash(&self) -> E::G2Affine {
        let mut hash_input = Vec::<u8>::new();
        self.commitment.write(&mut hash_input).unwrap();
        hash_input.extend_from_slice(&self.ciphertext);

        hash_to_g2(&hash_input)
    }

    pub fn serialized_length(&self) -> usize {
        self.commitment.serialized_size()
            + self.auth_tag.serialized_size()
            + self.ciphertext.len()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap()
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        bincode::deserialize(bytes).unwrap()
    }
}

pub fn encrypt<R: RngCore, E: PairingEngine>(
    message: &[u8],
    aad: &[u8],
    pubkey: &E::G1Affine,
    rng: &mut R,
) -> Ciphertext<E> {
    // r
    let rand_element = E::Fr::rand(rng);
    // g
    let g_gen = E::G1Affine::prime_subgroup_generator();
    // h
    let h_gen = E::G2Affine::prime_subgroup_generator();

    let ry_prep = E::G1Prepared::from(pubkey.mul(rand_element).into());
    // s
    let product = E::product_of_pairings(&[(ry_prep, h_gen.into())]);
    // u
    let commitment = g_gen.mul(rand_element).into();

    let cipher = shared_secret_to_chacha::<E>(&product);
    let nonce = nonce_from_commitment::<E>(commitment);
    let ciphertext = cipher.encrypt(&nonce, message).unwrap();
    // w
    let auth_tag = construct_tag_hash::<E>(commitment, &ciphertext, aad)
        .mul(rand_element)
        .into();

    // TODO: Consider adding aad to the Ciphertext struct
    Ciphertext::<E> {
        commitment,
        ciphertext,
        auth_tag,
    }
}

/// Implements the check section 4.4.2 of the Ferveo paper, 'TPKE.CheckCiphertextValidity(U,W,aad)'
/// See: https://eprint.iacr.org/2022/898.pdf
/// See: https://nikkolasg.github.io/ferveo/tpke.html#to-validate-ciphertext-for-ind-cca2-security
pub fn check_ciphertext_validity<E: PairingEngine>(
    c: &Ciphertext<E>,
    aad: &[u8],
    g_inv: &E::G1Prepared,
) -> Result<()> {
    // H_G2(U, aad)
    let hash_g2 = E::G2Prepared::from(construct_tag_hash::<E>(
        c.commitment,
        &c.ciphertext[..],
        aad,
    ));

    let is_ciphertext_valid = E::product_of_pairings(&[
        // e(U, H_G2(U, aad)) = e(G, W)
        (E::G1Prepared::from(c.commitment), hash_g2),
        (g_inv.clone(), E::G2Prepared::from(c.auth_tag)),
    ]) == E::Fqk::one();

    if is_ciphertext_valid {
        Ok(())
    } else {
        Err(ThresholdEncryptionError::CiphertextVerificationFailed.into())
    }
}

pub fn decrypt_symmetric<E: PairingEngine>(
    ciphertext: &Ciphertext<E>,
    aad: &[u8],
    private_key: &E::G2Affine,
    g_inv: &E::G1Prepared,
) -> Result<Vec<u8>> {
    check_ciphertext_validity(ciphertext, aad, g_inv)?;
    let shared_secret = E::product_of_pairings(&[(
        E::G1Prepared::from(ciphertext.commitment),
        E::G2Prepared::from(*private_key),
    )]);
    decrypt_with_shared_secret_unchecked(ciphertext, &shared_secret)
}

fn decrypt_with_shared_secret_unchecked<E: PairingEngine>(
    ciphertext: &Ciphertext<E>,
    shared_secret: &E::Fqk,
) -> Result<Vec<u8>> {
    let nonce = nonce_from_commitment::<E>(ciphertext.commitment);
    let ciphertext = ciphertext.ciphertext.to_vec();

    let cipher = shared_secret_to_chacha::<E>(shared_secret);
    let plaintext = cipher
        .decrypt(&nonce, ciphertext.as_ref())
        .map_err(|_| ThresholdEncryptionError::CiphertextVerificationFailed)?;

    Ok(plaintext)
}

pub fn decrypt_with_shared_secret<E: PairingEngine>(
    ciphertext: &Ciphertext<E>,
    aad: &[u8],
    shared_secret: &E::Fqk,
    g_inv: &E::G1Prepared,
) -> Result<Vec<u8>> {
    check_ciphertext_validity(ciphertext, aad, g_inv)?;
    decrypt_with_shared_secret_unchecked(ciphertext, shared_secret)
}

fn sha256(input: &[u8]) -> Vec<u8> {
    let mut result = [0u8; 32];
    let mut hasher = Sha256::new();
    hasher.input(input);
    hasher.result(&mut result);
    result.to_vec()
}

pub fn shared_secret_to_chacha<E: PairingEngine>(
    s: &E::Fqk,
) -> ChaCha20Poly1305 {
    let mut prf_key = Vec::new();
    s.write(&mut prf_key).unwrap();
    let prf_key_32 = sha256(&prf_key);

    ChaCha20Poly1305::new(GenericArray::from_slice(&prf_key_32))
}

fn nonce_from_commitment<E: PairingEngine>(commitment: E::G1Affine) -> Nonce {
    let mut commitment_bytes = Vec::new();
    commitment
        .serialize_unchecked(&mut commitment_bytes)
        .unwrap();
    let commitment_hash = sha256(&commitment_bytes);
    *Nonce::from_slice(&commitment_hash[..12])
}

fn hash_to_g2<T: ark_serialize::CanonicalDeserialize>(message: &[u8]) -> T {
    let mut point_ser: Vec<u8> = Vec::new();
    let point = htp_bls12381_g2(message);
    point.serialize(&mut point_ser).unwrap();
    T::deserialize(&point_ser[..]).unwrap()
}

fn construct_tag_hash<E: PairingEngine>(
    u: E::G1Affine,
    stream_ciphertext: &[u8],
    aad: &[u8],
) -> E::G2Affine {
    let mut hash_input = Vec::<u8>::new();
    u.write(&mut hash_input).unwrap();
    hash_input.extend_from_slice(stream_ciphertext);
    hash_input.extend_from_slice(aad);

    hash_to_g2(&hash_input)
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::G1Projective;
    use ark_ec::ProjectiveCurve;
    use ark_std::{test_rng, UniformRand};
    use rand::prelude::StdRng;

    use crate::test_common::*;
    use crate::*;

    type E = ark_bls12_381::Bls12_381;

    #[test]
    fn ciphertext_serialization() {
        let rng = &mut test_rng();
        let msg: &[u8] = "abc".as_bytes();
        let aad: &[u8] = "my-aad".as_bytes();
        let pubkey = G1Projective::rand(rng).into_affine();

        let ciphertext = encrypt::<StdRng, E>(msg, aad, &pubkey, rng);
        let deserialized: Ciphertext<E> =
            Ciphertext::from_bytes(&ciphertext.to_bytes());

        assert_eq!(ciphertext, deserialized)
    }

    #[test]
    fn symmetric_encryption() {
        let rng = &mut test_rng();
        let shares_num = 16;
        let threshold = shares_num * 2 / 3;
        let msg: &[u8] = "abc".as_bytes();
        let aad: &[u8] = "my-aad".as_bytes();

        let (pubkey, privkey, contexts) =
            setup_fast::<E>(threshold, shares_num, rng);
        let g_inv = &contexts[0].setup_params.g_inv;

        let ciphertext = encrypt::<StdRng, E>(msg, aad, &pubkey, rng);

        let plaintext =
            decrypt_symmetric(&ciphertext, aad, &privkey, g_inv).unwrap();

        assert_eq!(msg, plaintext)
    }

    #[test]
    fn ciphertext_validity_check() {
        let rng = &mut test_rng();
        let shares_num = 16;
        let threshold = shares_num * 2 / 3;
        let msg: &[u8] = "abc".as_bytes();
        let aad: &[u8] = "my-aad".as_bytes();
        let (pubkey, _, contexts) = setup_fast::<E>(threshold, shares_num, rng);
        let g_inv = contexts[0].setup_params.g_inv.clone();
        let mut ciphertext = encrypt::<StdRng, E>(msg, aad, &pubkey, rng);

        // So far, the ciphertext is valid
        assert!(check_ciphertext_validity(&ciphertext, aad, &g_inv).is_ok());

        // Malformed the ciphertext
        ciphertext.ciphertext[0] += 1;
        assert!(check_ciphertext_validity(&ciphertext, aad, &g_inv).is_err());

        // Malformed the AAD
        let aad = "bad aad".as_bytes();
        assert!(check_ciphertext_validity(&ciphertext, aad, &g_inv).is_err());
    }
}
