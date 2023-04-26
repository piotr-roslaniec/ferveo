use std::ops::Mul;

use ark_ec::{pairing::Pairing, AffineRepr};
use ark_ff::{One, UniformRand};
use ark_serialize::{CanonicalSerialize, Compress};
use chacha20poly1305::{
    aead::{generic_array::GenericArray, Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use ferveo_common::serialization;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use sha2::{digest::Digest, Sha256};

use crate::{htp_bls12381_g2, Error, Result};

#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ciphertext<E: Pairing> {
    // U
    #[serde_as(as = "serialization::SerdeAs")]
    pub commitment: E::G1Affine,

    // W
    #[serde_as(as = "serialization::SerdeAs")]
    pub auth_tag: E::G2Affine,

    // V
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
}

impl<E: Pairing> Ciphertext<E> {
    pub fn check(&self, g_inv: &E::G1Prepared) -> Result<bool> {
        let hash_g2 = E::G2Prepared::from(self.construct_tag_hash()?);

        Ok(E::multi_pairing(
            [self.commitment.into(), g_inv.to_owned()],
            [hash_g2, self.auth_tag.into()],
        )
        .0 == E::TargetField::one())
    }

    fn construct_tag_hash(&self) -> Result<E::G2Affine> {
        let mut hash_input = Vec::<u8>::new();
        self.commitment.serialize_compressed(&mut hash_input)?;
        hash_input.extend_from_slice(&self.ciphertext);

        hash_to_g2(&hash_input)
    }

    pub fn serialized_length(&self) -> usize {
        self.commitment.serialized_size(Compress::No)
            + self.auth_tag.serialized_size(Compress::No)
            + self.ciphertext.len()
    }
}

pub fn encrypt<E: Pairing>(
    message: &[u8],
    aad: &[u8],
    pubkey: &E::G1Affine,
    rng: &mut impl rand::Rng,
) -> Result<Ciphertext<E>> {
    // r
    let rand_element = E::ScalarField::rand(rng);
    // g
    let g_gen = E::G1Affine::generator();
    // h
    let h_gen = E::G2Affine::generator();

    let ry_prep = E::G1Prepared::from(pubkey.mul(rand_element).into());
    // s
    let product = E::pairing(ry_prep, h_gen).0;
    // u
    let commitment = g_gen.mul(rand_element).into();

    let nonce = nonce_from_commitment::<E>(commitment)?;
    let ciphertext = shared_secret_to_chacha::<E>(&product)?
        .encrypt(&nonce, message)
        .map_err(Error::SymmetricEncryptionError)?
        .to_vec();
    // w
    let auth_tag = construct_tag_hash::<E>(commitment, &ciphertext, aad)?
        .mul(rand_element)
        .into();

    // TODO: Consider adding aad to the Ciphertext struct
    Ok(Ciphertext::<E> {
        commitment,
        ciphertext,
        auth_tag,
    })
}

/// Implements the check section 4.4.2 of the Ferveo paper, 'TPKE.CheckCiphertextValidity(U,W,aad)'
/// See: https://eprint.iacr.org/2022/898.pdf
/// See: https://nikkolasg.github.io/ferveo/tpke.html#to-validate-ciphertext-for-ind-cca2-security
pub fn check_ciphertext_validity<E: Pairing>(
    c: &Ciphertext<E>,
    aad: &[u8],
    g_inv: &E::G1Prepared,
) -> Result<()> {
    // H_G2(U, aad)
    let hash_g2 = E::G2Prepared::from(construct_tag_hash::<E>(
        c.commitment,
        &c.ciphertext[..],
        aad,
    )?);

    let is_ciphertext_valid = E::multi_pairing(
        // e(U, H_G2(U, aad)) = e(G, W)
        [c.commitment.into(), g_inv.to_owned()],
        [hash_g2, c.auth_tag.into()],
    )
    .0 == E::TargetField::one();

    if is_ciphertext_valid {
        Ok(())
    } else {
        Err(Error::CiphertextVerificationFailed)
    }
}

pub fn decrypt_symmetric<E: Pairing>(
    ciphertext: &Ciphertext<E>,
    aad: &[u8],
    private_key: &E::G2Affine,
    g_inv: &E::G1Prepared,
) -> Result<Vec<u8>> {
    check_ciphertext_validity(ciphertext, aad, g_inv)?;
    let shared_secret = E::pairing(
        E::G1Prepared::from(ciphertext.commitment),
        E::G2Prepared::from(*private_key),
    )
    .0;
    decrypt_with_shared_secret_unchecked(ciphertext, &shared_secret)
}

fn decrypt_with_shared_secret_unchecked<E: Pairing>(
    ciphertext: &Ciphertext<E>,
    shared_secret: &E::TargetField,
) -> Result<Vec<u8>> {
    let nonce = nonce_from_commitment::<E>(ciphertext.commitment)?;
    let ciphertext = ciphertext.ciphertext.to_vec();

    let plaintext = shared_secret_to_chacha::<E>(shared_secret)?
        .decrypt(&nonce, ciphertext.as_ref())
        .map_err(|_| Error::CiphertextVerificationFailed)?
        .to_vec();

    Ok(plaintext)
}

pub fn decrypt_with_shared_secret<E: Pairing>(
    ciphertext: &Ciphertext<E>,
    aad: &[u8],
    shared_secret: &E::TargetField,
    g_inv: &E::G1Prepared,
) -> Result<Vec<u8>> {
    check_ciphertext_validity(ciphertext, aad, g_inv)?;
    decrypt_with_shared_secret_unchecked(ciphertext, shared_secret)
}

fn sha256(input: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(input);
    let result = hasher.finalize();
    result.to_vec()
}

pub fn shared_secret_to_chacha<E: Pairing>(
    s: &E::TargetField,
) -> Result<ChaCha20Poly1305> {
    let mut prf_key = Vec::new();
    s.serialize_compressed(&mut prf_key)?;
    let prf_key_32 = sha256(&prf_key);

    Ok(ChaCha20Poly1305::new(GenericArray::from_slice(&prf_key_32)))
}

fn nonce_from_commitment<E: Pairing>(commitment: E::G1Affine) -> Result<Nonce> {
    let mut commitment_bytes = Vec::new();
    commitment.serialize_compressed(&mut commitment_bytes)?;
    let commitment_hash = sha256(&commitment_bytes);
    Ok(*Nonce::from_slice(&commitment_hash[..12]))
}

fn hash_to_g2<T: ark_serialize::CanonicalDeserialize>(
    message: &[u8],
) -> Result<T> {
    let point = htp_bls12381_g2(message);
    let mut point_ser: Vec<u8> = Vec::new();
    point.serialize_compressed(&mut point_ser)?;
    T::deserialize_compressed(&point_ser[..])
        .map_err(Error::ArkworksSerializationError)
}

fn construct_tag_hash<E: Pairing>(
    commitment: E::G1Affine,
    stream_ciphertext: &[u8],
    aad: &[u8],
) -> Result<E::G2Affine> {
    let mut hash_input = Vec::<u8>::new();
    commitment.serialize_compressed(&mut hash_input)?;
    hash_input.extend_from_slice(stream_ciphertext);
    hash_input.extend_from_slice(aad);
    hash_to_g2(&hash_input)
}

#[cfg(test)]
mod tests {

    use ark_std::test_rng;

    use crate::{test_common::*, *};

    type E = ark_bls12_381::Bls12_381;

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

        let ciphertext = encrypt::<E>(msg, aad, &pubkey, rng).unwrap();

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
        let mut ciphertext = encrypt::<E>(msg, aad, &pubkey, rng).unwrap();

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
