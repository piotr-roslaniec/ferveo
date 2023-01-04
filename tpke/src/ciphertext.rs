use crate::*;

use ark_ec::{AffineCurve, PairingEngine};
use ark_ff::{FromBytes, One, ToBytes, UniformRand};
use ark_serialize::CanonicalSerialize;
use chacha20poly1305::{
    aead::{generic_array::GenericArray, Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand_core::RngCore;

use crate::{construct_tag_hash, hash_to_g2};

#[derive(Clone, Debug)]
pub struct Ciphertext<E: PairingEngine> {
    pub commitment: E::G1Affine, // U
    pub auth_tag: E::G2Affine,   // W
    pub ciphertext: Vec<u8>,     // V
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

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.commitment.write(&mut bytes).unwrap();
        self.auth_tag.write(&mut bytes).unwrap();
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        const COMMITMENT_LEN: usize = 97;
        let mut commitment_bytes = [0u8; COMMITMENT_LEN];
        commitment_bytes.copy_from_slice(&bytes[..COMMITMENT_LEN]);
        let commitment = E::G1Affine::read(&commitment_bytes[..]).unwrap();

        const AUTH_TAG_LEN: usize = 193;
        let mut auth_tag_bytes = [0u8; AUTH_TAG_LEN];
        auth_tag_bytes.copy_from_slice(
            &bytes[COMMITMENT_LEN..COMMITMENT_LEN + AUTH_TAG_LEN],
        );
        let auth_tag = E::G2Affine::read(&auth_tag_bytes[..]).unwrap();

        const CIPHERTEXT_LEN: usize = 33;
        let ciphertext = bytes[COMMITMENT_LEN + AUTH_TAG_LEN..].to_vec();

        Self {
            commitment,
            ciphertext,
            auth_tag,
        }
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

    Ciphertext::<E> {
        commitment,
        ciphertext,
        auth_tag,
    }
}

pub fn check_ciphertext_validity<E: PairingEngine>(
    c: &Ciphertext<E>,
    aad: &[u8],
) -> bool {
    let g_inv = E::G1Prepared::from(-E::G1Affine::prime_subgroup_generator());
    let hash_g2 = E::G2Prepared::from(construct_tag_hash::<E>(
        c.commitment,
        &c.ciphertext[..],
        aad,
    ));

    E::product_of_pairings(&[
        (E::G1Prepared::from(c.commitment), hash_g2),
        (g_inv, E::G2Prepared::from(c.auth_tag)),
    ]) == E::Fqk::one()
}

fn decrypt<E: PairingEngine>(
    ciphertext: &Ciphertext<E>,
    privkey: E::G2Affine,
) -> Vec<u8> {
    let s = E::product_of_pairings(&[(
        E::G1Prepared::from(ciphertext.commitment),
        E::G2Prepared::from(privkey),
    )]);
    decrypt_with_shared_secret(ciphertext, &s)
}

pub fn checked_decrypt<E: PairingEngine>(
    ciphertext: &Ciphertext<E>,
    aad: &[u8],
    privkey: E::G2Affine,
) -> Vec<u8> {
    if !check_ciphertext_validity(ciphertext, aad) {
        panic!("Ciphertext is invalid");
    }
    let s = E::product_of_pairings(&[(
        E::G1Prepared::from(ciphertext.commitment),
        E::G2Prepared::from(privkey),
    )]);
    decrypt_with_shared_secret(ciphertext, &s)
}

fn decrypt_with_shared_secret<E: PairingEngine>(
    ciphertext: &Ciphertext<E>,
    s: &E::Fqk,
) -> Vec<u8> {
    let nonce = nonce_from_commitment::<E>(ciphertext.commitment);
    let ciphertext = ciphertext.ciphertext.to_vec();

    let cipher = shared_secret_to_chacha::<E>(s);
    let plaintext = cipher.decrypt(&nonce, ciphertext.as_ref()).unwrap();

    plaintext
}

pub fn checked_decrypt_with_shared_secret<E: PairingEngine>(
    ciphertext: &Ciphertext<E>,
    aad: &[u8],
    s: &E::Fqk,
) -> Vec<u8> {
    if !check_ciphertext_validity(ciphertext, aad) {
        panic!("Ciphertext is invalid");
    }
    decrypt_with_shared_secret(ciphertext, s)
}

fn blake2s_hash(input: &[u8]) -> Vec<u8> {
    let mut hasher = blake2b_simd::Params::new().hash_length(32).to_state();
    hasher.update(input);
    hasher.finalize().as_bytes().to_vec()
}

pub fn shared_secret_to_chacha<E: PairingEngine>(
    s: &E::Fqk,
) -> ChaCha20Poly1305 {
    let mut prf_key = Vec::new();
    s.write(&mut prf_key).unwrap();
    let prf_key_32 = blake2s_hash(&prf_key);

    ChaCha20Poly1305::new(GenericArray::from_slice(&prf_key_32))
}

fn nonce_from_commitment<E: PairingEngine>(commitment: E::G1Affine) -> Nonce {
    let mut commitment_bytes = Vec::new();
    commitment
        .serialize_unchecked(&mut commitment_bytes)
        .unwrap();
    let commitment_hash = blake2s_hash(&commitment_bytes);
    *Nonce::from_slice(&commitment_hash[..12])
}
