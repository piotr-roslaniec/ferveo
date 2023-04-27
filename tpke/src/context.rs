use std::ops::Mul;

use ark_ec::{pairing::Pairing, CurveGroup};

use crate::{
    check_ciphertext_validity, prepare_combine_simple, BlindedKeyShare,
    Ciphertext, DecryptionShareFast, DecryptionSharePrecomputed,
    DecryptionShareSimple, PrivateKeyShare, PublicKeyShare, Result,
};

#[derive(Clone, Debug)]
pub struct PublicDecryptionContextFast<E: Pairing> {
    pub domain: E::ScalarField,
    pub public_key_share: PublicKeyShare<E>,
    pub blinded_key_share: BlindedKeyShare<E>,
    // This decrypter's contribution to N(0), namely (-1)^|domain| * \prod_i omega_i
    pub lagrange_n_0: E::ScalarField,
    pub h_inv: E::G2Prepared,
}

#[derive(Clone, Debug)]
pub struct PublicDecryptionContextSimple<E: Pairing> {
    pub domain: E::ScalarField,
    pub public_key_share: PublicKeyShare<E>,
    pub blinded_key_share: BlindedKeyShare<E>,
    pub h: E::G2Affine,
    pub validator_public_key: E::G2,
}

#[derive(Clone, Debug)]
pub struct SetupParams<E: Pairing> {
    pub b: E::ScalarField,
    pub b_inv: E::ScalarField,
    pub g: E::G1Affine,
    pub g_inv: E::G1Prepared,
    pub h_inv: E::G2Prepared,
    pub h: E::G2Affine,
}

#[derive(Clone, Debug)]
pub struct PrivateDecryptionContextFast<E: Pairing> {
    pub index: usize,
    pub setup_params: SetupParams<E>,
    pub private_key_share: PrivateKeyShare<E>,
    pub public_decryption_contexts: Vec<PublicDecryptionContextFast<E>>,
}

impl<E: Pairing> PrivateDecryptionContextFast<E> {
    pub fn create_share(
        &self,
        ciphertext: &Ciphertext<E>,
        aad: &[u8],
    ) -> Result<DecryptionShareFast<E>> {
        check_ciphertext_validity::<E>(
            ciphertext,
            aad,
            &self.setup_params.g_inv,
        )?;

        let decryption_share = ciphertext
            .commitment
            .mul(self.setup_params.b_inv)
            .into_affine();

        Ok(DecryptionShareFast {
            decrypter_index: self.index,
            decryption_share,
        })
    }
}

#[derive(Clone, Debug)]
pub struct PrivateDecryptionContextSimple<E: Pairing> {
    pub index: usize,
    pub setup_params: SetupParams<E>,
    pub private_key_share: PrivateKeyShare<E>,
    pub public_decryption_contexts: Vec<PublicDecryptionContextSimple<E>>,
    // TODO: Remove/replace with `setup_params.b` after refactoring
    pub validator_private_key: E::ScalarField,
}

impl<E: Pairing> PrivateDecryptionContextSimple<E> {
    pub fn create_share(
        &self,
        ciphertext: &Ciphertext<E>,
        aad: &[u8],
    ) -> Result<DecryptionShareSimple<E>> {
        DecryptionShareSimple::create(
            &self.validator_private_key,
            &self.private_key_share,
            ciphertext,
            aad,
            &self.setup_params.g_inv,
        )
    }

    pub fn create_share_precomputed(
        &self,
        ciphertext: &Ciphertext<E>,
        aad: &[u8],
    ) -> Result<DecryptionSharePrecomputed<E>> {
        let domain = self
            .public_decryption_contexts
            .iter()
            .map(|c| c.domain)
            .collect::<Vec<_>>();
        let lagrange_coeffs = prepare_combine_simple::<E>(&domain);

        DecryptionSharePrecomputed::new(
            self.index,
            &self.validator_private_key,
            &self.private_key_share,
            ciphertext,
            aad,
            &lagrange_coeffs[self.index],
            &self.setup_params.g_inv,
        )
    }
}
