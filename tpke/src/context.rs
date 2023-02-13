use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};

use crate::{
    check_ciphertext_validity, prepare_combine_simple, BlindedKeyShare,
    Ciphertext, DecryptionShareFast, DecryptionShareSimple,
    DecryptionShareSimplePrecomputed, PrivateKeyShare, PublicKeyShare, Result,
};

#[derive(Clone, Debug)]
pub struct PublicDecryptionContextFast<E: PairingEngine> {
    pub domain: E::Fr,
    pub public_key_share: PublicKeyShare<E>,
    pub blinded_key_share: BlindedKeyShare<E>,
    // This decrypter's contribution to N(0), namely (-1)^|domain| * \prod_i omega_i
    pub lagrange_n_0: E::Fr,
    pub h_inv: E::G2Prepared,
}

#[derive(Clone, Debug)]
pub struct PublicDecryptionContextSimple<E: PairingEngine> {
    pub domain: E::Fr,
    pub public_key_share: PublicKeyShare<E>,
    pub blinded_key_share: BlindedKeyShare<E>,
    pub h: E::G2Affine,
    pub validator_public_key: E::G2Projective,
}

#[derive(Clone, Debug)]
pub struct SetupParams<E: PairingEngine> {
    pub b: E::Fr,
    pub b_inv: E::Fr,
    pub g: E::G1Affine,
    pub g_inv: E::G1Prepared,
    pub h_inv: E::G2Prepared,
    pub h: E::G2Affine,
}

#[derive(Clone, Debug)]
pub struct PrivateDecryptionContextFast<E: PairingEngine> {
    pub index: usize,
    pub setup_params: SetupParams<E>,
    pub private_key_share: PrivateKeyShare<E>,
    pub public_decryption_contexts: Vec<PublicDecryptionContextFast<E>>,
}

impl<E: PairingEngine> PrivateDecryptionContextFast<E> {
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
pub struct PrivateDecryptionContextSimple<E: PairingEngine> {
    pub index: usize,
    pub setup_params: SetupParams<E>,
    pub private_key_share: PrivateKeyShare<E>,
    pub public_decryption_contexts: Vec<PublicDecryptionContextSimple<E>>,
    // TODO: Remove/replace with `setup_params.b` after refactoring
    pub validator_private_key: E::Fr,
}

impl<E: PairingEngine> PrivateDecryptionContextSimple<E> {
    pub fn create_share(
        &self,
        ciphertext: &Ciphertext<E>,
        aad: &[u8],
    ) -> Result<DecryptionShareSimple<E>> {
        DecryptionShareSimple::create(
            self.index,
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
    ) -> Result<DecryptionShareSimplePrecomputed<E>> {
        let domain = self
            .public_decryption_contexts
            .iter()
            .map(|c| c.domain)
            .collect::<Vec<_>>();
        let lagrange_coeffs = prepare_combine_simple::<E>(&domain);

        DecryptionShareSimplePrecomputed::new(
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
