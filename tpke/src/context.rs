use crate::*;
use ark_ec::ProjectiveCurve;

#[derive(Clone, Debug)]
pub struct PublicDecryptionContext<E: PairingEngine> {
    pub domain: Vec<E::Fr>,
    pub public_key_shares: PublicKeyShares<E>,
    pub blinded_key_shares: BlindedKeyShares<E>,
    // This decrypter's contribution to N(0), namely (-1)^|domain| * \prod_i omega_i
    pub lagrange_n_0: E::Fr,
}

#[derive(Clone, Debug)]
pub struct PublicDecryptionContextSimple<E: PairingEngine> {
    pub domain: E::Fr,
    pub public_key_shares: PublicKeyShares<E>,
    pub blinded_key_shares: BlindedKeyShares<E>,
}

#[derive(Clone, Debug)]
pub struct PrivateDecryptionContext<E: PairingEngine> {
    pub index: usize,
    pub b: E::Fr,
    pub b_inv: E::Fr,
    pub private_key_share: PrivateKeyShare<E>,
    pub public_decryption_contexts: Vec<PublicDecryptionContext<E>>,
    pub g: E::G1Affine,
    pub g_inv: E::G1Prepared,
    pub h_inv: E::G2Prepared,
    pub scalar_bits: usize,
    pub window_size: usize,
}

impl<E: PairingEngine> PrivateDecryptionContext<E> {
    pub fn create_share(
        &self,
        ciphertext: &Ciphertext<E>,
    ) -> DecryptionShare<E> {
        // let decryption_share =
        //     ciphertext.commitment.mul(self.b_inv).into_affine();
        let decryption_share = ciphertext.commitment;

        DecryptionShare {
            decrypter_index: self.index,
            decryption_share,
        }
    }
    pub fn batch_verify_decryption_shares<R: RngCore>(
        &self,
        ciphertexts: &[Ciphertext<E>],
        shares: &[Vec<DecryptionShare<E>>],
        //ciphertexts_and_shares: &[(Ciphertext<E>, Vec<DecryptionShare<E>>)],
        rng: &mut R,
    ) -> bool {
        let num_ciphertexts = ciphertexts.len();
        let num_shares = shares[0].len();

        // Get [b_i] H for each of the decryption shares
        let blinding_keys = shares[0]
            .iter()
            .map(|d| {
                self.public_decryption_contexts[d.decrypter_index]
                    .blinded_key_shares
                    .blinding_key_prepared
                    .clone()
            })
            .collect::<Vec<_>>();

        // For each ciphertext, generate num_shares random scalars
        let alpha_ij = (0..num_ciphertexts)
            .map(|_| generate_random::<_, E>(num_shares, rng))
            .collect::<Vec<_>>();

        let mut pairings = Vec::with_capacity(num_shares + 1);

        // Compute \sum_i \alpha_{i,j} for each ciphertext j
        let sum_alpha_i = alpha_ij
            .iter()
            .map(|alpha_j| alpha_j.iter().sum::<E::Fr>())
            .collect::<Vec<_>>();

        // Compute \sum_j [ \sum_i \alpha_{i,j} ] U_j
        let sum_u_j = E::G1Prepared::from(
            izip!(ciphertexts.iter(), sum_alpha_i.iter())
                .map(|(c, alpha_j)| c.commitment.mul(*alpha_j))
                .sum::<E::G1Projective>()
                .into_affine(),
        );

        // e(\sum_j [ \sum_i \alpha_{i,j} ] U_j, -H)
        pairings.push((sum_u_j, self.h_inv.clone()));

        let mut sum_d_j = vec![E::G1Projective::zero(); num_shares];

        // sum_D_j = { [\sum_j \alpha_{i,j} ] D_i }
        for (d, alpha_j) in izip!(shares.iter(), alpha_ij.iter()) {
            for (sum_alpha_d_i, d_ij, alpha) in
                izip!(sum_d_j.iter_mut(), d.iter(), alpha_j.iter())
            {
                *sum_alpha_d_i += d_ij.decryption_share.mul(*alpha);
            }
        }

        // e([\sum_j \alpha_{i,j} ] D_i, B_i)
        for (d_i, b_i) in izip!(sum_d_j.iter(), blinding_keys.iter()) {
            pairings
                .push((E::G1Prepared::from(d_i.into_affine()), b_i.clone()));
        }

        E::product_of_pairings(&pairings) == E::Fqk::one()
    }
}

#[derive(Clone, Debug)]
pub struct PrivateDecryptionContextSimple<E: PairingEngine> {
    pub index: usize,
    pub b: E::Fr,
    pub b_inv: E::Fr,
    pub private_key_share: PrivateKeyShare<E>,
    pub public_decryption_contexts: Vec<PublicDecryptionContextSimple<E>>,
    pub g: E::G1Affine,
    pub g_inv: E::G1Prepared,
    pub h_inv: E::G2Prepared,
}

impl<E: PairingEngine> PrivateDecryptionContextSimple<E> {
    pub fn create_share(
        &self,
        ciphertext: &Ciphertext<E>,
    ) -> DecryptionShareSimple<E> {
        let u = ciphertext.commitment;
        let z_i = self.private_key_share.clone();
        let z_i = z_i.private_key_shares[0];
        // C_i = e(U, Z_i)
        let c_i = E::pairing(u, z_i);
        DecryptionShareSimple {
            decrypter_index: self.index,
            decryption_share: c_i,
        }
    }
}
