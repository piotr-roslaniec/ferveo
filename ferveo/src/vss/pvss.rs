use std::{marker::PhantomData, ops::Mul};

use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{Field, Zero};
use ark_poly::{
    polynomial::univariate::DensePolynomial, DenseUVPolynomial,
    EvaluationDomain,
};
use group_threshold_cryptography as tpke;
use itertools::Itertools;
use measure_time::print_time;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use subproductdomain::fast_multiexp;
use tpke::{
    prepare_combine_simple, refresh_private_key_share,
    update_share_for_recovery, Ciphertext, DecryptionSharePrecomputed,
    DecryptionShareSimple, PrivateKeyShare,
};

use crate::{
    batch_to_projective_g1, batch_to_projective_g2, Error,
    PubliclyVerifiableDkg, Result,
};

/// These are the blinded evaluations of shares of a single random polynomial
pub type ShareEncryptions<E> = <E as Pairing>::G2Affine;

/// Marker struct for unaggregated PVSS transcripts
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Unaggregated;

/// Marker struct for aggregated PVSS transcripts
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Aggregated;

/// Trait gate used to add extra methods to aggregated PVSS transcripts
pub trait Aggregate {}

/// Apply trait gate to Aggregated marker struct
impl Aggregate for Aggregated {}

/// Type alias for non aggregated PVSS transcripts
pub type Pvss<E> = PubliclyVerifiableSS<E>;

/// Type alias for aggregated PVSS transcripts
pub type AggregatedPvss<E> = PubliclyVerifiableSS<E, Aggregated>;

/// The choice of group generators
#[derive(Clone, Debug)]
pub struct PubliclyVerifiableParams<E: Pairing> {
    pub g: E::G1,
    pub h: E::G2,
}

impl<E: Pairing> PubliclyVerifiableParams<E> {
    pub fn g_inv(&self) -> E::G1Prepared {
        E::G1Prepared::from(-self.g)
    }
}

/// Each validator posts a transcript to the chain. Once enough
/// validators have done this (their total voting power exceeds
/// 2/3 the total), this will be aggregated into a final key
#[serde_as]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PubliclyVerifiableSS<E: Pairing, T = Unaggregated> {
    /// Used in Feldman commitment to the VSS polynomial, F = g^{\phi}
    #[serde_as(as = "ferveo_common::serialization::SerdeAs")]
    pub coeffs: Vec<E::G1Affine>,

    /// The shares to be dealt to each validator
    #[serde_as(as = "ferveo_common::serialization::SerdeAs")]
    // pub shares: Vec<ShareEncryptions<E>>, // TODO: Using a custom type instead of referring to E:G2Affine breaks the serialization
    pub shares: Vec<E::G2Affine>,

    /// Proof of Knowledge
    #[serde_as(as = "ferveo_common::serialization::SerdeAs")]
    pub sigma: E::G2Affine,

    /// Marker struct to distinguish between aggregated and
    /// non aggregated PVSS transcripts
    phantom: PhantomData<T>,
}

impl<E: Pairing, T> PubliclyVerifiableSS<E, T> {
    /// Create a new PVSS instance
    /// `s`: the secret constant coefficient to share
    /// `dkg`: the current DKG session
    /// `rng` a cryptographic random number generator
    pub fn new<R: RngCore>(
        s: &E::ScalarField,
        dkg: &PubliclyVerifiableDkg<E>,
        rng: &mut R,
    ) -> Result<Self> {
        // Our random polynomial, \phi(x) = s + \sum_{i=1}^{t-1} a_i x^i
        let mut phi = DensePolynomial::<E::ScalarField>::rand(
            (dkg.params.security_threshold - 1) as usize,
            rng,
        );
        phi.coeffs[0] = *s; // setting the first coefficient to secret value

        // Evaluations of the polynomial over the domain
        let evals = phi.evaluate_over_domain_by_ref(dkg.domain);
        // commitment to coeffs, F_i
        let coeffs = fast_multiexp(&phi.coeffs, dkg.pvss_params.g);
        let shares = dkg
            .validators
            .iter()
            .map(|val| {
                // ek_{i}^{eval_i}, i = validator index
                fast_multiexp(
                    // &evals.evals[i..i] = &evals.evals[i]
                    &[evals.evals[val.share_index]], // one share per validator
                    val.validator.public_key.encryption_key.into_group(),
                )[0]
            })
            .collect::<Vec<ShareEncryptions<E>>>();
        if shares.len() != dkg.validators.len() {
            return Err(Error::InsufficientValidators(
                shares.len() as u32,
                dkg.validators.len() as u32,
            ));
        }
        // phi.zeroize(); // TODO zeroize?
        // TODO: Cross check proof of knowledge check with the whitepaper; this check proves that there is a relationship between the secret and the pvss transcript
        // Sigma is a proof of knowledge of the secret, sigma = h^s
        let sigma = E::G2Affine::generator().mul(*s).into(); //todo hash to curve
        let vss = Self {
            coeffs,
            shares,
            sigma,
            phantom: Default::default(),
        };
        Ok(vss)
    }

    /// Verify the pvss transcript from a validator. This is not the full check,
    /// i.e. we optimistically do not check the commitment. This is deferred
    /// until the aggregation step
    pub fn verify_optimistic(&self) -> bool {
        // We're only checking the proof of knowledge here, sigma ?= h^s
        // "Does the first coefficient of the secret polynomial match the proof of knowledge?"
        E::pairing(
            self.coeffs[0].into_group(), // F_0 = g^s
            E::G2Affine::generator(),    // h
        ) == E::pairing(
            E::G1Affine::generator(), // g
            self.sigma,               // h^s
        )
    }

    /// Part of checking the validity of an aggregated PVSS transcript
    ///
    /// Implements check #4 in 4.2.3 section of https://eprint.iacr.org/2022/898.pdf
    ///
    /// If aggregation fails, a validator needs to know that their pvss
    /// transcript was at fault so that the can issue a new one. This
    /// function may also be used for that purpose.
    pub fn verify_full(&self, dkg: &PubliclyVerifiableDkg<E>) -> bool {
        // compute the commitment
        let mut commitment = batch_to_projective_g1::<E>(&self.coeffs);
        print_time!("commitment fft");
        dkg.domain.fft_in_place(&mut commitment);

        // Each validator checks that their share is correct
        dkg.validators
            .iter()
            .zip(self.shares.iter())
            .all(|(validator, y_i)| {
                // TODO: Check #3 is missing
                // See #3 in 4.2.3 section of https://eprint.iacr.org/2022/898.pdf

                // Validator checks checks aggregated shares against commitment
                let ek_i =
                    validator.validator.public_key.encryption_key.into_group();
                let a_i = &commitment[validator.share_index];
                // We verify that e(G, Y_i) = e(A_i, ek_i) for validator i
                // See #4 in 4.2.3 section of https://eprint.iacr.org/2022/898.pdf
                // e(G,Y) = e(A, ek)
                E::pairing(dkg.pvss_params.g, *y_i) == E::pairing(a_i, ek_i)
            })
    }
}

/// Extra methods available to aggregated PVSS transcripts
impl<E: Pairing, T: Aggregate> PubliclyVerifiableSS<E, T> {
    /// Verify that this PVSS instance is a valid aggregation of
    /// the PVSS instances, produced by [`aggregate`],
    /// and received by the DKG context `dkg`
    /// Returns the total valid weight of the aggregated PVSS
    pub fn verify_aggregation(
        &self,
        dkg: &PubliclyVerifiableDkg<E>,
    ) -> Result<u32> {
        print_time!("PVSS verify_aggregation");
        self.verify_full(dkg);
        // Now, we verify that the aggregated PVSS transcript is a valid aggregation
        // If it is, we return the total weights of the PVSS transcripts
        let mut y = E::G1::zero();
        // TODO: If we don't deal with share weights anymore, do we even need to call `verify_aggregation`?
        let mut shares_total = 0u32;
        for (_, pvss) in dkg.vss.iter() {
            y += pvss.coeffs[0].into_group();
            shares_total += 1
        }
        if y.into_affine() == self.coeffs[0] {
            Ok(shares_total)
        } else {
            Err(Error::InvalidTranscriptAggregate)
        }
    }

    pub fn decrypt_private_key_share(
        &self,
        validator_decryption_key: &E::ScalarField,
        validator_index: usize,
    ) -> PrivateKeyShare<E> {
        // Decrypt private key shares https://nikkolasg.github.io/ferveo/pvss.html#validator-decryption-of-private-key-shares
        let private_key_share = self
            .shares
            .get(validator_index)
            .unwrap()
            .mul(
                validator_decryption_key
                    .inverse()
                    .expect("Validator decryption key must have an inverse"),
            )
            .into_affine();
        PrivateKeyShare { private_key_share }
    }

    pub fn make_decryption_share_simple(
        &self,
        ciphertext: &Ciphertext<E>,
        aad: &[u8],
        validator_decryption_key: &E::ScalarField,
        validator_index: usize,
        g_inv: &E::G1Prepared,
    ) -> Result<DecryptionShareSimple<E>> {
        let private_key_share = self.decrypt_private_key_share(
            validator_decryption_key,
            validator_index,
        );
        DecryptionShareSimple::create(
            validator_index,
            validator_decryption_key,
            &private_key_share,
            ciphertext,
            aad,
            g_inv,
        )
        .map_err(|e| e.into())
    }
    pub fn make_decryption_share_simple_precomputed(
        &self,
        ciphertext: &Ciphertext<E>,
        aad: &[u8],
        validator_decryption_key: &E::ScalarField,
        validator_index: usize,
        domain_points: &[E::ScalarField],
        g_inv: &E::G1Prepared,
    ) -> Result<DecryptionSharePrecomputed<E>> {
        let private_key_share = self.decrypt_private_key_share(
            validator_decryption_key,
            validator_index,
        );

        let lagrange_coeffs = prepare_combine_simple::<E>(domain_points);

        DecryptionSharePrecomputed::new(
            validator_index,
            validator_decryption_key,
            &private_key_share,
            ciphertext,
            aad,
            &lagrange_coeffs[validator_index],
            g_inv,
        )
        .map_err(|e| e.into())
    }

    pub fn refresh_decryption_share(
        &self,
        ciphertext: &Ciphertext<E>,
        aad: &[u8],
        validator_decryption_key: &E::ScalarField,
        validator_index: usize,
        polynomial: &DensePolynomial<E::ScalarField>,
        dkg: &PubliclyVerifiableDkg<E>,
    ) -> Result<DecryptionShareSimple<E>> {
        let validator_private_key_share = self.decrypt_private_key_share(
            validator_decryption_key,
            validator_index,
        );
        let h = dkg.pvss_params.h;
        let domain_point = dkg.domain.element(validator_index);
        let refreshed_private_key_share = refresh_private_key_share(
            &h,
            &domain_point,
            polynomial,
            &validator_private_key_share,
        );
        DecryptionShareSimple::create(
            validator_index,
            validator_decryption_key,
            &refreshed_private_key_share,
            ciphertext,
            aad,
            &dkg.pvss_params.g_inv(),
        )
        .map_err(|e| e.into())
    }

    pub fn update_private_key_share_for_recovery(
        &self,
        validator_decryption_key: &E::ScalarField,
        validator_index: usize,
        share_updates: &[E::G2],
    ) -> PrivateKeyShare<E> {
        // Retrieves their private key share
        let private_key_share = self.decrypt_private_key_share(
            validator_decryption_key,
            validator_index,
        );

        // And updates their share
        update_share_for_recovery::<E>(&private_key_share, share_updates)
    }
}

/// Aggregate the PVSS instances in `pvss` from DKG session `dkg`
/// into a new PVSS instance
/// See: https://nikkolasg.github.io/ferveo/pvss.html?highlight=aggregate#aggregation
pub fn aggregate<E: Pairing>(
    dkg: &PubliclyVerifiableDkg<E>,
) -> PubliclyVerifiableSS<E, Aggregated> {
    let pvss = &dkg.vss;
    let mut pvss_iter = pvss.iter();
    let (_, first_pvss) = pvss_iter
        .next()
        .expect("May not aggregate empty PVSS instances");
    let mut coeffs = batch_to_projective_g1::<E>(&first_pvss.coeffs);
    let mut sigma = first_pvss.sigma;

    let mut shares = batch_to_projective_g2::<E>(&first_pvss.shares);

    // So now we're iterating over the PVSS instances, and adding their coefficients and shares, and their sigma
    // sigma is the sum of all the sigma_i, which is the proof of knowledge of the secret polynomial
    // Aggregating is just adding the corresponding values in pvss instances, so pvss = pvss + pvss_j
    for (_, next) in pvss_iter {
        sigma = (sigma + next.sigma).into();
        coeffs
            .iter_mut()
            .zip_eq(next.coeffs.iter())
            .for_each(|(a, b)| *a += b);
        shares
            .iter_mut()
            .zip_eq(next.shares.iter())
            .for_each(|(a, b)| *a += b);
    }
    let shares = E::G2::normalize_batch(&shares);

    PubliclyVerifiableSS {
        coeffs: E::G1::normalize_batch(&coeffs),
        shares,
        sigma,
        phantom: Default::default(),
    }
}

pub fn aggregate_for_decryption<E: Pairing>(
    dkg: &PubliclyVerifiableDkg<E>,
) -> Vec<ShareEncryptions<E>> {
    // From docs: https://nikkolasg.github.io/ferveo/pvss.html?highlight=aggregate#aggregation
    // "Two PVSS instances may be aggregated into a single PVSS instance by adding elementwise each of the corresponding group elements."
    let shares = dkg
        .vss
        .values()
        .map(|pvss| pvss.shares.clone())
        .collect::<Vec<_>>();
    let first_share = shares
        .first()
        .expect("Need one or more decryption shares to aggregate")
        .to_vec();
    shares
        .into_iter()
        .skip(1)
        // We're assuming that in every PVSS instance, the shares are in the same order
        .fold(first_share, |acc, shares| {
            acc.into_iter()
                .zip_eq(shares.into_iter())
                .map(|(a, b)| (a + b).into())
                .collect()
        })
}

#[cfg(test)]
mod test_pvss {
    use ark_bls12_381::Bls12_381 as EllipticCurve;
    use ark_ec::AffineRepr;
    use ark_ff::UniformRand;

    use super::*;
    use crate::dkg::pv::test_common::*;

    type ScalarField = <EllipticCurve as Pairing>::ScalarField;
    type G1 = <EllipticCurve as Pairing>::G1Affine;
    type G2 = <EllipticCurve as Pairing>::G2Affine;

    /// Test the happy flow that a pvss with the correct form is created
    /// and that appropriate validations pass
    #[test]
    fn test_new_pvss() {
        let rng = &mut ark_std::test_rng();
        let dkg = setup_dkg(0);
        let s = ScalarField::rand(rng);
        let pvss =
            Pvss::<EllipticCurve>::new(&s, &dkg, rng).expect("Test failed");
        // check that the chosen secret coefficient is correct
        assert_eq!(pvss.coeffs[0], G1::generator().mul(s));
        //check that a polynomial of the correct degree was created
        assert_eq!(pvss.coeffs.len(), dkg.params.security_threshold as usize);
        // check that the correct number of shares were created
        assert_eq!(pvss.shares.len(), dkg.validators.len());
        // check that the prove of knowledge is correct
        assert_eq!(pvss.sigma, G2::generator().mul(s));
        // check that the optimistic verify returns true
        assert!(pvss.verify_optimistic());
        // check that the full verify returns true
        assert!(pvss.verify_full(&dkg));
    }

    /// Check that if the proof of knowledge is wrong,
    /// the optimistic verification of PVSS fails
    #[test]
    fn test_verify_pvss_wrong_proof_of_knowledge() {
        let rng = &mut ark_std::test_rng();
        let dkg = setup_dkg(0);
        let mut s = ScalarField::rand(rng);
        // ensure that the proof of knowledge is not zero
        while s == ScalarField::zero() {
            s = ScalarField::rand(rng);
        }
        let mut pvss =
            PubliclyVerifiableSS::<EllipticCurve>::new(&s, &dkg, rng)
                .expect("Test failed");

        pvss.sigma = G2::zero();
        assert!(!pvss.verify_optimistic());
    }

    /// Check that if PVSS shares are tampered with, the full verification fails
    #[test]
    fn test_verify_pvss_bad_shares() {
        let rng = &mut ark_std::test_rng();
        let dkg = setup_dkg(0);
        let s = ScalarField::rand(rng);
        let pvss = Pvss::<EllipticCurve>::new(&s, &dkg, rng).unwrap();

        // So far, everything works
        assert!(pvss.verify_optimistic());
        assert!(pvss.verify_full(&dkg));

        // Now, we're going to tamper with the PVSS shares
        let mut bad_pvss = pvss;
        bad_pvss.shares[0] = G2::zero();

        // Optimistic verification should not catch this issue
        assert!(bad_pvss.verify_optimistic());
        // Full verification should catch this issue
        assert!(!bad_pvss.verify_full(&dkg));
    }

    /// Check that happy flow of aggregating PVSS transcripts
    /// Should have the correct form and validations pass
    #[test]
    fn test_aggregate_pvss() {
        let dkg = setup_dealt_dkg();
        let aggregate = aggregate(&dkg);
        //check that a polynomial of the correct degree was created
        assert_eq!(
            aggregate.coeffs.len(),
            dkg.params.security_threshold as usize
        );
        // check that the correct number of shares were created
        assert_eq!(aggregate.shares.len(), dkg.validators.len());
        // check that the optimistic verify returns true
        assert!(aggregate.verify_optimistic());
        // check that the full verify returns true
        assert!(aggregate.verify_full(&dkg));
        // check that the verification of aggregation passes
        assert_eq!(
            aggregate.verify_aggregation(&dkg).expect("Test failed"),
            dkg.validators.len() as u32
        );
    }

    /// Check that if the aggregated pvss transcript has an
    /// incorrect constant term, the verification fails
    #[test]
    fn test_verify_aggregation_fails_if_constant_term_wrong() {
        let dkg = setup_dealt_dkg();
        let mut aggregated = aggregate(&dkg);
        while aggregated.coeffs[0] == G1::zero() {
            let dkg = setup_dkg(0);
            aggregated = aggregate(&dkg);
        }
        aggregated.coeffs[0] = G1::zero();
        assert_eq!(
            aggregated
                .verify_aggregation(&dkg)
                .expect_err("Test failed")
                .to_string(),
            "Transcript aggregate doesn't match the received PVSS instances"
        )
    }
}
