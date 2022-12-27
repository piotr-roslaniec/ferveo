#![allow(unused_imports)]
pub mod dkg;
pub mod msg;
pub mod vss;

pub mod primitives;
use itertools::izip;
pub use primitives::*;

use ferveo_common::Rng;

use crate::dkg::*;
use crate::msg::*;

use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{Field, One, Zero};
use ark_poly::{
    polynomial::univariate::DensePolynomial, polynomial::UVPolynomial,
    EvaluationDomain,
};
use ark_std::{end_timer, start_timer};
use serde::*;

use anyhow::{anyhow, Result};
pub use dkg::*;
pub use msg::*;
pub use vss::*;

use ark_ec::msm::FixedBaseMSM;
use ark_ec::PairingEngine;
use ark_ff::PrimeField;

use measure_time::print_time;

pub fn share_combine_simple<E: PairingEngine>(
    shares: &[E::Fqk],
    lagrange: &[E::Fr],
    // prepared_key_shares: &[E::G2Affine],
) -> E::Fqk {
    let mut product_of_shares = E::Fqk::one();

    // Sum of C_i^{L_i}
    for (c_i, alpha_i) in izip!(shares.iter(), lagrange.iter()) {
        // Exponentiation by alpha_i
        let ss = c_i.pow(alpha_i.into_repr());
        product_of_shares *= ss;
    }

    product_of_shares
}

#[cfg(test)]
mod test_dkg_full {
    use super::*;

    use crate::dkg::pv::test_common::*;
    use ark_bls12_381::Bls12_381 as EllipticCurve;
    use ark_ff::UniformRand;
    use ferveo_common::{TendermintValidator, ValidatorSet};
    use group_threshold_cryptography as tpke;

    type E = ark_bls12_381::Bls12_381;

    /// Test happy flow for a full DKG with simple threshold decryption variant
    #[test]
    fn test_dkg_simple_decryption_variant() {
        //
        // The following is copied from other tests
        //

        let rng = &mut ark_std::test_rng();
        let dkg = setup_dealt_dkg();
        let aggregate = aggregate(&dkg);
        // check that a polynomial of the correct degree was created
        assert_eq!(aggregate.coeffs.len(), 5);
        // check that the correct number of shares were created
        assert_eq!(aggregate.shares.len(), 4);
        // check that the optimistic verify returns true
        assert!(aggregate.verify_optimistic());
        // check that the full verify returns true
        assert!(aggregate.verify_full(&dkg, rng));
        // check that the verification of aggregation passes
        assert_eq!(
            aggregate
                .verify_aggregation(&dkg, rng)
                .expect("Test failed"),
            6
        );

        //
        // Now, we start the actual test
        //

        // At this point, we have a DKG that has been dealt and aggregated
        // We now want to test the decryption of a message

        // First, we encrypt a message using a DKG public key

        let msg: &[u8] = "abc".as_bytes();
        let aad: &[u8] = "my-aad".as_bytes();
        let public_key = dkg.final_key();
        let ciphertext = tpke::encrypt::<_, E>(msg, aad, &public_key, rng);

        // TODO: Update test utils so that we can easily get a validator keypair for each validator
        let validator_keypairs = gen_keypairs();

        // TODO: Check ciphertext validity, https://nikkolasg.github.io/ferveo/tpke.html#to-validate-ciphertext-for-ind-cca2-security

        // Each validator computes a decryption share
        let decryption_shares = validator_keypairs.iter().map(|keypair| {
            // let decryption_shares = aggregate
            let decryption_shares = aggregate
               .shares[0]
                .iter()
                .map(|share| {
                    // TODO: In simple decryption variant, we only have one share per validator
                    // assert_eq!(z_i.len(), 1);
                    let z_i = share.mul(keypair.decryption_key);
                    
                    // Validator decryption of private key shares, https://nikkolasg.github.io/ferveo/pvss.html#validator-decryption-of-private-key-shares
                    let u = ciphertext.commitment;
                    let c_i = E::pairing(u, z_i);
                    c_i
                })
                .collect::<Vec<_>>();

            // TODO: In simple decryption variant, we only have one share per validator
            // assert_eq!(decryption_shares.len(), 1);
            // decryption_shares[0]
            decryption_shares
        });


        // let s = share_combine_simple::<E>(&aggregate.shares, &aggregate.coeffs);

        /*
        TODO: This variant seems to be outdated/unused in simple threshold decryption variant

        // Following section 4.4.8 of the paper, we need to compute the following:
        let decryption_shares = validator_keypairs.iter().map(|validator| {
            // TODO: Check the validity of (U, W)

            // Compute the decryption share D_{i,j} = [dk_j^{-1}]*U_i
            // We only have one U in this case
            let u = ciphertext.commitment;
            let dk_j = validator.decryption_key;
            let dk_j_inv = dk_j.inverse().unwrap();
            let d_ij = u.mul(dk_j_inv);
            d_ij
        });
        */
    }
}
