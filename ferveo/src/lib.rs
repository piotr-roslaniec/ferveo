#![allow(unused_imports)]

pub mod dkg;
pub mod msg;
pub mod vss;

pub mod primitives;

use itertools::{izip, zip_eq};
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

#[cfg(test)]
mod test_dkg_full {
    use super::*;

    use crate::dkg::pv::test_common::*;
    use ark_bls12_381::Bls12_381 as EllipticCurve;
    use ark_ff::UniformRand;
    use ferveo_common::{TendermintValidator, ValidatorSet};
    use group_threshold_cryptography as tpke;
    use itertools::{zip_eq, Itertools};

    type E = ark_bls12_381::Bls12_381;

    #[test]
    fn test_dkg_simple_decryption_variant_with_single_validator() {
        let rng = &mut ark_std::test_rng();
        // Make sure that the number of shares is a power of 2 for the FFT to work (Radix-2 FFT domain is being used)
        let dkg = setup_dealt_dkg_with_n_validators(1, 1, 1);

        // First, we encrypt a message using a DKG public key
        let msg: &[u8] = "abc".as_bytes();
        let aad: &[u8] = "my-aad".as_bytes();
        let public_key = dkg.final_key(); // sum of g^coeffs[0] for all validators
        let ciphertext = tpke::encrypt::<_, E>(msg, aad, &public_key, rng);

        let validator_keypair = gen_n_keypairs(1)[0];
        let encrypted_shares = batch_to_projective(&dkg.vss.get(&0).unwrap().shares);

        let decryption_shares =
            encrypted_shares.iter().map(|encrypted_share| {
                // Decrypt private key shares https://nikkolasg.github.io/ferveo/pvss.html#validator-decryption-of-private-key-shares
                let z_i = encrypted_share.mul(validator_keypair.decryption_key.inverse().unwrap().into_repr());
                let u = ciphertext.commitment;
                let c_i = E::pairing(u, z_i);
                c_i
            })
            .collect::<Vec<_>>();

        let shares_x = &dkg
            .domain
            .elements()
            .take(decryption_shares.len())
            .collect::<Vec<_>>();
        let lagrange_coeffs = tpke::prepare_combine_simple::<E>(&shares_x);

        let s = tpke::share_combine_simple::<E>(&decryption_shares, &lagrange_coeffs);

        let plaintext =
            tpke::checked_decrypt_with_shared_secret(&ciphertext, aad, &s);
        assert_eq!(plaintext, msg);
    }

    /// Test happy flow for a full DKG with simple threshold decryption variant
    #[test]
    #[ignore]
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
        assert!(aggregate.verify_full(&dkg));
        // check that the verification of aggregation passes
        assert_eq!(aggregate.verify_aggregation(&dkg).expect("Test failed"), 4);

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
        let aggregate = aggregate_for_decryption(&dkg);

        // Each validator attempts to aggregate and decrypt the secret shares
        let decryption_shares = zip_eq(validator_keypairs, aggregate)
            .map(|(keypair, encrypted_shares)| {
                let z_i = encrypted_shares.mul(keypair.decryption_key);
                let u = ciphertext.commitment;
                let c_i = E::pairing(u, z_i);
                c_i
            })
            .collect::<Vec<_>>();

        let shares_x = &dkg
            .domain
            .elements()
            .take(decryption_shares.len())
            .collect::<Vec<_>>();
        let lagrange_coeffs = tpke::prepare_combine_simple::<E>(&shares_x);

        let s = tpke::share_combine_simple::<E>(&decryption_shares, &lagrange_coeffs);

        let plaintext =
            tpke::checked_decrypt_with_shared_secret(&ciphertext, aad, &s);
        assert_eq!(plaintext, msg);
    }
}
