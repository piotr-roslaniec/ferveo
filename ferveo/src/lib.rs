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
    use ark_bls12_381::{Bls12_381 as EllipticCurve, Bls12_381, G2Projective};
    use ark_ec::bls12::G2Affine;
    use ark_ff::{Fp12, UniformRand};
    use ferveo_common::{Keypair, TendermintValidator, ValidatorSet};
    use group_threshold_cryptography as tpke;
    use group_threshold_cryptography::Ciphertext;
    use itertools::{zip_eq, Itertools};

    type E = Bls12_381;

    #[test]
    fn test_dkg_simple_decryption_variant_single_validator() {
        let rng = &mut ark_std::test_rng();
        let dkg = setup_dealt_dkg_with_n_validators(1, 1);

        let msg: &[u8] = "abc".as_bytes();
        let aad: &[u8] = "my-aad".as_bytes();
        let public_key = dkg.final_key();

        let ciphertext = tpke::encrypt::<_, E>(msg, aad, &public_key, rng);

        let aggregate = aggregate_for_decryption(&dkg);
        // Aggregate contains only one set of shares
        assert_eq!(aggregate, dkg.vss.get(&0).unwrap().shares);

        let validator_keypairs = gen_n_keypairs(1);
        let decryption_shares =
            make_decryption_shares(&ciphertext, validator_keypairs, aggregate);

        let shares_x = &dkg
            .domain
            .elements()
            .take(decryption_shares.len())
            .collect::<Vec<_>>();
        let lagrange_coeffs = tpke::prepare_combine_simple::<E>(shares_x);

        let shared_secret = tpke::share_combine_simple::<E>(
            &decryption_shares,
            &lagrange_coeffs,
        );

        let plaintext = tpke::checked_decrypt_with_shared_secret(
            &ciphertext,
            aad,
            &shared_secret,
        );
        assert_eq!(plaintext, msg);
    }

    #[test]
    fn test_dkg_simple_decryption_variant() {
        let rng = &mut ark_std::test_rng();
        let dkg = setup_dealt_dkg_with_n_validators(3, 4);

        let msg: &[u8] = "abc".as_bytes();
        let aad: &[u8] = "my-aad".as_bytes();
        let public_key = dkg.final_key();
        let ciphertext = tpke::encrypt::<_, E>(msg, aad, &public_key, rng);

        let aggregate = aggregate_for_decryption(&dkg);

        // TODO: Before creating decryption shares, check ciphertext validity
        // See: https://nikkolasg.github.io/ferveo/tpke.html#to-validate-ciphertext-for-ind-cca2-security

        let validator_keypairs = gen_n_keypairs(4);
        // Make sure validators are in the same order dkg is by comparing their public keys
        dkg.validators
            .iter()
            .zip_eq(validator_keypairs.iter())
            .for_each(|(v, k)| {
                assert_eq!(v.validator.public_key, k.public());
            });
        let decryption_shares =
            make_decryption_shares(&ciphertext, validator_keypairs, aggregate);

        let shares_x = &dkg
            .domain
            .elements()
            .take(decryption_shares.len())
            .collect::<Vec<_>>();
        let lagrange_coeffs = tpke::prepare_combine_simple::<E>(shares_x);

        let shared_secret = tpke::share_combine_simple::<E>(
            &decryption_shares,
            &lagrange_coeffs,
        );

        let plaintext = tpke::checked_decrypt_with_shared_secret(
            &ciphertext,
            aad,
            &shared_secret,
        );
        assert_eq!(plaintext, msg);
    }
}
