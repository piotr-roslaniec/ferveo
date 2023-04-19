pub mod api;
pub mod dkg;
pub mod primitives;
mod vss;

pub use dkg::*;
use group_threshold_cryptography as tpke;
pub use primitives::*;
pub use vss::*;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Threshold encryption error
    #[error("Threshold encryption error")]
    ThresholdEncryptionError(#[from] tpke::Error),

    /// Number of shares parameter must be a power of two
    #[error("Number of shares parameter must be a power of two. Got {0}")]
    InvalidShareNumberParameter(u32),

    /// DKG is not in a valid state to deal PVSS shares
    #[error("Invalid DKG state to deal PVSS shares")]
    InvalidDkgStateToDeal,

    /// DKG is not in a valid state to aggregate PVSS transcripts
    #[error("Invalid DKG state to aggregate PVSS transcripts")]
    InvalidDkgStateToAggregate,

    /// DKG is not in a valid state to verify PVSS transcripts
    #[error("Invalid DKG state to verify PVSS transcripts")]
    InvalidDkgStateToVerify,

    /// DKG is not in a valid state to ingest PVSS transcripts
    #[error("Invalid DKG state to ingest PVSS transcripts")]
    InvalidDkgStateToIngest,

    /// DKG validator set must contain the validator with the given address
    #[error("Expected validator to be a part of the DKG validator set: {0}")]
    ValidatorNotInSet(String),

    /// DKG received an unknown dealer. Dealer must be the part of the DKG validator set.
    #[error("DKG received an unknown dealer: {0}")]
    UnknownDealer(String),

    /// DKG received a PVSS transcript from a dealer that has already been dealt.
    #[error("DKG received a PVSS transcript from a dealer that has already been dealt: {0}")]
    DuplicateDealer(String),

    /// DKG received an invalid transcript for which optimistic verification failed
    #[error("DKG received an invalid transcript")]
    InvalidPvssTranscript,

    /// Aggregation failed because the DKG did not receive enough PVSS transcripts
    #[error(
        "Insufficient transcripts for aggregation (expected {0}, got {1})"
    )]
    InsufficientTranscriptsForAggregate(u32, u32),

    /// Failed to derive a valid final key for the DKG
    #[error("Failed to derive a valid final key for the DKG")]
    InvalidFinalKey,

    /// Not enough validators to perform the DKG for a given number of shares
    #[error("Not enough validators (expected {0}, got {1})")]
    InsufficientValidators(u32, u32),

    /// Transcript aggregate doesn't match the received PVSS instances
    #[error("Transcript aggregate doesn't match the received PVSS instances")]
    InvalidTranscriptAggregate,

    /// Serialization error
    #[error("Serialization error")]
    SerializationError(#[from] ark_serialize::SerializationError),
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod test_dkg_full {
    use std::collections::HashMap;

    use ark_bls12_381::{Bls12_381 as E, Fr, G1Affine};
    use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
    use ark_ff::{UniformRand, Zero};
    use ark_poly::EvaluationDomain;
    use ark_std::test_rng;
    use ferveo_common::Keypair;
    use group_threshold_cryptography as tpke;
    use group_threshold_cryptography::{
        Ciphertext, DecryptionSharePrecomputed, DecryptionShareSimple,
    };
    use itertools::{izip, Itertools};

    use super::*;
    use crate::dkg::pv::test_common::*;

    type TargetField = <E as Pairing>::TargetField;

    fn make_shared_secret_simple_tdec(
        dkg: &PubliclyVerifiableDkg<E>,
        aad: &[u8],
        ciphertext: &Ciphertext<E>,
        validator_keypairs: &[Keypair<E>],
    ) -> (
        PubliclyVerifiableSS<E, Aggregated>,
        Vec<DecryptionShareSimple<E>>,
        TargetField,
    ) {
        // Make sure validators are in the same order dkg is by comparing their public keys
        dkg.validators
            .iter()
            .zip_eq(validator_keypairs.iter())
            .for_each(|(v, k)| {
                assert_eq!(v.validator.public_key, k.public());
            });

        let pvss_aggregated = aggregate(dkg);

        let decryption_shares: Vec<DecryptionShareSimple<E>> =
            validator_keypairs
                .iter()
                .enumerate()
                .map(|(validator_index, validator_keypair)| {
                    pvss_aggregated
                        .make_decryption_share_simple(
                            ciphertext,
                            aad,
                            &validator_keypair.decryption_key,
                            validator_index,
                            &dkg.pvss_params.g_inv(),
                        )
                        .unwrap()
                })
                .collect();

        let domain = &dkg
            .domain
            .elements()
            .take(decryption_shares.len())
            .collect::<Vec<_>>();
        assert_eq!(domain.len(), decryption_shares.len());

        // TODO: Consider refactor this part into tpke::combine_simple and expose it
        //  as a public API in tpke::api

        let lagrange_coeffs = tpke::prepare_combine_simple::<E>(domain);
        let shared_secret = tpke::share_combine_simple::<E>(
            &decryption_shares,
            &lagrange_coeffs,
        );

        (pvss_aggregated, decryption_shares, shared_secret)
    }

    #[test]
    fn test_dkg_simple_tdec() {
        let rng = &mut test_rng();

        let dkg = setup_dealt_dkg_with_n_validators(3, 4);
        let msg: &[u8] = "abc".as_bytes();
        let aad: &[u8] = "my-aad".as_bytes();
        let public_key = dkg.final_key();
        let ciphertext =
            tpke::encrypt::<E>(msg, aad, &public_key, rng).unwrap();
        let validator_keypairs = gen_n_keypairs(4);

        let (_, _, shared_secret) = make_shared_secret_simple_tdec(
            &dkg,
            aad,
            &ciphertext,
            &validator_keypairs,
        );

        let plaintext = tpke::decrypt_with_shared_secret(
            &ciphertext,
            aad,
            &shared_secret,
            &dkg.pvss_params.g_inv(),
        )
        .unwrap();
        assert_eq!(plaintext, msg);
    }

    #[test]
    fn test_dkg_simple_tdec_precomputed() {
        let rng = &mut test_rng();

        let dkg = setup_dealt_dkg_with_n_validators(3, 4);
        let msg: &[u8] = "abc".as_bytes();
        let aad: &[u8] = "my-aad".as_bytes();
        let public_key = dkg.final_key();
        let ciphertext =
            tpke::encrypt::<E>(msg, aad, &public_key, rng).unwrap();
        let validator_keypairs = gen_n_keypairs(4);

        let pvss_aggregated = aggregate(&dkg);
        let domain_points = dkg
            .domain
            .elements()
            .take(validator_keypairs.len())
            .collect::<Vec<_>>();

        let decryption_shares: Vec<DecryptionSharePrecomputed<E>> =
            validator_keypairs
                .iter()
                .enumerate()
                .map(|(validator_index, validator_keypair)| {
                    pvss_aggregated
                        .make_decryption_share_simple_precomputed(
                            &ciphertext,
                            aad,
                            &validator_keypair.decryption_key,
                            validator_index,
                            &domain_points,
                            &dkg.pvss_params.g_inv(),
                        )
                        .unwrap()
                })
                .collect();

        let shared_secret =
            tpke::share_combine_precomputed::<E>(&decryption_shares);

        // Combination works, let's decrypt
        let plaintext = tpke::decrypt_with_shared_secret(
            &ciphertext,
            aad,
            &shared_secret,
            &dkg.pvss_params.g_inv(),
        )
        .unwrap();
        assert_eq!(plaintext, msg);
    }

    #[test]
    fn test_dkg_simple_tdec_share_verification() {
        let rng = &mut test_rng();

        let dkg = setup_dealt_dkg_with_n_validators(3, 4);
        let msg: &[u8] = "abc".as_bytes();
        let aad: &[u8] = "my-aad".as_bytes();
        let public_key = dkg.final_key();
        let ciphertext =
            tpke::encrypt::<E>(msg, aad, &public_key, rng).unwrap();
        let validator_keypairs = gen_n_keypairs(4);

        let (pvss_aggregated, decryption_shares, _) =
            make_shared_secret_simple_tdec(
                &dkg,
                aad,
                &ciphertext,
                &validator_keypairs,
            );

        izip!(
            &pvss_aggregated.shares,
            &validator_keypairs,
            &decryption_shares,
        )
        .for_each(
            |(aggregated_share, validator_keypair, decryption_share)| {
                assert!(decryption_share.verify(
                    aggregated_share,
                    &validator_keypair.public().encryption_key,
                    &dkg.pvss_params.h,
                    &ciphertext,
                ));
            },
        );

        // Testing red-path decryption share verification
        let decryption_share = decryption_shares[0].clone();

        // Should fail because of the bad decryption share
        let mut with_bad_decryption_share = decryption_share.clone();
        with_bad_decryption_share.decryption_share = TargetField::zero();
        assert!(!with_bad_decryption_share.verify(
            &pvss_aggregated.shares[0],
            &validator_keypairs[0].public().encryption_key,
            &dkg.pvss_params.h,
            &ciphertext,
        ));

        // Should fail because of the bad checksum
        let mut with_bad_checksum = decryption_share;
        with_bad_checksum.validator_checksum.checksum = G1Affine::zero();
        assert!(!with_bad_checksum.verify(
            &pvss_aggregated.shares[0],
            &validator_keypairs[0].public().encryption_key,
            &dkg.pvss_params.h,
            &ciphertext,
        ));
    }

    #[test]
    fn test_dkg_simple_tdec_share_recovery() {
        let rng = &mut test_rng();

        let mut dkg = setup_dealt_dkg_with_n_validators(3, 4);
        let msg: &[u8] = "abc".as_bytes();
        let aad: &[u8] = "my-aad".as_bytes();
        let public_key = &dkg.final_key();
        let ciphertext = tpke::encrypt::<E>(msg, aad, public_key, rng).unwrap();
        let mut validator_keypairs = gen_n_keypairs(4);

        // Create an initial shared secret
        let (_, _, old_shared_secret) = make_shared_secret_simple_tdec(
            &dkg,
            aad,
            &ciphertext,
            &validator_keypairs,
        );

        // Now, we're going to recover a new share at a random point and check that the shared secret is still the same

        // Our random point
        let x_r = Fr::rand(rng);

        // Remove one participant from the contexts and all nested structure
        let removed_validator = dkg.validators.pop().unwrap();
        validator_keypairs.pop();
        // Remember to remove one domain point too
        let mut domain_points = dkg.domain.elements().collect::<Vec<_>>();
        domain_points.pop().unwrap();

        // Each participant prepares an update for each other participant
        let share_updates = &dkg
            .validators
            .iter()
            .map(|p| {
                let deltas_i = tpke::prepare_share_updates_for_recovery::<E>(
                    &domain_points,
                    &dkg.pvss_params.h.into_affine(),
                    &x_r,
                    dkg.params.security_threshold as usize,
                    rng,
                );
                (p.share_index, deltas_i)
            })
            .collect::<HashMap<_, _>>();

        // Participants share updates and update their shares
        let pvss_aggregated = aggregate(&dkg);

        // Now, every participant separately:
        let updated_shares: Vec<_> = validator_keypairs
            .iter()
            .enumerate()
            .map(|(validator_index, validator_keypair)| {
                // Receives updates from other participants
                let updates_for_participant: Vec<_> = share_updates
                    .values()
                    .map(|updates| *updates.get(validator_index).unwrap())
                    .collect();

                // Creates updated private key shares
                pvss_aggregated.update_private_key_share_for_recovery(
                    &validator_keypair.decryption_key,
                    validator_index,
                    &updates_for_participant,
                )
            })
            .collect();

        // Now, we have to combine new share fragments into a new share
        let new_private_key_share =
            tpke::recover_share_from_updated_private_shares(
                &x_r,
                &domain_points,
                &updated_shares,
            );

        // Get decryption shares from remaining participants
        let mut decryption_shares: Vec<DecryptionShareSimple<E>> =
            validator_keypairs
                .iter()
                .enumerate()
                .map(|(validator_index, validator_keypair)| {
                    pvss_aggregated
                        .make_decryption_share_simple(
                            &ciphertext,
                            aad,
                            &validator_keypair.decryption_key,
                            validator_index,
                            &dkg.pvss_params.g_inv(),
                        )
                        .unwrap()
                })
                .collect();

        // Create a decryption share from a recovered private key share
        let new_validator_decryption_key = Fr::rand(rng);
        let validator_index = removed_validator.share_index;
        decryption_shares.push(
            DecryptionShareSimple::create(
                validator_index,
                &new_validator_decryption_key,
                &new_private_key_share,
                &ciphertext,
                aad,
                &dkg.pvss_params.g_inv(),
            )
            .unwrap(),
        );

        let lagrange = tpke::prepare_combine_simple::<E>(&domain_points);
        let new_shared_secret =
            tpke::share_combine_simple::<E>(&decryption_shares, &lagrange);

        assert_eq!(old_shared_secret, new_shared_secret);
    }

    #[test]
    fn simple_tdec_share_refreshing() {
        let rng = &mut test_rng();
        let dkg = setup_dealt_dkg_with_n_validators(3, 4);

        let msg: &[u8] = "abc".as_bytes();
        let aad: &[u8] = "my-aad".as_bytes();
        let public_key = dkg.final_key();
        let ciphertext =
            tpke::encrypt::<E>(msg, aad, &public_key, rng).unwrap();

        let validator_keypairs = gen_n_keypairs(4);
        let pvss_aggregated = aggregate(&dkg);

        // Create an initial shared secret
        let (_, _, old_shared_secret) = make_shared_secret_simple_tdec(
            &dkg,
            aad,
            &ciphertext,
            &validator_keypairs,
        );

        // Now, we're going to refresh the shares and check that the shared secret is the same

        // Dealer computes a new random polynomial with constant term x_r = 0
        let polynomial = tpke::make_random_polynomial_at::<E>(
            dkg.params.security_threshold as usize,
            &Fr::zero(),
            rng,
        );

        // Dealer shares the polynomial with participants

        // Participants computes new decryption shares
        let new_decryption_shares: Vec<DecryptionShareSimple<E>> =
            validator_keypairs
                .iter()
                .enumerate()
                .map(|(validator_index, validator_keypair)| {
                    pvss_aggregated
                        .refresh_decryption_share(
                            &ciphertext,
                            aad,
                            &validator_keypair.decryption_key,
                            validator_index,
                            &polynomial,
                            &dkg,
                        )
                        .unwrap()
                })
                .collect();

        // Create a new shared secret
        let domain = &dkg.domain.elements().collect::<Vec<_>>();
        // TODO: Combine `tpke::prepare_combine_simple` and `tpke::share_combine_simple` into
        //  one function and expose it in the tpke::api?
        let lagrange_coeffs = tpke::prepare_combine_simple::<E>(domain);
        let new_shared_secret = tpke::share_combine_simple::<E>(
            &new_decryption_shares,
            &lagrange_coeffs,
        );

        assert_eq!(old_shared_secret, new_shared_secret);
    }
}
