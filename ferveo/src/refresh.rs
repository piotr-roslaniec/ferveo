use std::{ops::Mul, usize};

use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::Zero;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use group_threshold_cryptography as tpke;
use itertools::zip_eq;
use rand_core::RngCore;
use tpke::{lagrange_basis_at, PrivateKeyShare};

/// From PSS paper, section 4.2.1, (https://link.springer.com/content/pdf/10.1007/3-540-44750-4_27.pdf)
pub fn prepare_share_updates_for_recovery<E: Pairing>(
    domain_points: &[E::ScalarField],
    h: &E::G2Affine,
    x_r: &E::ScalarField,
    threshold: usize,
    rng: &mut impl RngCore,
) -> Vec<E::G2> {
    // Generate a new random polynomial with constant term x_r
    let d_i = make_random_polynomial_at::<E>(threshold, x_r, rng);

    // Now, we need to evaluate the polynomial at each of participants' indices
    domain_points
        .iter()
        .map(|x_i| {
            let eval = d_i.evaluate(x_i);
            h.mul(eval)
        })
        .collect()
}

/// From PSS paper, section 4.2.3, (https://link.springer.com/content/pdf/10.1007/3-540-44750-4_27.pdf)
pub fn update_share_for_recovery<E: Pairing>(
    private_key_share: &PrivateKeyShare<E>,
    share_updates: &[E::G2],
) -> PrivateKeyShare<E> {
    let private_key_share = share_updates
        .iter()
        .fold(
            private_key_share.private_key_share.into_group(),
            |acc, delta| acc + delta,
        )
        .into_affine();
    PrivateKeyShare { private_key_share }
}

/// From the PSS paper, section 4.2.4, (https://link.springer.com/content/pdf/10.1007/3-540-44750-4_27.pdf)
pub fn recover_share_from_updated_private_shares<E: Pairing>(
    x_r: &E::ScalarField,
    domain_points: &[E::ScalarField],
    updated_private_shares: &[PrivateKeyShare<E>],
) -> PrivateKeyShare<E> {
    // Interpolate new shares to recover y_r
    let lagrange = lagrange_basis_at::<E>(domain_points, x_r);
    let prods = zip_eq(updated_private_shares, lagrange)
        .map(|(y_j, l)| y_j.private_key_share.mul(l));
    let y_r = prods.fold(E::G2::zero(), |acc, y_j| acc + y_j);

    PrivateKeyShare {
        private_key_share: y_r.into_affine(),
    }
}

pub fn make_random_polynomial_with_root<E: Pairing>(
    threshold: usize,
    root: &E::ScalarField,
    rng: &mut impl RngCore,
) -> DensePolynomial<E::ScalarField> {
    // [][threshold-1]
    let mut threshold_poly =
        DensePolynomial::<E::ScalarField>::rand(threshold - 1, rng);

    // [0..][threshold]
    threshold_poly[0] = E::ScalarField::zero();

    // Now, we calculate d_i_0
    // This is the term that will "zero out" the polynomial at x_r, d_i(x_r) = 0
    let d_i_0 = E::ScalarField::zero() - threshold_poly.evaluate(root);
    threshold_poly[0] = d_i_0;

    // Evaluating the polynomial at the root should result in 0
    debug_assert!(threshold_poly.evaluate(root) == E::ScalarField::zero());
    debug_assert!(threshold_poly.coeffs.len() == threshold);

    threshold_poly
}

// TODO: Expose a method to create a proper decryption share after refreshing
pub fn refresh_private_key_share<E: Pairing>(
    h: &E::G2,
    domain_point: &E::ScalarField,
    polynomial: &DensePolynomial<E::ScalarField>,
    validator_private_key_share: &PrivateKeyShare<E>,
) -> PrivateKeyShare<E> {
    let evaluated_polynomial = polynomial.evaluate(domain_point);
    let share_update = h.mul(evaluated_polynomial);
    let updated_share =
        validator_private_key_share.private_key_share.into_group()
            + share_update;
    PrivateKeyShare {
        private_key_share: updated_share.into_affine(),
    }
}

#[cfg(test)]
mod tests_refresh {

    use std::{collections::HashMap, ops::Mul};

    use ark_bls12_381::Fr;
    use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
    // use ark_ff::Zero;
    use ark_std::{test_rng, UniformRand, Zero};
    // use ferveo_common::{FromBytes, ToBytes};
    use rand_core::RngCore;

    // use tpke::test_common::{make_shared_secret};

    type E = ark_bls12_381::Bls12_381;
    // type TargetField = <E as Pairing>::TargetField;
    type ScalarField = <E as Pairing>::ScalarField;

    use crate::{
        make_random_polynomial_with_root, prepare_share_updates_for_recovery,
        recover_share_from_updated_private_shares, refresh_private_key_share,
        update_share_for_recovery,
    };

    use group_threshold_cryptography::{
        encrypt,
        test_common::{make_shared_secret, setup_simple},
        CiphertextHeader, DecryptionShareSimple,
        PrivateDecryptionContextSimple, PrivateKeyShare, SecretBox,
        SharedSecret,
    };

    fn make_new_share_fragments<R: RngCore>(
        rng: &mut R,
        threshold: usize,
        x_r: &Fr,
        remaining_participants: &[PrivateDecryptionContextSimple<E>],
    ) -> Vec<PrivateKeyShare<E>> {
        // Each participant prepares an update for each other participant
        let domain_points = remaining_participants[0]
            .public_decryption_contexts
            .iter()
            .map(|c| c.domain)
            .collect::<Vec<_>>();
        let h = remaining_participants[0].public_decryption_contexts[0].h;
        let share_updates = remaining_participants
            .iter()
            .map(|p| {
                let deltas_i = prepare_share_updates_for_recovery::<E>(
                    &domain_points,
                    &h,
                    x_r,
                    threshold,
                    rng,
                );
                (p.index, deltas_i)
            })
            .collect::<HashMap<_, _>>();

        // Participants share updates and update their shares
        let new_share_fragments: Vec<_> = remaining_participants
            .iter()
            .map(|p| {
                // Current participant receives updates from other participants
                let updates_for_participant: Vec<_> = share_updates
                    .values()
                    .map(|updates| *updates.get(p.index).unwrap())
                    .collect();

                // And updates their share
                update_share_for_recovery::<E>(
                    &p.private_key_share,
                    &updates_for_participant,
                )
            })
            .collect();

        new_share_fragments
    }

    fn make_shared_secret_from_contexts<E: Pairing>(
        contexts: &[PrivateDecryptionContextSimple<E>],
        ciphertext_header: &CiphertextHeader<E>,
        aad: &[u8],
    ) -> SharedSecret<E> {
        let decryption_shares: Vec<_> = contexts
            .iter()
            .map(|c| c.create_share(ciphertext_header, aad).unwrap())
            .collect();
        make_shared_secret(
            &contexts[0].public_decryption_contexts,
            &decryption_shares,
        )
    }

    /// Ñ parties (where t <= Ñ <= N) jointly execute a "share recovery" algorithm, and the output is 1 new share.
    /// The new share is intended to restore a previously existing share, e.g., due to loss or corruption.
    #[test]
    fn tdec_simple_variant_share_recovery_at_selected_point() {
        let rng = &mut test_rng();
        let shares_num = 16;
        let threshold = shares_num * 2 / 3;

        let (_, _, mut contexts) =
            setup_simple::<E>(threshold, shares_num, rng);

        // Prepare participants

        // First, save the soon-to-be-removed participant
        let selected_participant = contexts.pop().unwrap();
        let x_r = selected_participant
            .public_decryption_contexts
            .last()
            .unwrap()
            .domain;
        let original_private_key_share = selected_participant.private_key_share;

        // Remove one participant from the contexts and all nested structures
        let mut remaining_participants = contexts;
        for p in &mut remaining_participants {
            p.public_decryption_contexts.pop().unwrap();
        }

        // Each participant prepares an update for each other participant, and uses it to create a new share fragment
        let new_share_fragments = make_new_share_fragments(
            rng,
            threshold,
            &x_r,
            &remaining_participants,
        );

        // Now, we have to combine new share fragments into a new share
        let domain_points = &remaining_participants[0]
            .public_decryption_contexts
            .iter()
            .map(|ctxt| ctxt.domain)
            .collect::<Vec<_>>();
        let new_private_key_share = recover_share_from_updated_private_shares(
            &x_r,
            domain_points,
            &new_share_fragments,
        );

        assert_eq!(new_private_key_share, original_private_key_share);
    }

    /// Ñ parties (where t <= Ñ <= N) jointly execute a "share recovery" algorithm, and the output is 1 new share.
    /// The new share is independent from the previously existing shares. We can use this to on-board a new participant into an existing cohort.
    #[test]
    fn tdec_simple_variant_share_recovery_at_random_point() {
        let rng = &mut test_rng();
        let shares_num = 16;
        let threshold = shares_num * 2 / 3;
        let msg = "my-msg".as_bytes().to_vec();
        let aad: &[u8] = "my-aad".as_bytes();

        let (pubkey, _, contexts) =
            setup_simple::<E>(threshold, shares_num, rng);
        let g_inv = &contexts[0].setup_params.g_inv;
        let ciphertext =
            encrypt::<E>(SecretBox::new(msg), aad, &pubkey, rng).unwrap();

        // Create an initial shared secret
        let old_shared_secret = make_shared_secret_from_contexts(
            &contexts,
            &ciphertext.header().unwrap(),
            aad,
        );

        // Now, we're going to recover a new share at a random point and check that the shared secret is still the same

        // Our random point
        let x_r = ScalarField::rand(rng);

        // Remove one participant from the contexts and all nested structures
        let mut remaining_participants = contexts.clone();
        remaining_participants.pop().unwrap();
        for p in &mut remaining_participants {
            p.public_decryption_contexts.pop().unwrap();
        }

        let new_share_fragments = make_new_share_fragments(
            rng,
            threshold,
            &x_r,
            &remaining_participants,
        );

        // Now, we have to combine new share fragments into a new share
        let domain_points = &remaining_participants[0]
            .public_decryption_contexts
            .iter()
            .map(|ctxt| ctxt.domain)
            .collect::<Vec<_>>();
        let new_private_key_share = recover_share_from_updated_private_shares(
            &x_r,
            domain_points,
            &new_share_fragments,
        );

        // Get decryption shares from remaining participants
        let mut decryption_shares: Vec<_> = remaining_participants
            .iter()
            .map(|c| {
                c.create_share(&ciphertext.header().unwrap(), aad).unwrap()
            })
            .collect();

        // Create a decryption share from a recovered private key share
        let new_validator_decryption_key = ScalarField::rand(rng);
        decryption_shares.push(
            DecryptionShareSimple::create(
                &new_validator_decryption_key,
                &new_private_key_share,
                &ciphertext.header().unwrap(),
                aad,
                g_inv,
            )
            .unwrap(),
        );

        // Creating a shared secret from remaining shares and the recovered one
        let new_shared_secret = make_shared_secret(
            &remaining_participants[0].public_decryption_contexts,
            &decryption_shares,
        );

        assert_eq!(old_shared_secret, new_shared_secret);
    }

    /// Ñ parties (where t <= Ñ <= N) jointly execute a "share refresh" algorithm.
    /// The output is M new shares (with M <= Ñ), with each of the M new shares substituting the
    /// original share (i.e., the original share is deleted).
    #[test]
    fn tdec_simple_variant_share_refreshing() {
        let rng = &mut test_rng();
        let shares_num = 16;
        let threshold = shares_num * 2 / 3;
        let msg = "my-msg".as_bytes().to_vec();
        let aad: &[u8] = "my-aad".as_bytes();

        let (pubkey, _, contexts) =
            setup_simple::<E>(threshold, shares_num, rng);
        let g_inv = &contexts[0].setup_params.g_inv;
        let pub_contexts = contexts[0].public_decryption_contexts.clone();
        let ciphertext =
            encrypt::<E>(SecretBox::new(msg), aad, &pubkey, rng).unwrap();

        // Create an initial shared secret
        let old_shared_secret = make_shared_secret_from_contexts(
            &contexts,
            &ciphertext.header().unwrap(),
            aad,
        );

        // Now, we're going to refresh the shares and check that the shared secret is the same

        // Dealer computes a new random polynomial with constant term x_r
        let polynomial = make_random_polynomial_with_root::<E>(
            threshold,
            &ScalarField::zero(),
            rng,
        );

        // Dealer shares the polynomial with participants

        // Participants computes new decryption shares
        let new_decryption_shares: Vec<_> = contexts
            .iter()
            .enumerate()
            .map(|(i, p)| {
                // Participant computes share updates and update their private key shares
                let private_key_share = refresh_private_key_share::<E>(
                    &p.setup_params.h.into_group(),
                    &p.public_decryption_contexts[i].domain,
                    &polynomial,
                    &p.private_key_share,
                );
                DecryptionShareSimple::create(
                    &p.validator_private_key,
                    &private_key_share,
                    &ciphertext.header().unwrap(),
                    aad,
                    g_inv,
                )
                .unwrap()
            })
            .collect();

        let new_shared_secret =
            make_shared_secret(&pub_contexts, &new_decryption_shares);

        assert_eq!(old_shared_secret, new_shared_secret);
    }
}
