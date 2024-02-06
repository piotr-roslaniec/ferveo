use std::{ops::Mul, usize};

use ark_ec::{pairing::Pairing, CurveGroup};
use ark_ff::Zero;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use ferveo_tdec::lagrange_basis_at;
use itertools::zip_eq;
use rand_core::RngCore;
use zeroize::ZeroizeOnDrop;

type InnerPrivateKeyShare<E> = ferveo_tdec::PrivateKeyShare<E>;

/// Private key share held by a participant in the DKG protocol.
#[derive(Debug, Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct PrivateKeyShare<E: Pairing>(pub InnerPrivateKeyShare<E>);

impl<E: Pairing> PrivateKeyShare<E> {
    /// From PSS paper, section 4.2.3, (https://link.springer.com/content/pdf/10.1007/3-540-44750-4_27.pdf)
    pub fn make_updated_key_share(
        &self,
        share_updates: &[impl PrivateKeyShareUpdate<E>],
    ) -> UpdatedPrivateKeyShare<E> {
        let updated_key_share = share_updates
            .iter()
            .fold(self.0.private_key_share, |acc, delta| {
                (acc + delta.inner().private_key_share).into()
            });
        let updated_key_share = InnerPrivateKeyShare {
            private_key_share: updated_key_share,
        };
        UpdatedPrivateKeyShare(updated_key_share)
    }

    /// From the PSS paper, section 4.2.4, (https://link.springer.com/content/pdf/10.1007/3-540-44750-4_27.pdf)
    pub fn recover_share_from_updated_private_shares(
        x_r: &E::ScalarField,
        domain_points: &[E::ScalarField],
        updated_private_shares: &[UpdatedPrivateKeyShare<E>],
    ) -> ferveo_tdec::PrivateKeyShare<E> {
        // Interpolate new shares to recover y_r
        let lagrange = lagrange_basis_at::<E>(domain_points, x_r);
        let prods = zip_eq(updated_private_shares, lagrange)
            .map(|(y_j, l)| y_j.0.private_key_share.mul(l));
        let y_r = prods.fold(E::G2::zero(), |acc, y_j| acc + y_j);
        ferveo_tdec::PrivateKeyShare {
            private_key_share: y_r.into_affine(),
        }
    }
}

/// An updated private key share, resulting from an intermediate step in a share recovery or refresh operation.
#[derive(Debug, Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct UpdatedPrivateKeyShare<E: Pairing>(InnerPrivateKeyShare<E>);

impl<E: Pairing> UpdatedPrivateKeyShare<E> {
    /// One-way conversion from `UpdatedPrivateKeyShare` to `PrivateKeyShare`.
    /// Use this method to eject from the `UpdatedPrivateKeyShare` type and use the resulting `PrivateKeyShare` in further operations.
    pub fn inner(&self) -> PrivateKeyShare<E> {
        PrivateKeyShare(self.0.clone())
    }
}

impl<E: Pairing> UpdatedPrivateKeyShare<E> {
    pub fn new(private_key_share: InnerPrivateKeyShare<E>) -> Self {
        Self(private_key_share)
    }
}

// TODO: Replace with an into trait?
/// Trait for types that can be used to update a private key share.
pub trait PrivateKeyShareUpdate<E: Pairing> {
    fn inner(&self) -> &InnerPrivateKeyShare<E>; // TODO: Should we return g2affine instead?
}

/// An update to a private key share generated by a participant in a share recovery operation.
#[derive(Debug, Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct ShareRecoveryUpdate<E: Pairing>(InnerPrivateKeyShare<E>);

impl<E: Pairing> PrivateKeyShareUpdate<E> for ShareRecoveryUpdate<E> {
    fn inner(&self) -> &InnerPrivateKeyShare<E> {
        &self.0
    }
}

impl<E: Pairing> ShareRecoveryUpdate<E> {
    /// From PSS paper, section 4.2.1, (https://link.springer.com/content/pdf/10.1007/3-540-44750-4_27.pdf)
    pub fn make_share_updates_for_recovery(
        domain_points: &[E::ScalarField],
        h: &E::G2Affine,
        x_r: &E::ScalarField,
        threshold: usize,
        rng: &mut impl RngCore,
    ) -> Vec<ShareRecoveryUpdate<E>> {
        // Update polynomial has root at x_r
        prepare_share_updates_with_root::<E>(
            domain_points,
            h,
            x_r,
            threshold,
            rng,
        )
        .iter()
        .map(|p| Self(p.clone()))
        .collect()
    }
}

/// An update to a private key share generated by a participant in a share refresh operation.
#[derive(Debug, Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct ShareRefreshUpdate<E: Pairing>(InnerPrivateKeyShare<E>);

impl<E: Pairing> PrivateKeyShareUpdate<E> for ShareRefreshUpdate<E> {
    fn inner(&self) -> &InnerPrivateKeyShare<E> {
        &self.0
    }
}

impl<E: Pairing> ShareRefreshUpdate<E> {
    /// From PSS paper, section 4.2.1, (https://link.springer.com/content/pdf/10.1007/3-540-44750-4_27.pdf)
    pub fn make_share_updates_for_refresh(
        domain_points: &[E::ScalarField],
        h: &E::G2Affine,
        threshold: usize,
        rng: &mut impl RngCore,
    ) -> Vec<ShareRefreshUpdate<E>> {
        // Update polynomial has root at 0
        prepare_share_updates_with_root::<E>(
            domain_points,
            h,
            &E::ScalarField::zero(),
            threshold,
            rng,
        )
        .iter()
        .cloned()
        .map(|p| ShareRefreshUpdate(p))
        .collect()
    }
}

/// Prepare share updates with a given root
/// This is a helper function for `ShareRecoveryUpdate::make_share_updates_for_recovery` and `ShareRefreshUpdate::make_share_updates_for_refresh`
/// It generates a new random polynomial with a defined root and evaluates it at each of the participants' indices.
/// The result is a list of share updates.
/// We represent the share updates as `InnerPrivateKeyShare` to avoid dependency on the concrete implementation of `PrivateKeyShareUpdate`.
fn prepare_share_updates_with_root<E: Pairing>(
    domain_points: &[E::ScalarField],
    h: &E::G2Affine,
    root: &E::ScalarField,
    threshold: usize,
    rng: &mut impl RngCore,
) -> Vec<InnerPrivateKeyShare<E>> {
    // Generate a new random polynomial with defined root
    let d_i = make_random_polynomial_with_root::<E>(threshold - 1, root, rng);

    // Now, we need to evaluate the polynomial at each of participants' indices
    domain_points
        .iter()
        .map(|x_i| {
            let eval = d_i.evaluate(x_i);
            h.mul(eval).into_affine()
        })
        .map(|p| InnerPrivateKeyShare {
            private_key_share: p,
        })
        .collect()
}

/// Generate a random polynomial with a given root
fn make_random_polynomial_with_root<E: Pairing>(
    degree: usize,
    root: &E::ScalarField,
    rng: &mut impl RngCore,
) -> DensePolynomial<E::ScalarField> {
    // [c_0, c_1, ..., c_{degree}] (Random polynomial)
    let mut poly = DensePolynomial::<E::ScalarField>::rand(degree, rng);

    // [0, c_1, ... , c_{degree}]  (We zeroize the free term)
    poly[0] = E::ScalarField::zero();

    // Now, we calculate a new free term so that `poly(root) = 0`
    let new_c_0 = E::ScalarField::zero() - poly.evaluate(root);
    poly[0] = new_c_0;

    // Evaluating the polynomial at the root should result in 0
    debug_assert!(poly.evaluate(root) == E::ScalarField::zero());
    debug_assert!(poly.coeffs.len() == degree + 1);

    poly
}

#[cfg(test)]
mod tests_refresh {
    use std::collections::HashMap;

    use ark_bls12_381::Fr;
    use ark_std::{test_rng, UniformRand, Zero};
    use ferveo_tdec::{
        test_common::setup_simple, PrivateDecryptionContextSimple,
    };
    use rand_core::RngCore;
    use test_case::test_matrix;

    use crate::{
        test_common::*, PrivateKeyShare, ShareRecoveryUpdate,
        ShareRefreshUpdate, UpdatedPrivateKeyShare,
    };

    fn make_updated_private_key_shares<R: RngCore>(
        rng: &mut R,
        threshold: usize,
        x_r: &Fr,
        remaining_participants: &[PrivateDecryptionContextSimple<E>],
    ) -> Vec<UpdatedPrivateKeyShare<E>> {
        // Each participant prepares an update for each other participant
        // TODO: Extract as parameter
        let domain_points = remaining_participants[0]
            .public_decryption_contexts
            .iter()
            .map(|c| c.domain)
            .collect::<Vec<_>>();
        let h = remaining_participants[0].public_decryption_contexts[0].h;
        let share_updates = remaining_participants
            .iter()
            .map(|p| {
                let deltas_i =
                    ShareRecoveryUpdate::make_share_updates_for_recovery(
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
        let updated_private_key_shares: Vec<_> = remaining_participants
            .iter()
            .map(|p| {
                // Current participant receives updates from other participants
                let updates_for_participant: Vec<_> = share_updates
                    .values()
                    .map(|updates| updates.get(p.index).cloned().unwrap())
                    .collect();

                // And updates their share
                // TODO: Remove wrapping after migrating to dkg based tests
                PrivateKeyShare(p.private_key_share.clone())
                    .make_updated_key_share(&updates_for_participant)
            })
            .collect();

        updated_private_key_shares
    }

    /// Ñ parties (where t <= Ñ <= N) jointly execute a "share recovery" algorithm, and the output is 1 new share.
    /// The new share is intended to restore a previously existing share, e.g., due to loss or corruption.
    #[test_matrix([4, 7, 11, 16])]
    fn tdec_simple_variant_share_recovery_at_selected_point(shares_num: usize) {
        let rng = &mut test_rng();
        let security_threshold = shares_num * 2 / 3;

        let (_, _, mut contexts) =
            setup_simple::<E>(security_threshold, shares_num, rng);

        // Prepare participants

        // First, save the soon-to-be-removed participant
        let selected_participant = contexts.pop().unwrap();
        let x_r = selected_participant
            .public_decryption_contexts
            .last()
            .unwrap()
            .domain;
        let original_private_key_share = selected_participant.private_key_share;

        // Remove the selected participant from the contexts and all nested structures
        let mut remaining_participants = contexts;
        for p in &mut remaining_participants {
            p.public_decryption_contexts.pop().unwrap();
        }

        // Each participant prepares an update for each other participant, and uses it to create a new share fragment
        let updated_private_key_shares = make_updated_private_key_shares(
            rng,
            security_threshold,
            &x_r,
            &remaining_participants,
        );

        // Now, we have to combine new share fragments into a new share
        let domain_points = &remaining_participants[0]
            .public_decryption_contexts
            .iter()
            .map(|ctxt| ctxt.domain)
            .collect::<Vec<_>>();
        let new_private_key_share =
            PrivateKeyShare::recover_share_from_updated_private_shares(
                &x_r,
                &domain_points[..security_threshold],
                &updated_private_key_shares[..security_threshold],
            );

        assert_eq!(new_private_key_share, original_private_key_share);

        // If we don't have enough private share updates, the resulting private share will be incorrect
        assert_eq!(domain_points.len(), updated_private_key_shares.len());
        let incorrect_private_key_share =
            PrivateKeyShare::recover_share_from_updated_private_shares(
                &x_r,
                &domain_points[..(security_threshold - 1)],
                &updated_private_key_shares[..(security_threshold - 1)],
            );

        assert_ne!(incorrect_private_key_share, original_private_key_share);
    }

    /// Ñ parties (where t <= Ñ <= N) jointly execute a "share recovery" algorithm, and the output is 1 new share.
    /// The new share is independent from the previously existing shares. We can use this to on-board a new participant into an existing cohort.
    #[test_matrix([4, 7, 11, 16])]
    fn tdec_simple_variant_share_recovery_at_random_point(shares_num: usize) {
        let rng = &mut test_rng();
        let threshold = shares_num * 2 / 3;

        let (_, shared_private_key, mut contexts) =
            setup_simple::<E>(threshold, shares_num, rng);

        // Prepare participants

        // Remove one participant from the contexts and all nested structures
        contexts.pop().unwrap();
        let mut remaining_participants = contexts.clone();
        for p in &mut remaining_participants {
            p.public_decryption_contexts.pop().unwrap();
        }

        // Now, we're going to recover a new share at a random point and check that the shared secret is still the same

        // Our random point
        let x_r = ScalarField::rand(rng);

        // Each participant prepares an update for each other participant, and uses it to create a new share fragment
        let share_recovery_fragmetns = make_updated_private_key_shares(
            rng,
            threshold,
            &x_r,
            &remaining_participants,
        );

        // Now, we have to combine new share fragments into a new share
        let domain_points = &mut remaining_participants[0]
            .public_decryption_contexts
            .iter()
            .map(|ctxt| ctxt.domain)
            .collect::<Vec<_>>();
        let recovered_private_key_share =
            PrivateKeyShare::recover_share_from_updated_private_shares(
                &x_r,
                &domain_points[..threshold],
                &share_recovery_fragmetns[..threshold],
            );

        let mut private_shares = contexts
            .iter()
            .cloned()
            .map(|ctxt| ctxt.private_key_share)
            .collect::<Vec<_>>();

        // Finally, let's recreate the shared private key from some original shares and the recovered one
        domain_points.push(x_r);
        private_shares.push(recovered_private_key_share);
        // This is a workaround for a type mismatch - We need to convert the private shares to updated private shares
        // This is just to test that we are able to recover the shared private key from the updated private shares
        let updated_private_key_shares = private_shares
            .iter()
            .cloned()
            .map(UpdatedPrivateKeyShare::new)
            .collect::<Vec<_>>();
        let start_from = shares_num - threshold;
        let new_shared_private_key =
            PrivateKeyShare::recover_share_from_updated_private_shares(
                &ScalarField::zero(),
                &domain_points[start_from..],
                &updated_private_key_shares[start_from..],
            );

        assert_eq!(shared_private_key, new_shared_private_key);
    }

    /// Ñ parties (where t <= Ñ <= N) jointly execute a "share refresh" algorithm.
    /// The output is M new shares (with M <= Ñ), with each of the M new shares substituting the
    /// original share (i.e., the original share is deleted).
    #[test_matrix([4, 7, 11, 16])]
    fn tdec_simple_variant_share_refreshing(shares_num: usize) {
        let rng = &mut test_rng();
        let threshold = shares_num * 2 / 3;

        let (_, private_key_share, contexts) =
            setup_simple::<E>(threshold, shares_num, rng);

        let domain_points = &contexts[0]
            .public_decryption_contexts
            .iter()
            .map(|ctxt| ctxt.domain)
            .collect::<Vec<_>>();
        let h = contexts[0].public_decryption_contexts[0].h;

        // Each participant prepares an update for each other participant:
        let share_updates = contexts
            .iter()
            .map(|p| {
                let deltas_i =
                    ShareRefreshUpdate::<E>::make_share_updates_for_refresh(
                        domain_points,
                        &h,
                        threshold,
                        rng,
                    );
                (p.index, deltas_i)
            })
            .collect::<HashMap<_, _>>();

        // Participants "refresh" their shares with the updates from each other:
        let refreshed_shares: Vec<_> = contexts
            .iter()
            .map(|p| {
                // Current participant receives updates from other participants
                let updates_for_participant: Vec<_> = share_updates
                    .values()
                    .map(|updates| updates.get(p.index).cloned().unwrap())
                    .collect();

                // And creates a new, refreshed share
                // TODO: Remove wrapping after migrating to dkg based tests
                PrivateKeyShare(p.private_key_share.clone())
                    .make_updated_key_share(&updates_for_participant)
            })
            .collect();

        // Finally, let's recreate the shared private key from the refreshed shares
        let new_shared_private_key =
            PrivateKeyShare::recover_share_from_updated_private_shares(
                &ScalarField::zero(),
                &domain_points[..threshold],
                &refreshed_shares[..threshold],
            );

        assert_eq!(private_key_share, new_shared_private_key);
    }
}
