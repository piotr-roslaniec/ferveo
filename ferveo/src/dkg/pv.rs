use crate::*;
use anyhow::Context;
use ark_ec::bn::TwistType::D;
use ark_ec::PairingEngine;
use ark_ff::Field;
use ark_serialize::*;
use ark_std::{end_timer, start_timer};
use ferveo_common::{PublicKey, TendermintValidator, ValidatorSet};
use std::collections::BTreeMap;

/// The DKG context that holds all of the local state for participating in the DKG
#[derive(Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PubliclyVerifiableDkg<E: PairingEngine> {
    pub params: Params,
    pub pvss_params: PubliclyVerifiableParams<E>,
    pub session_keypair: ferveo_common::Keypair<E>,
    pub validators: Vec<ferveo_common::Validator<E>>,
    pub vss: BTreeMap<u32, PubliclyVerifiableSS<E>>,
    pub domain: ark_poly::Radix2EvaluationDomain<E::Fr>,
    pub state: DkgState<E>,
    pub me: usize,
    pub window: (u32, u32),
}

impl<E: PairingEngine> PubliclyVerifiableDkg<E> {
    /// Create a new DKG context to participate in the DKG
    /// Every identity in the DKG is linked to an ed25519 public key;
    /// `validator_set`: The set of validators and their respective voting powers
    ///                  *IMPORTANT: this set should be reverse sorted*
    /// `params` contains the parameters of the DKG such as number of shares
    /// `me` the validator creating this instance
    /// `session_keypair` the keypair for `me`
    pub fn new(
        validator_set: ValidatorSet<E>,
        params: Params,
        me: TendermintValidator<E>,
        session_keypair: ferveo_common::Keypair<E>,
    ) -> Result<Self> {
        use ark_std::UniformRand;
        let domain = ark_poly::Radix2EvaluationDomain::<E::Fr>::new(
            params.shares_num as usize,
        )
        .ok_or_else(|| anyhow!("unable to construct domain"))?;

        // keep track of the owner of this instance in the validator set
        let me = validator_set
            .validators
            .iter()
            .position(|probe| me.address == probe.address)
            .context(
                "could not find this validator in the provided validator set",
            )?;

        let validators = make_validators(validator_set);

        // TODO: Remove my_partition
        let my_partition =
            params.retry_after * (2 * me as u32 / params.retry_after);
        Ok(Self {
            session_keypair,
            params,
            pvss_params: PubliclyVerifiableParams::<E> {
                g: E::G1Projective::prime_subgroup_generator(),
                h: E::G2Projective::prime_subgroup_generator(),
            },
            vss: BTreeMap::new(),
            domain,
            state: DkgState::Sharing {
                accumulated_shares: 0,
                block: 0,
            },
            me,
            validators,
            // TODO: Remove window
            window: (my_partition, my_partition + params.retry_after),
        })
    }

    /// Increment the number of blocks processed since the DKG protocol
    /// began if we are still sharing PVSS transcripts.
    ///
    /// Returns a value indicating if we should issue a PVSS transcript
    pub fn increase_block(&mut self) -> PvssScheduler {
        match self.state {
            DkgState::Sharing { ref mut block, .. }
                if !self.vss.contains_key(&(self.me as u32)) =>
            {
                *block += 1;
                // if our scheduled window begins, issue PVSS
                if self.window.0 + 1 == *block {
                    PvssScheduler::Issue
                } else if &self.window.1 < block {
                    // reset the window during which we try to get our
                    // PVSS on chain
                    *block = self.window.0 + 1;
                    // reissue PVSS
                    PvssScheduler::Issue
                } else {
                    PvssScheduler::Wait
                }
            }
            _ => PvssScheduler::Wait,
        }
    }

    /// Create a new PVSS instance within this DKG session, contributing to the final key
    /// `rng` is a cryptographic random number generator
    /// Returns a PVSS dealing message to post on-chain
    pub fn share<R: Rng>(&mut self, rng: &mut R) -> Result<Message<E>> {
        use ark_std::UniformRand;
        print_time!("PVSS Sharing");
        let vss = Pvss::<E>::new(&E::Fr::rand(rng), self, rng)?;
        match self.state {
            DkgState::Sharing { .. } | DkgState::Dealt => {
                Ok(Message::Deal(vss))
            }
            _ => {
                Err(anyhow!("DKG is not in a valid state to deal PVSS shares"))
            }
        }
    }

    /// Aggregate all received PVSS messages into a single message, prepared to post on-chain
    pub fn aggregate(&self) -> Result<Message<E>> {
        match self.state {
            DkgState::Dealt => {
                let final_key = self.final_key();
                Ok(Message::Aggregate(Aggregation {
                    vss: aggregate(self),
                    final_key,
                }))
            }
            _ => Err(anyhow!(
                "Not enough PVSS transcripts received to aggregate"
            )),
        }
    }

    /// Returns the public key generated by the DKG
    pub fn final_key(&self) -> E::G1Affine {
        self.vss
            .values()
            .map(|vss| vss.coeffs[0].into_projective())
            .sum::<E::G1Projective>()
            .into_affine()
    }

    /// Verify a DKG related message in a block proposal
    /// `sender` is the validator of the sender of the message
    /// `payload` is the content of the message
    pub fn verify_message(
        &self,
        sender: &TendermintValidator<E>,
        payload: &Message<E>,
    ) -> Result<()> {
        match payload {
            Message::Deal(pvss) if matches!(self.state, DkgState::Sharing{..} | DkgState::Dealt) => {
                // TODO: If this is two slow, we can convert self.validators to
                // an address keyed hashmap after partitioning the shares shares
                // in the [`new`] method
                let sender = self.validators
                    .iter().position(|probe| sender.address == probe.validator.address)
                    .context("dkg received unknown dealer")?;
                if self.vss.contains_key(&(sender as u32)) {
                    Err(anyhow!("Repeat dealer {}", sender))
                } else if !pvss.verify_optimistic() {
                    Err(anyhow!("Invalid PVSS transcript"))
                } else {
                    Ok(())
                }
            }
            Message::Aggregate(Aggregation { vss, final_key }) if matches!(self.state, DkgState::Dealt) => {
                let minimum_shares = self.params.shares_num
                    - self.params.security_threshold;
                let verified_shares = vss.verify_aggregation(self)?;
                // we reject aggregations that fail to meet the security threshold
                if verified_shares < minimum_shares {
                    Err(
                        anyhow!("Aggregation failed because the verified shares was insufficient")
                    )
                } else if &self.final_key() == final_key {
                    Ok(())
                } else {
                    Err(
                        anyhow!("The final key was not correctly derived from the aggregated transcripts")
                    )
                }
            }
            _ => Err(anyhow!("DKG state machine is not in correct state to verify this message"))
        }
    }

    /// After consensus has agreed to include a verified
    /// message on the blockchain, we apply the chains
    /// to the state machine
    pub fn apply_message(
        &mut self,
        sender: TendermintValidator<E>,
        payload: Message<E>,
    ) -> Result<()> {
        match payload {
            Message::Deal(pvss) if matches!(self.state, DkgState::Sharing{..} | DkgState::Dealt) => {
                // Add the ephemeral public key and pvss transcript
                let sender = self.validators
                    .iter().position(|probe| sender.address == probe.validator.address)
                    .context("dkg received unknown dealer")?;
                self.vss.insert(sender as u32, pvss);

                // we keep track of the amount of shares seen until the security
                // threshold is met. Then we may change the state of the DKG
                if let DkgState::Sharing { ref mut accumulated_shares, .. } = &mut self.state {
                    *accumulated_shares += 1;
                    if *accumulated_shares >= self.params.shares_num - self.params.security_threshold {
                        self.state = DkgState::Dealt;
                    }
                }
                Ok(())
            }
            Message::Aggregate(_) if matches!(self.state, DkgState::Dealt) => {
                // change state and cache the final key
                self.state = DkgState::Success { final_key: self.final_key() };
                Ok(())
            }
            _ => Err(anyhow!("DKG state machine is not in correct state to apply this message"))
        }
    }
}

#[derive(
    Serialize,
    Deserialize,
    Clone,
    Debug,
    CanonicalSerialize,
    CanonicalDeserialize,
)]
#[serde(bound = "")]
pub struct Aggregation<E: PairingEngine> {
    #[serde(with = "ferveo_common::ark_serde")]
    vss: AggregatedPvss<E>,
    #[serde(with = "ferveo_common::ark_serde")]
    final_key: E::G1Affine,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "")]
pub enum Message<E: PairingEngine> {
    #[serde(with = "ferveo_common::ark_serde")]
    Deal(Pvss<E>),
    #[serde(with = "ferveo_common::ark_serde")]
    Aggregate(Aggregation<E>),
}

/// Factory functions for testing
#[cfg(test)]
pub(crate) mod test_common {
    pub use super::*;
    pub use ark_bls12_381::Bls12_381 as EllipticCurve;
    pub use ark_ff::UniformRand;

    pub type G1 = <EllipticCurve as PairingEngine>::G1Affine;

    pub fn gen_n_keypairs(
        n: u32,
    ) -> Vec<ferveo_common::Keypair<EllipticCurve>> {
        let rng = &mut ark_std::test_rng();
        (0..n)
            .map(|_| ferveo_common::Keypair::<EllipticCurve>::new(rng))
            .collect()
    }

    /// Generate a set of keypairs for each validator
    pub fn gen_keypairs() -> Vec<ferveo_common::Keypair<EllipticCurve>> {
        gen_n_keypairs(4)
    }

    pub fn gen_n_validators(
        keypairs: &[ferveo_common::Keypair<EllipticCurve>],
        n: u32,
    ) -> ValidatorSet<EllipticCurve> {
        ValidatorSet::new(
            (0..n)
                .map(|i| TendermintValidator {
                    power: 1, // TODO: Should set to 1 in order to force partitioning to give one share to each validator. Replace with 1 by reworking how partitioning works.
                    address: format!("validator_{}", i),
                    public_key: keypairs[i as usize].public(),
                })
                .collect(),
        )
    }

    /// Generate a few validators
    pub fn gen_validators(
        keypairs: &[ferveo_common::Keypair<EllipticCurve>],
    ) -> ValidatorSet<EllipticCurve> {
        gen_n_validators(keypairs, 4)
    }

    pub fn setup_dkg_for_n_validators(
        n_validators: u32,
        security_threshold: u32,
        shares_num: u32,
        my_index: usize,
    ) -> PubliclyVerifiableDkg<EllipticCurve> {
        let keypairs = gen_n_keypairs(n_validators);
        for _keypair in &keypairs {}
        let validators = gen_n_validators(&keypairs, n_validators);
        let me = validators.validators[my_index].clone();
        PubliclyVerifiableDkg::new(
            validators,
            Params {
                tau: 0,
                security_threshold,
                shares_num,
                retry_after: 2,
            },
            me,
            keypairs[my_index],
        )
        .expect("Setup failed")
    }

    /// Create a test dkg
    ///
    /// The [`test_dkg_init`] module checks correctness of this setup
    pub fn setup_dkg(validator: usize) -> PubliclyVerifiableDkg<EllipticCurve> {
        setup_dkg_for_n_validators(4, 2, 6, validator)
    }

    /// Set up a dkg with enough pvss transcripts to meet the threshold
    ///
    /// The correctness of this function is tested in the module [`test_dealing`]
    pub fn setup_dealt_dkg() -> PubliclyVerifiableDkg<EllipticCurve> {
        setup_dealt_dkg_with_n_validators(2, 4)
    }

    pub fn setup_dealt_dkg_with_n_validators(
        security_threshold: u32,
        shares_num: u32,
    ) -> PubliclyVerifiableDkg<EllipticCurve> {
        let n_validators = shares_num;
        // Make sure that the number of shares is a power of 2 for the FFT to work (Radix-2 FFT domain is being used)
        let is_power_of_2 = |n: u32| n != 0 && (n & (n - 1)) == 0;
        assert!(is_power_of_2(shares_num));

        let rng = &mut ark_std::test_rng();

        // Gather everyone's transcripts
        let transcripts = (0..n_validators)
            .map(|i| {
                let mut dkg = setup_dkg_for_n_validators(
                    n_validators,
                    security_threshold,
                    shares_num,
                    i as usize,
                );
                dkg.share(rng).expect("Test failed")
            })
            .collect::<Vec<_>>();

        // Our test dkg
        let mut dkg = setup_dkg_for_n_validators(
            n_validators,
            security_threshold,
            shares_num,
            0,
        );
        transcripts
            .into_iter()
            .enumerate()
            .for_each(|(sender, pvss)| {
                dkg.apply_message(
                    dkg.validators[sender].validator.clone(),
                    pvss,
                )
                .expect("Setup failed");
            });
        dkg
    }
}

/// Test initializing DKG
#[cfg(test)]
mod test_dkg_init {
    use super::test_common::*;

    /// Test that dkg fails to start if the `me` input
    /// is not in the validator set
    #[test]
    fn test_dkg_fail_unknown_validator() {
        let rng = &mut ark_std::test_rng();
        let keypairs = gen_keypairs();
        let keypair = ferveo_common::Keypair::<EllipticCurve>::new(rng);
        let err = PubliclyVerifiableDkg::<EllipticCurve>::new(
            gen_validators(&keypairs),
            Params {
                tau: 0,
                security_threshold: 4,
                shares_num: 8,
                retry_after: 2,
            },
            TendermintValidator::<EllipticCurve> {
                power: 9001,
                address: "non-existant-validator".into(),
                public_key: keypair.public(),
            },
            keypair,
        )
        .expect_err("Test failed");
        assert_eq!(
            err.to_string(),
            "could not find this validator in the provided validator set"
        )
    }

    /// Test that the windows of a validator are correctly
    /// computed from the `retry_after` param
    #[test]
    fn test_validator_windows() {
        for i in 0..4_u32 {
            let dkg = setup_dkg(i as usize);
            assert_eq!(dkg.window, (2 * i, 2 * i + 2));
        }
    }
}

/// Test the dealing phase of the DKG
#[cfg(test)]
mod test_dealing {
    use super::test_common::*;
    use crate::DkgState::Dealt;

    /// Test that dealing correct PVSS transcripts
    /// pass verification an application and that
    /// state is updated correctly
    #[test]
    fn test_pvss_dealing() {
        let rng = &mut ark_std::test_rng();
        // gather everyone's transcripts
        let mut transcripts = vec![];
        for i in 0..4 {
            let mut dkg = setup_dkg(i);
            transcripts.push(dkg.share(rng).expect("Test failed"));
        }
        // our test dkg
        let mut dkg = setup_dkg(0);
        // iterate over transcripts
        let mut expected = 0u32;
        for (sender, pvss) in transcripts.iter().enumerate() {
            // check the verification passes
            assert!(dkg
                .verify_message(&dkg.validators[sender].validator, pvss)
                .is_ok());
            // check that application passes
            assert!(dkg
                .apply_message(
                    dkg.validators[sender].validator.clone(),
                    pvss.clone(),
                )
                .is_ok());
            expected += 1; // dkg.validators[3 - sender].validator.power as u32;
                           // As long as we still have transcripts to deal, we should be in the Dealt state
            if sender < transcripts.len() - 1 {
                // check that shares accumulates correctly
                match dkg.state {
                    DkgState::Sharing {
                        accumulated_shares, ..
                    } => {
                        assert_eq!(accumulated_shares, expected)
                    }
                    _ => panic!("Test failed"),
                }
            } else {
                // check that when enough shares is accumulated, we transition state
                assert!(matches!(dkg.state, DkgState::Dealt));
            }
        }
    }

    /// Test the verification and application of
    /// pvss transcripts from unknown validators
    /// are rejected
    #[test]
    fn test_pvss_from_unknown_dealer_rejected() {
        let rng = &mut ark_std::test_rng();
        let mut dkg = setup_dkg(0);
        assert!(matches!(
            dkg.state,
            DkgState::Sharing {
                accumulated_shares: 0,
                block: 0
            }
        ));
        let pvss = dkg.share(rng).expect("Test failed");
        let sender = TendermintValidator::<EllipticCurve> {
            power: 9001,
            address: "Goku".into(),
            public_key: ferveo_common::Keypair::<EllipticCurve>::new(rng)
                .public(),
        };
        // check that verification fails
        assert!(dkg.verify_message(&sender, &pvss).is_err());
        // check that application fails
        assert!(dkg.apply_message(sender, pvss).is_err());
        // check that state has not changed
        assert!(matches!(
            dkg.state,
            DkgState::Sharing {
                accumulated_shares: 0,
                block: 0,
            }
        ));
    }

    /// Test that if a validator sends two pvss transcripts,
    /// the second fails to verify
    #[test]
    fn test_pvss_sent_twice_rejected() {
        let rng = &mut ark_std::test_rng();
        let mut dkg = setup_dkg(0);
        assert!(matches!(
            dkg.state,
            DkgState::Sharing {
                accumulated_shares: 0,
                block: 0,
            }
        ));
        let pvss = dkg.share(rng).expect("Test failed");
        let sender = dkg.validators[3].validator.clone();
        // check that verification fails
        assert!(dkg.verify_message(&sender, &pvss).is_ok());
        // check that application fails
        assert!(dkg.apply_message(sender.clone(), pvss.clone()).is_ok());
        // check that state has appropriately changed
        assert!(matches!(
            dkg.state,
            DkgState::Sharing {
                accumulated_shares: 1,
                block: 0,
            }
        ));
        // check that sending another pvss from same sender fails
        assert!(dkg.verify_message(&sender, &pvss).is_err());
    }

    /// Test that if a validators tries to verify it's own
    /// share message, it passes
    #[test]
    fn test_own_pvss() {
        let rng = &mut ark_std::test_rng();
        let mut dkg = setup_dkg(0);
        assert!(matches!(
            dkg.state,
            DkgState::Sharing {
                accumulated_shares: 0,
                block: 0,
            }
        ));
        // create share message and check state update
        let pvss = dkg.share(rng).expect("Test failed");
        assert!(matches!(
            dkg.state,
            DkgState::Sharing {
                accumulated_shares: 0,
                block: 0,
            }
        ));
        let sender = dkg.validators[0].validator.clone();
        // check that verification fails
        assert!(dkg.verify_message(&sender, &pvss).is_ok());
        assert!(dkg.apply_message(sender, pvss).is_ok());
        // check that state did not change
        assert!(matches!(
            dkg.state,
            DkgState::Sharing {
                accumulated_shares: 1,
                block: 0,
            }
        ));
    }

    /// Test that the [`PubliclyVerifiableDkg<E>::share`] method
    /// errors if its state is not [`DkgState::Shared{..} | Dkg::Dealt`]
    #[test]
    fn test_pvss_cannot_share_from_wrong_state() {
        let rng = &mut ark_std::test_rng();
        let mut dkg = setup_dkg(0);
        assert!(matches!(
            dkg.state,
            DkgState::Sharing {
                accumulated_shares: 0,
                block: 0,
            }
        ));

        dkg.state = DkgState::Success {
            final_key: G1::zero(),
        };
        assert!(dkg.share(rng).is_err());

        // check that even if security threshold is met, we can still share
        dkg.state = DkgState::Dealt;
        assert!(dkg.share(rng).is_ok());
    }

    /// Check that share messages can only be
    /// verified or applied if the dkg is in
    /// state [`DkgState::Share{..} | DkgState::Dealt`]
    #[test]
    fn test_share_message_state_guards() {
        let rng = &mut ark_std::test_rng();
        let mut dkg = setup_dkg(0);
        let pvss = dkg.share(rng).expect("Test failed");
        assert!(matches!(
            dkg.state,
            DkgState::Sharing {
                accumulated_shares: 0,
                block: 0,
            }
        ));
        let sender = dkg.validators[3].validator.clone();
        dkg.state = DkgState::Success {
            final_key: G1::zero(),
        };
        assert!(dkg.verify_message(&sender, &pvss).is_err());
        assert!(dkg.apply_message(sender.clone(), pvss.clone()).is_err());

        // check that we can still accept pvss transcripts after meeting threshold
        dkg.state = DkgState::Dealt;
        assert!(dkg.verify_message(&sender, &pvss).is_ok());
        assert!(dkg.apply_message(sender, pvss).is_ok());
        assert!(matches!(dkg.state, DkgState::Dealt))
    }

    /// Check that if a validators window has not arrived,
    /// the DKG advises us to wait
    #[test]
    fn test_pvss_wait_before_window() {
        let mut dkg = setup_dkg(1);
        if let DkgState::Sharing { block, .. } = dkg.state {
            assert!(dkg.window.0 > block);
        } else {
            panic!("Test failed");
        }
        assert_eq!(dkg.increase_block(), PvssScheduler::Wait);
    }

    /// Test that the DKG advises us to not issue a PVSS transcript
    /// if we are not in state [`DkgState::Sharing{..}`]
    #[test]
    fn test_pvss_wait_if_not_in_sharing_state() {
        let mut dkg = setup_dkg(0);
        for state in vec![
            DkgState::Dealt,
            DkgState::Success {
                final_key: G1::zero(),
            },
            DkgState::Invalid,
        ] {
            dkg.state = state;
            assert_eq!(dkg.increase_block(), PvssScheduler::Wait);
        }
    }

    /// Test that if we already have our PVSS on chain,
    /// the DKG advises us not to issue a new one
    #[test]
    fn test_pvss_wait_if_already_applied() {
        let rng = &mut ark_std::test_rng();
        let mut dkg = setup_dkg(0);
        let pvss = dkg.share(rng).expect("Test failed");
        let sender = dkg.validators[0].validator.clone();
        // check that verification fails
        assert!(dkg.verify_message(&sender, &pvss).is_ok());
        assert!(dkg.apply_message(sender, pvss).is_ok());
        assert_eq!(dkg.increase_block(), PvssScheduler::Wait);
    }

    /// Test that if our own PVSS transcript is not on chain
    /// after the retry window, the DKG advises us to issue again.
    #[test]
    fn test_pvss_reissue() {
        let mut dkg = setup_dkg(0);
        dkg.state = DkgState::Sharing {
            accumulated_shares: 0,
            block: 2,
        };
        assert_eq!(dkg.increase_block(), PvssScheduler::Issue);
        assert_eq!(dkg.increase_block(), PvssScheduler::Wait);
    }

    /// Test that we are only advised to issue a PVSS at the
    /// beginning of our window, not for every block in it
    #[test]
    fn test_pvss_wait_middle_of_window() {
        let mut dkg = setup_dkg(0);
        assert_eq!(dkg.increase_block(), PvssScheduler::Issue);
        if let DkgState::Sharing { block, .. } = dkg.state {
            assert!(dkg.window.0 < block && block < dkg.window.1);
        } else {
            panic!("Test failed");
        }
        assert_eq!(dkg.increase_block(), PvssScheduler::Wait);
    }
}

/// Test aggregating transcripts into final key
#[cfg(test)]
mod test_aggregation {
    use super::test_common::*;

    /// Test that if the security threshold is
    /// met, we can create a final key
    #[test]
    fn test_aggregate() {
        let mut dkg = setup_dealt_dkg();
        let aggregate = dkg.aggregate().expect("Test failed");
        let sender = dkg.validators[dkg.me].validator.clone();
        assert!(dkg.verify_message(&sender, &aggregate).is_ok());
        assert!(dkg.apply_message(sender, aggregate).is_ok());
        assert!(matches!(dkg.state, DkgState::Success { .. }));
    }

    /// Test that aggregate only succeeds if we are in
    /// the state [`DkgState::Dealt]
    #[test]
    fn test_aggregate_state_guards() {
        let mut dkg = setup_dealt_dkg();
        dkg.state = DkgState::Sharing {
            accumulated_shares: 0,
            block: 0,
        };
        assert!(dkg.aggregate().is_err());
        dkg.state = DkgState::Success {
            final_key: G1::zero(),
        };
        assert!(dkg.aggregate().is_err());
    }

    /// Test that aggregate message fail to be verified
    /// or applied unless dkg.state is
    /// [`DkgState::Dealt`]
    #[test]
    fn test_aggregate_message_state_guards() {
        let mut dkg = setup_dealt_dkg();
        let aggregate = dkg.aggregate().expect("Test failed");
        let sender = dkg.validators[dkg.me].validator.clone();
        dkg.state = DkgState::Sharing {
            accumulated_shares: 0,
            block: 0,
        };
        assert!(dkg.verify_message(&sender, &aggregate).is_err());
        assert!(dkg
            .apply_message(sender.clone(), aggregate.clone())
            .is_err());
        dkg.state = DkgState::Success {
            final_key: G1::zero(),
        };
        assert!(dkg.verify_message(&sender, &aggregate).is_err());
        assert!(dkg.apply_message(sender, aggregate).is_err())
    }

    /// Test that an aggregate message will fail to verify if the
    /// security threshold is not met
    #[test]
    fn test_aggregate_wont_verify_if_under_threshold() {
        let mut dkg = setup_dealt_dkg();
        dkg.params.shares_num = 10;
        let aggregate = dkg.aggregate().expect("Test failed");
        let sender = dkg.validators[dkg.me].validator.clone();
        assert!(dkg.verify_message(&sender, &aggregate).is_err());
    }

    /// If the aggregated pvss passes, check that the announced
    /// key is correct. Verification should fail if it is not
    #[test]
    fn test_aggregate_wont_verify_if_wrong_key() {
        let mut dkg = setup_dealt_dkg();
        let mut aggregate = dkg.aggregate().expect("Test failed");
        while dkg.final_key() == G1::zero() {
            dkg = setup_dealt_dkg();
        }
        if let Message::Aggregate(Aggregation { final_key, .. }) =
            &mut aggregate
        {
            *final_key = G1::zero();
        }
        let sender = dkg.validators[dkg.me].validator.clone();
        assert!(dkg.verify_message(&sender, &aggregate).is_err());
    }
}
