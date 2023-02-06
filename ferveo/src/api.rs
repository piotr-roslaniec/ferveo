use ark_poly::EvaluationDomain;
use group_threshold_cryptography as tpke;
use rand::rngs::StdRng;
use rand::{thread_rng, RngCore};

pub type E = ark_bls12_381::Bls12_381;

#[derive(Clone)]
pub struct Validator(ferveo_common::ExternalValidator<E>);

#[derive(Clone, Debug)]
pub struct Transcript(crate::PubliclyVerifiableSS<E>);

#[derive(Clone)]
pub struct DkgPublicKey(tpke::api::TpkePublicKey);

#[derive(Clone)]
pub struct Dkg(crate::PubliclyVerifiableDkg<E>);

impl Dkg {
    pub fn new(
        tau: u64,
        shares_num: u32,
        security_threshold: u32,
        validators: &[Validator],
        me: &Validator,
    ) -> Self {
        let validators = &validators
            .iter()
            .map(|v| v.0.clone())
            .collect::<Vec<ferveo_common::ExternalValidator<E>>>();
        let me = &me.0;
        let params = crate::Params {
            tau,
            security_threshold,
            shares_num,
        };
        let session_keypair = ferveo_common::Keypair::<E> {
            decryption_key: ark_ff::UniformRand::rand(&mut ark_std::test_rng()),
        };
        let dkg = crate::PubliclyVerifiableDkg::<E>::new(
            validators,
            params,
            me,
            session_keypair,
        )
        .unwrap();
        Self(dkg)
    }

    pub fn final_key(&self) -> DkgPublicKey {
        DkgPublicKey(self.0.final_key())
    }

    pub fn generate_transcript<R: RngCore>(&self, rng: &mut R) -> Transcript {
        Transcript(self.0.create_share(rng).unwrap())
    }

    pub fn aggregate_transcripts(
        &mut self,
        messages: &Vec<(Validator, Transcript)>,
    ) -> AggregatedTranscript {
        // Avoid mutating current state
        // TODO: Rewrite `deal` to not require mutability after validating this API design
        for (validator, transcript) in messages {
            self.0
                .deal(validator.0.clone(), transcript.0.clone())
                .unwrap();
        }

        AggregatedTranscript(crate::pvss::aggregate(&self.0))
    }
}

pub struct Ciphertext(tpke::api::TpkeCiphertext);

pub struct UnblindingKey(tpke::api::TpkeUnblindingKey);

pub struct DecryptionShare(tpke::api::TpkeDecryptionShareSimplePrecomputed);

pub struct AggregatedTranscript(
    crate::PubliclyVerifiableSS<E, crate::Aggregated>,
);

impl AggregatedTranscript {
    pub fn validate(&self, dkg: &Dkg) -> bool {
        self.0.verify_full(&dkg.0)
    }

    pub fn create_decryption_share(
        &self,
        dkg: &Dkg,
        ciphertext: &Ciphertext,
        aad: &[u8],
        unblinding_key: &UnblindingKey,
    ) -> DecryptionShare {
        let domain_points: Vec<_> = dkg.0.domain.elements().collect();
        DecryptionShare(self.0.make_decryption_share_simple_precomputed(
            &ciphertext.0,
            aad,
            &unblinding_key.0,
            dkg.0.me,
            &domain_points,
        ))
    }
}

#[cfg(test)]
mod test_ferveo_api {
    use crate::api::{Ciphertext, Dkg, UnblindingKey, Validator};
    use crate::dkg::test_common::{
        gen_n_keypairs, gen_n_validators, setup_dealt_dkg_with_n_validators,
        setup_dkg_for_n_validators,
    };
    use crate::{aggregate, Message, Params, PubliclyVerifiableDkg};
    use ark_bls12_381::{Bls12_381 as E, Fr, G2Projective};
    use ark_ec::ProjectiveCurve;
    use ark_poly::EvaluationDomain;
    use ark_serialize::CanonicalSerialize;
    use ark_std::UniformRand;
    use ferveo_common::PublicKey;
    use group_threshold_cryptography as tpke;
    use itertools::{iproduct, izip};
    use rand::prelude::StdRng;
    use rand::SeedableRng;
    use std::collections::HashMap;
    use std::fmt::format;

    #[test]
    fn test_server_api_simple_tdec_precomputed() {
        let rng = &mut StdRng::seed_from_u64(0);

        let tau = 1;
        let security_threshold = 3;
        let shares_num = 4;

        let validator_keypairs = gen_n_keypairs(shares_num);
        let validators = validator_keypairs
            .iter()
            .enumerate()
            .map(|(i, keypair)| {
                Validator(ferveo_common::ExternalValidator {
                    address: format!("validator-{}", i),
                    public_key: keypair.public(),
                })
            })
            .collect::<Vec<_>>();

        // Each validator holds their own DKG instance and generates a transcript every
        // every validator, including themselves
        let messages: Vec<_> = validators
            .iter()
            .map(|sender| {
                let dkg = Dkg::new(
                    tau,
                    shares_num,
                    security_threshold,
                    &validators,
                    sender,
                );
                (sender.clone(), dkg.generate_transcript(rng))
            })
            .collect();

        // Now that every validator holds a dkg instance and a transcript for every other validator,
        // every validator can aggregate the transcripts
        let me = validators[0].clone();
        let mut dkg =
            Dkg::new(tau, shares_num, security_threshold, &validators, &me);
        let pvss_aggregated = dkg.aggregate_transcripts(&messages);

        // At this point, any given validator should be able to provide a DKG public key
        let public_key = dkg.final_key();

        // In the meantime, the client creates a ciphertext and decryption request
        let msg: &[u8] = "abc".as_bytes();
        let aad: &[u8] = "my-aad".as_bytes();
        let ciphertext = tpke::encrypt::<_, E>(msg, aad, &public_key.0, rng);

        // Having aggregated the transcripts, the validators can now create decryption shares
        let decryption_shares: Vec<_> = izip!(&validators, &validator_keypairs)
            .map(|(validator, validator_keypair)| {
                // Each validator holds their own instance of DKG and creates their own aggregate
                let mut dkg = Dkg::new(
                    tau,
                    shares_num,
                    security_threshold,
                    &validators,
                    validator,
                );
                let aggregate = dkg.aggregate_transcripts(&messages);
                assert!(pvss_aggregated.validate(&dkg));
                aggregate.create_decryption_share(
                    &dkg,
                    &Ciphertext(ciphertext.clone()),
                    aad,
                    &UnblindingKey(validator_keypair.decryption_key),
                )
            })
            .collect();

        // Now, the decryption share can be used to decrypt the ciphertext
        // This part is part of the client API
        let decryption_shares: Vec<_> = decryption_shares
            .iter()
            .map(|decryption_share| decryption_share.0.clone())
            .collect();

        let shared_secret =
            tpke::share_combine_simple_precomputed::<E>(&decryption_shares);

        let plaintext =
            tpke::decrypt_with_shared_secret(&ciphertext, aad, &shared_secret)
                .unwrap();
        assert_eq!(plaintext, msg);
    }
}
