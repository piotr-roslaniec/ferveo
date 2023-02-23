use ark_poly::EvaluationDomain;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ferveo_common::serialization::ser::serialize;
pub use ferveo_common::{ExternalValidator, Keypair, PublicKey};
use group_threshold_cryptography as tpke;
use rand::rngs::StdRng;
use rand::{thread_rng, RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
pub use tpke::api::{
    decrypt_with_shared_secret, encrypt, share_combine_simple_precomputed,
    Ciphertext, DecryptionShareSimplePrecomputed as DecryptionShare,
    DkgPublicKey, G1Prepared, Result, SharedSecret, UnblindingKey, E,
};

pub use crate::PubliclyVerifiableSS as Transcript;

#[derive(Clone)]
pub struct Dkg(crate::PubliclyVerifiableDkg<E>);

impl Dkg {
    pub fn new(
        tau: u64,
        shares_num: u32,
        security_threshold: u32,
        validators: &[ExternalValidator<E>],
        me: &ExternalValidator<E>,
    ) -> Result<Self> {
        let params = crate::Params {
            tau,
            security_threshold,
            shares_num,
        };
        let session_keypair = Keypair::<E> {
            decryption_key: ark_ff::UniformRand::rand(&mut ark_std::test_rng()),
        };
        let dkg = crate::PubliclyVerifiableDkg::<E>::new(
            validators,
            params,
            me,
            session_keypair,
        )?;
        Ok(Self(dkg))
    }

    pub fn final_key(&self) -> DkgPublicKey {
        self.0.final_key()
    }

    pub fn generate_transcript<R: RngCore>(
        &self,
        rng: &mut R,
    ) -> Result<crate::PubliclyVerifiableSS<E>> {
        self.0.create_share(rng)
    }

    pub fn aggregate_transcripts(
        &mut self,
        messages: &Vec<(ExternalValidator<E>, Transcript<E>)>,
    ) -> Result<AggregatedTranscript> {
        // Avoid mutating current state
        // TODO: Rewrite `deal` to not require mutability after validating this API design
        for (validator, transcript) in messages {
            self.0.deal(validator.clone(), transcript.clone())?;
        }
        Ok(AggregatedTranscript(crate::pvss::aggregate(&self.0)))
    }

    pub fn g1_inv(&self) -> G1Prepared {
        self.0.pvss_params.g_inv()
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
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
        validator_keypair: &Keypair<E>,
    ) -> Result<DecryptionShare> {
        let domain_points: Vec<_> = dkg.0.domain.elements().collect();
        self.0.make_decryption_share_simple_precomputed(
            ciphertext,
            aad,
            &validator_keypair.decryption_key,
            dkg.0.me,
            &domain_points,
            &dkg.0.pvss_params.g_inv(),
        )
    }
}

#[cfg(test)]
mod test_ferveo_api {
    use std::collections::HashMap;
    use std::fmt::format;

    use ark_bls12_381::{Bls12_381 as E, G2Projective};
    use ark_ec::CurveGroup;
    use ark_poly::EvaluationDomain;
    use ark_serialize::CanonicalSerialize;
    use ark_std::UniformRand;
    use ferveo_common::PublicKey;
    use group_threshold_cryptography as tpke;
    use itertools::{iproduct, izip};
    use rand::prelude::StdRng;
    use rand::SeedableRng;

    use crate::api::*;
    use crate::dkg::test_common::*;

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
            .map(|(i, keypair)| ExternalValidator {
                address: format!("validator-{}", i),
                public_key: keypair.public(),
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
                )
                .unwrap();
                (sender.clone(), dkg.generate_transcript(rng).unwrap())
            })
            .collect();

        // Now that every validator holds a dkg instance and a transcript for every other validator,
        // every validator can aggregate the transcripts
        let me = validators[0].clone();
        let mut dkg =
            Dkg::new(tau, shares_num, security_threshold, &validators, &me)
                .unwrap();
        let pvss_aggregated = dkg.aggregate_transcripts(&messages).unwrap();

        // At this point, any given validator should be able to provide a DKG public key
        let public_key = dkg.final_key();

        // In the meantime, the client creates a ciphertext and decryption request
        let msg: &[u8] = "abc".as_bytes();
        let aad: &[u8] = "my-aad".as_bytes();
        let rng = &mut thread_rng();
        let ciphertext = encrypt(msg, aad, &public_key, rng).unwrap();

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
                )
                .unwrap();
                let aggregate = dkg.aggregate_transcripts(&messages).unwrap();
                assert!(pvss_aggregated.validate(&dkg));
                aggregate
                    .create_decryption_share(
                        &dkg,
                        &ciphertext,
                        aad,
                        validator_keypair,
                    )
                    .unwrap()
            })
            .collect();

        // Now, the decryption share can be used to decrypt the ciphertext
        // This part is part of the client API

        let shared_secret =
            share_combine_simple_precomputed(&decryption_shares);

        let plaintext = decrypt_with_shared_secret(
            &ciphertext,
            aad,
            &shared_secret,
            &dkg.0.pvss_params.g_inv(),
        )
        .unwrap();
        assert_eq!(plaintext, msg);
    }
}
