use ark_poly::EvaluationDomain;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ferveo_common::serialization;
pub use ferveo_common::{ExternalValidator, Keypair, PublicKey};
use group_threshold_cryptography as tpke;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
pub use tpke::api::{
    decrypt_with_shared_secret, encrypt, prepare_combine_simple,
    share_combine_precomputed, share_combine_simple, Ciphertext,
    DecryptionSharePrecomputed, DecryptionShareSimple, DomainPoint, Fr,
    G1Affine, G1Prepared, SharedSecret, E,
};

pub use crate::{PubliclyVerifiableSS as Transcript, Result};

#[serde_as]
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DkgPublicKey(
    #[serde_as(as = "serialization::SerdeAs")] pub G1Affine,
);

impl DkgPublicKey {
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut writer = Vec::new();
        self.0.serialize_uncompressed(&mut writer)?;
        Ok(writer)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<DkgPublicKey> {
        let mut reader = bytes;
        let pk = G1Affine::deserialize_uncompressed(&mut reader)?;
        Ok(Self(pk))
    }
}

pub type LagrangeCoefficient = FieldPoint;
pub type UnblindingKey = FieldPoint;

#[serde_as]
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FieldPoint(#[serde_as(as = "serialization::SerdeAs")] pub Fr);

impl FieldPoint {
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut writer = Vec::new();
        self.0.serialize_uncompressed(&mut writer)?;
        Ok(writer)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<FieldPoint> {
        let mut reader = bytes;
        let coeff = Fr::deserialize_uncompressed(&mut reader)?;
        Ok(Self(coeff))
    }
}

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
        DkgPublicKey(self.0.final_key())
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

    pub fn public_params(&self) -> DkgPublicParameters {
        DkgPublicParameters {
            g1_inv: self.0.pvss_params.g_inv(),
            domain_points: self.0.domain.elements().collect(),
        }
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

    pub fn create_decryption_share_precomputed(
        &self,
        dkg: &Dkg,
        ciphertext: &Ciphertext,
        aad: &[u8],
        validator_keypair: &Keypair<E>,
    ) -> Result<DecryptionSharePrecomputed> {
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

    pub fn create_decryption_share_simple(
        &self,
        dkg: &Dkg,
        ciphertext: &Ciphertext,
        aad: &[u8],
        validator_keypair: &Keypair<E>,
    ) -> Result<DecryptionShareSimple> {
        self.0.make_decryption_share_simple(
            ciphertext,
            aad,
            &validator_keypair.decryption_key,
            dkg.0.me,
            &dkg.0.pvss_params.g_inv(),
        )
    }
}

#[serde_as]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DkgPublicParameters {
    #[serde_as(as = "serialization::SerdeAs")]
    pub g1_inv: G1Prepared,
    #[serde_as(as = "serialization::SerdeAs")]
    pub domain_points: Vec<Fr>,
}

impl DkgPublicParameters {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        bincode::deserialize(bytes).unwrap()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap()
    }
}

#[cfg(test)]
mod test_ferveo_api {
    use itertools::izip;
    use rand::{prelude::StdRng, thread_rng, SeedableRng};

    use crate::{api::*, dkg::test_common::*};

    #[test]
    fn test_server_api_tdec_precomputed() {
        let rng = &mut StdRng::seed_from_u64(0);

        let tau = 1;
        let shares_num = 4;
        // In precomputed variant, the security threshold is equal to the number of shares
        // TODO: Refactor DKG contractor to not require security threshold or this case
        // TODO: Or figure out a different way to simplify the precomputed variant API
        let security_threshold = shares_num;

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

        // Lets say that we've only receives `security_threshold` transcripts
        let messages = messages[..security_threshold as usize].to_vec();
        let pvss_aggregated = dkg.aggregate_transcripts(&messages).unwrap();

        // At this point, any given validator should be able to provide a DKG public key
        let public_key = dkg.final_key();

        // In the meantime, the client creates a ciphertext and decryption request
        let msg: &[u8] = "abc".as_bytes();
        let aad: &[u8] = "my-aad".as_bytes();
        let rng = &mut thread_rng();
        let ciphertext = encrypt(msg, aad, &public_key.0, rng).unwrap();

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
                    .create_decryption_share_precomputed(
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

        let shared_secret = share_combine_precomputed(&decryption_shares);

        let plaintext = decrypt_with_shared_secret(
            &ciphertext,
            aad,
            &shared_secret,
            &dkg.0.pvss_params.g_inv(),
        )
        .unwrap();
        assert_eq!(plaintext, msg);
    }

    #[test]
    fn test_server_api_tdec_simple() {
        let rng = &mut StdRng::seed_from_u64(0);

        let tau = 1;
        let shares_num = 4;
        let security_threshold = 3;

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

        // Lets say that we've only receives `security_threshold` transcripts
        let messages = messages[..security_threshold as usize].to_vec();
        let pvss_aggregated = dkg.aggregate_transcripts(&messages).unwrap();

        // At this point, any given validator should be able to provide a DKG public key
        let public_key = dkg.final_key();

        // In the meantime, the client creates a ciphertext and decryption request
        let msg: &[u8] = "abc".as_bytes();
        let aad: &[u8] = "my-aad".as_bytes();
        let rng = &mut thread_rng();
        let ciphertext = encrypt(msg, aad, &public_key.0, rng).unwrap();

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
                    .create_decryption_share_precomputed(
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

        let shared_secret = share_combine_precomputed(&decryption_shares);

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
