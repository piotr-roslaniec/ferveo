use std::io;

use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use bincode;
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

pub use crate::PubliclyVerifiableSS as Transcript;
use crate::{do_verify_aggregation, PVSSMap, PubliclyVerifiableSS, Result};

// Normally, we would use a custom trait for this, but we can't because
// the arkworks will not let us create a blanket implementation for G1Affine
// and Fr types. So instead, we're using this shared utility function:
pub fn to_bytes<T: CanonicalSerialize>(item: &T) -> Result<Vec<u8>> {
    let mut writer = Vec::new();
    item.serialize_uncompressed(&mut writer)?;
    Ok(writer)
}

pub fn from_bytes<T: CanonicalDeserialize>(bytes: &[u8]) -> Result<T> {
    let mut reader = io::Cursor::new(bytes);
    let item = T::deserialize_uncompressed(&mut reader)?;
    Ok(item)
}

#[serde_as]
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DkgPublicKey(
    #[serde_as(as = "serialization::SerdeAs")] pub G1Affine,
);

impl DkgPublicKey {
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        to_bytes(&self.0)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<DkgPublicKey> {
        from_bytes(bytes).map(DkgPublicKey)
    }
}

pub type UnblindingKey = FieldPoint;

#[serde_as]
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FieldPoint(#[serde_as(as = "serialization::SerdeAs")] pub Fr);

impl FieldPoint {
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        to_bytes(&self.0)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<FieldPoint> {
        from_bytes(bytes).map(FieldPoint)
    }
}

pub type ValidatorMessage = (ExternalValidator<E>, Transcript<E>);

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
    ) -> Result<Transcript<E>> {
        self.0.create_share(rng)
    }

    pub fn aggregate_transcripts(
        &mut self,
        messages: &[ValidatorMessage],
    ) -> Result<AggregatedTranscript> {
        // TODO: Avoid mutating current state
        for (validator, transcript) in messages {
            self.0.deal(validator, transcript)?;
        }
        Ok(AggregatedTranscript(crate::pvss::aggregate(&self.0.vss)))
    }

    pub fn public_params(&self) -> DkgPublicParameters {
        DkgPublicParameters {
            g1_inv: self.0.pvss_params.g_inv(),
            domain_points: self.0.domain.elements().collect(),
        }
    }
}

fn make_pvss_map(transcripts: &[PubliclyVerifiableSS<E>]) -> PVSSMap<E> {
    let mut pvss_map: PVSSMap<E> = PVSSMap::new();
    for (i, transcript) in transcripts.iter().enumerate() {
        pvss_map.insert(i as u32, transcript.clone());
    }
    pvss_map
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AggregatedTranscript(Transcript<E, crate::Aggregated>);

impl AggregatedTranscript {
    pub fn from_transcripts(transcripts: &[Transcript<E>]) -> Self {
        let pvss_map = make_pvss_map(transcripts);
        AggregatedTranscript(crate::pvss::aggregate(&pvss_map))
    }

    pub fn verify(
        &self,
        shares_num: u32,
        transcripts: &[Transcript<E>],
    ) -> Result<bool> {
        let pvss_params = crate::pvss::PubliclyVerifiableParams::<E>::default();
        let validators = vec![];
        let domain = Radix2EvaluationDomain::<Fr>::new(shares_num as usize)
            .expect("Unable to construct an evaluation domain");

        let is_valid_optimistic = self.0.verify_optimistic();
        if !is_valid_optimistic {
            return Err(crate::Error::InvalidTranscriptAggregate);
        }

        let pvss_map = make_pvss_map(transcripts);
        // This check also includes `verify_full`. See impl. for details.
        let is_valid = do_verify_aggregation(
            &self.0.coeffs,
            &self.0.shares,
            &pvss_params,
            &validators,
            &domain,
            &pvss_map,
        )?;
        Ok(is_valid)
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
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| e.into())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| e.into())
    }
}

#[cfg(test)]
mod test_ferveo_api {
    use itertools::{izip, zip_eq};
    use rand::{prelude::StdRng, thread_rng, SeedableRng};

    use crate::{api::*, dkg::test_common::*};

    #[test]
    fn test_server_api_tdec_precomputed() {
        let rng = &mut StdRng::seed_from_u64(0);

        let tau = 1;
        let shares_num = 4;
        // In precomputed variant, the security threshold is equal to the number of shares
        // TODO: Refactor DKG constructor to not require security threshold or this case
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
        let transcripts: Vec<_> = messages
            .iter()
            .map(|(_, transcript)| transcript)
            .cloned()
            .collect();
        let pvss_aggregated = dkg.aggregate_transcripts(&messages).unwrap();
        assert!(pvss_aggregated.verify(shares_num, &transcripts).unwrap());

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
                assert!(pvss_aggregated
                    .verify(shares_num, &transcripts)
                    .is_ok());
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
        let transcripts: Vec<_> = messages
            .iter()
            .map(|(_, transcript)| transcript)
            .cloned()
            .collect();
        let pvss_aggregated = dkg.aggregate_transcripts(&messages).unwrap();
        assert!(pvss_aggregated.verify(shares_num, &transcripts).unwrap());

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
                assert!(aggregate.verify(shares_num, &transcripts).unwrap());
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
            &dkg.public_params().g1_inv,
        )
        .unwrap();
        assert_eq!(plaintext, msg);
    }

    #[test]
    fn server_side_local_verification() {
        let rng = &mut StdRng::seed_from_u64(0);

        let tau = 1;
        let security_threshold = 3;
        let shares_num = 4;

        let (transcripts, validators, _validator_keypairs) =
            make_test_inputs(rng, tau, security_threshold, shares_num);

        // Now that every validator holds a dkg instance and a transcript for every other validator,
        // every validator can aggregate the transcripts
        let me = validators[0].clone();
        let mut dkg =
            Dkg::new(tau, shares_num, security_threshold, &validators, &me)
                .unwrap();

        let messages: Vec<_> =
            zip_eq(validators, transcripts.clone()).collect();
        let local_aggregate = dkg.aggregate_transcripts(&messages).unwrap();
        assert!(local_aggregate
            .verify(dkg.0.params.shares_num, &transcripts)
            .is_ok());
    }

    #[test]
    fn client_side_local_verification() {
        let rng = &mut StdRng::seed_from_u64(0);

        let tau = 1;
        let security_threshold = 3;
        let shares_num = 4;

        let (transcripts, _, _) =
            make_test_inputs(rng, tau, security_threshold, shares_num);

        // We only need `security_threshold` transcripts to aggregate
        let transcripts = &transcripts[..security_threshold as usize];

        // Create an aggregated transcript on the client side
        let aggregated_transcript =
            AggregatedTranscript::from_transcripts(transcripts);

        // We are separating the verification from the aggregation since the client may fetch
        // the aggregate from a side-channel or decide to persist it and verify it later

        // Now, the client can verify the aggregated transcript
        let result = aggregated_transcript.verify(shares_num, transcripts);
        assert!(result.is_ok());
        assert!(result.unwrap());

        // Test negative cases

        // Not enough transcripts
        let not_enough_transcripts = &transcripts[..2];
        assert!(not_enough_transcripts.len() < security_threshold as usize);
        let insufficient_aggregate =
            AggregatedTranscript::from_transcripts(not_enough_transcripts);
        let result = insufficient_aggregate.verify(shares_num, transcripts);
        assert!(result.is_err());

        // Unexpected transcripts in the aggregate or transcripts from a different ritual
        // Using same DKG parameters, but different DKG instances and validators
        let (bad_transcripts, _, _) =
            make_test_inputs(rng, tau, security_threshold, shares_num);
        let mixed_transcripts =
            [&transcripts[..2], &bad_transcripts[..1]].concat();
        let bad_aggregate =
            AggregatedTranscript::from_transcripts(&mixed_transcripts);
        let result = bad_aggregate.verify(shares_num, transcripts);
        assert!(result.is_err());
    }

    type TestInputs = (
        Vec<PubliclyVerifiableSS<E>>,
        Vec<ExternalValidator<E>>,
        Vec<Keypair<E>>,
    );

    fn make_test_inputs(
        rng: &mut StdRng,
        tau: u64,
        security_threshold: u32,
        shares_num: u32,
    ) -> TestInputs {
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
        let transcripts: Vec<_> = validators
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
                dkg.generate_transcript(rng).unwrap()
            })
            .collect();
        (transcripts, validators, validator_keypairs)
    }
}
