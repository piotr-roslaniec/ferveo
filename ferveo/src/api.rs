use ark_poly::EvaluationDomain;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use bincode::Options;
use group_threshold_cryptography as tpke;
use rand::rngs::StdRng;
use rand::{thread_rng, RngCore, SeedableRng};

pub type E = ark_bls12_381::Bls12_381;

pub fn encrypt(
    message: &[u8],
    aad: &[u8],
    public_key: &DkgPublicKey,
) -> Ciphertext {
    Ciphertext(tpke::api::encrypt(message, aad, &public_key.0))
}

pub fn combine_decryption_shares(
    decryption_shares: &[DecryptionShare],
) -> SharedSecret {
    let shares = decryption_shares
        .iter()
        .map(|share| share.0.clone())
        .collect::<Vec<_>>();
    SharedSecret(tpke::share_combine_simple_precomputed::<E>(&shares))
}

pub fn decrypt_with_shared_secret(
    ciphertext: &Ciphertext,
    aad: &[u8],
    shared_secret: &SharedSecret,
) -> Vec<u8> {
    tpke::api::decrypt_with_shared_secret(&ciphertext.0, aad, &shared_secret.0)
        .unwrap()
}

pub struct SharedSecret(tpke::api::TpkeSharedSecret);

pub struct Keypair(ferveo_common::Keypair<E>);

impl Keypair {
    pub fn random<R: RngCore>(rng: &mut R) -> Self {
        Self(ferveo_common::Keypair::<E>::new(rng))
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.public())
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(ferveo_common::Keypair::<E>::deserialize(bytes).unwrap())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![];
        self.0.serialize(&mut buf).unwrap();
        buf
    }
}

#[derive(Clone)]
pub struct PublicKey(ferveo_common::PublicKey<E>);

impl PublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(ferveo_common::PublicKey::<E>::deserialize(bytes).unwrap())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![];
        self.0.serialize(&mut buf).unwrap();
        buf
    }
}

#[derive(Clone)]
pub struct ExternalValidator(ferveo_common::ExternalValidator<E>);

impl ExternalValidator {
    pub fn new(address: String, public_key: PublicKey) -> Self {
        Self(ferveo_common::ExternalValidator {
            address,
            public_key: public_key.0,
        })
    }
}

#[derive(Clone, Debug)]
pub struct Transcript(crate::PubliclyVerifiableSS<E>);

impl Transcript {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(crate::PubliclyVerifiableSS::<E>::deserialize(bytes).unwrap())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![];
        self.0.serialize(&mut buf).unwrap();
        buf
    }
}

#[derive(Clone)]
pub struct DkgPublicKey(pub tpke::api::TpkeDkgPublicKey);

#[derive(Clone)]
pub struct Dkg(crate::PubliclyVerifiableDkg<E>);

impl Dkg {
    pub fn new(
        tau: u64,
        shares_num: u32,
        security_threshold: u32,
        validators: &[ExternalValidator],
        me: &ExternalValidator,
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
        messages: &Vec<(ExternalValidator, Transcript)>,
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

pub struct Ciphertext(pub tpke::api::Ciphertext);

pub struct UnblindingKey(tpke::api::TpkeUnblindingKey);

#[derive(Clone)]
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
        validator_keypair: &Keypair,
    ) -> DecryptionShare {
        let domain_points: Vec<_> = dkg.0.domain.elements().collect();
        DecryptionShare(self.0.make_decryption_share_simple_precomputed(
            &ciphertext.0 .0,
            aad,
            &validator_keypair.0.decryption_key,
            dkg.0.me,
            &domain_points,
        ))
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(
            crate::PubliclyVerifiableSS::<E, crate::Aggregated>::deserialize(
                bytes,
            )
            .unwrap(),
        )
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![];
        self.0.serialize(&mut buf).unwrap();
        buf
    }
}

#[cfg(test)]
mod test_ferveo_api {
    use std::collections::HashMap;
    use std::fmt::format;

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
            .map(|(i, keypair)| {
                ExternalValidator(ferveo_common::ExternalValidator {
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
        let ciphertext = encrypt(msg, aad, &public_key);

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
                    &ciphertext,
                    aad,
                    &Keypair(*validator_keypair),
                )
            })
            .collect();

        // Now, the decryption share can be used to decrypt the ciphertext
        // This part is part of the client API

        let shared_secret = combine_decryption_shares(&decryption_shares);

        let plaintext =
            decrypt_with_shared_secret(&ciphertext, aad, &shared_secret);
        assert_eq!(plaintext, msg);
    }
}
