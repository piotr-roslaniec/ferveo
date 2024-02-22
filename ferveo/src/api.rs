use std::{fmt, io};

use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use bincode;
use ferveo_common::serialization;
pub use ferveo_tdec::api::{
    prepare_combine_simple, share_combine_precomputed, share_combine_simple,
    Fr, G1Affine, G1Prepared, G2Affine, SecretBox, E,
};
use generic_array::{
    typenum::{Unsigned, U48},
    GenericArray,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

pub type PublicKey = ferveo_common::PublicKey<E>;
pub type Keypair = ferveo_common::Keypair<E>;
pub type Validator = crate::Validator<E>;
pub type Transcript = PubliclyVerifiableSS<E>;

pub type ValidatorMessage = (Validator, Transcript);

#[cfg(feature = "bindings-python")]
use crate::bindings_python;
#[cfg(feature = "bindings-wasm")]
use crate::bindings_wasm;
pub use crate::EthereumAddress;
use crate::{
    do_verify_aggregation, Error, Message, PVSSMap, PubliclyVerifiableParams,
    PubliclyVerifiableSS, Result,
};

pub type DecryptionSharePrecomputed =
    ferveo_tdec::api::DecryptionSharePrecomputed;

// Normally, we would use a custom trait for this, but we can't because
// the arkworks will not let us create a blanket implementation for G1Affine
// and Fr types. So instead, we're using this shared utility function:
pub fn to_bytes<T: CanonicalSerialize>(item: &T) -> Result<Vec<u8>> {
    let mut writer = Vec::new();
    item.serialize_compressed(&mut writer)?;
    Ok(writer)
}

pub fn from_bytes<T: CanonicalDeserialize>(bytes: &[u8]) -> Result<T> {
    let mut reader = io::Cursor::new(bytes);
    let item = T::deserialize_compressed(&mut reader)?;
    Ok(item)
}

pub fn encrypt(
    message: SecretBox<Vec<u8>>,
    aad: &[u8],
    pubkey: &DkgPublicKey,
) -> Result<Ciphertext> {
    let mut rng = rand::thread_rng();
    let ciphertext =
        ferveo_tdec::api::encrypt(message, aad, &pubkey.0, &mut rng)?;
    Ok(Ciphertext(ciphertext))
}

pub fn decrypt_with_shared_secret(
    ciphertext: &Ciphertext,
    aad: &[u8],
    shared_secret: &SharedSecret,
) -> Result<Vec<u8>> {
    let dkg_public_params = DkgPublicParameters::default();
    ferveo_tdec::api::decrypt_with_shared_secret(
        &ciphertext.0,
        aad,
        &shared_secret.0,
        &dkg_public_params.g1_inv,
    )
    .map_err(Error::from)
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Eq)]
pub struct Ciphertext(ferveo_tdec::api::Ciphertext);

impl Ciphertext {
    pub fn header(&self) -> Result<CiphertextHeader> {
        Ok(CiphertextHeader(self.0.header()?))
    }

    pub fn payload(&self) -> Vec<u8> {
        self.0.payload()
    }
}

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CiphertextHeader(ferveo_tdec::api::CiphertextHeader);

/// The ferveo variant to use for the decryption share derivation.
#[derive(
    PartialEq, Eq, Debug, Serialize, Deserialize, Copy, Clone, PartialOrd,
)]
pub enum FerveoVariant {
    /// The simple variant requires m of n shares to decrypt
    Simple,
    /// The precomputed variant requires n of n shares to decrypt
    Precomputed,
}

impl fmt::Display for FerveoVariant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FerveoVariant {
    pub fn as_str(&self) -> &'static str {
        match self {
            FerveoVariant::Simple => "FerveoVariant::Simple",
            FerveoVariant::Precomputed => "FerveoVariant::Precomputed",
        }
    }

    pub fn from_string(s: &str) -> Result<Self> {
        match s {
            "FerveoVariant::Simple" => Ok(FerveoVariant::Simple),
            "FerveoVariant::Precomputed" => Ok(FerveoVariant::Precomputed),
            _ => Err(Error::InvalidVariant(s.to_string())),
        }
    }
}

#[cfg(feature = "bindings-python")]
impl From<bindings_python::FerveoVariant> for FerveoVariant {
    fn from(variant: bindings_python::FerveoVariant) -> Self {
        variant.0
    }
}

#[cfg(feature = "bindings-wasm")]
impl From<bindings_wasm::FerveoVariant> for FerveoVariant {
    fn from(variant: bindings_wasm::FerveoVariant) -> Self {
        variant.0
    }
}

#[serde_as]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DkgPublicKey(
    #[serde_as(as = "serialization::SerdeAs")] pub(crate) G1Affine,
);

impl DkgPublicKey {
    pub fn to_bytes(&self) -> Result<GenericArray<u8, U48>> {
        let as_bytes = to_bytes(&self.0)?;
        Ok(GenericArray::<u8, U48>::from_slice(&as_bytes).to_owned())
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<DkgPublicKey> {
        let bytes =
            GenericArray::<u8, U48>::from_exact_iter(bytes.iter().cloned())
                .ok_or_else(|| {
                    Error::InvalidByteLength(
                        Self::serialized_size(),
                        bytes.len(),
                    )
                })?;
        from_bytes(&bytes).map(DkgPublicKey)
    }

    pub fn serialized_size() -> usize {
        U48::to_usize()
    }

    /// Generate a random DKG public key.
    /// Use this for testing only.
    pub fn random() -> Self {
        let mut rng = rand::thread_rng();
        let g1 = G1Affine::rand(&mut rng);
        Self(g1)
    }
}

pub type UnblindingKey = FieldPoint;

#[serde_as]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldPoint(#[serde_as(as = "serialization::SerdeAs")] pub Fr);

impl FieldPoint {
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        to_bytes(&self.0)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<FieldPoint> {
        from_bytes(bytes).map(FieldPoint)
    }
}

#[derive(Clone)]
pub struct Dkg(crate::PubliclyVerifiableDkg<E>);

impl Dkg {
    pub fn new(
        tau: u32,
        shares_num: u32,
        security_threshold: u32,
        validators: &[Validator],
        me: &Validator,
    ) -> Result<Self> {
        let dkg_params =
            crate::DkgParams::new(tau, security_threshold, shares_num)?;
        let dkg = crate::PubliclyVerifiableDkg::<E>::new(
            validators,
            &dkg_params,
            me,
        )?;
        Ok(Self(dkg))
    }

    pub fn public_key(&self) -> DkgPublicKey {
        DkgPublicKey(self.0.public_key())
    }

    pub fn generate_transcript<R: RngCore>(
        &mut self,
        rng: &mut R,
        // TODO: Replace with Message::Deal?
    ) -> Result<Transcript> {
        match self.0.share(rng) {
            Ok(Message::Deal(transcript)) => Ok(transcript),
            Err(e) => Err(e),
            _ => Err(Error::InvalidDkgStateToDeal),
        }
    }

    pub fn aggregate_transcripts(
        &mut self,
        messages: &[ValidatorMessage],
        // TODO: Replace with Message::Aggregate?
    ) -> Result<AggregatedTranscript> {
        // We must use `deal` here instead of to produce AggregatedTranscript instead of simply
        // creating an AggregatedTranscript from the messages, because `deal` also updates the
        // internal state of the DKG.
        // If we didn't do that, that would cause the DKG to produce incorrect decryption shares
        // in the future.
        // TODO: Remove this dependency on DKG state
        // TODO: Avoid mutating current state here
        for (validator, transcript) in messages {
            self.0.deal(validator, transcript)?;
        }
        let pvss = messages
            .iter()
            .map(|(_, t)| t)
            .cloned()
            .collect::<Vec<PubliclyVerifiableSS<E>>>();
        Ok(AggregatedTranscript(crate::pvss::aggregate(&pvss)?))
    }

    pub fn public_params(&self) -> DkgPublicParameters {
        DkgPublicParameters {
            g1_inv: self.0.pvss_params.g_inv(),
        }
    }
}

fn make_pvss_map(messages: &[ValidatorMessage]) -> PVSSMap<E> {
    let mut pvss_map: PVSSMap<E> = PVSSMap::new();
    messages.iter().for_each(|(validator, transcript)| {
        pvss_map.insert(validator.address.clone(), transcript.clone());
    });
    pvss_map
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregatedTranscript(
    pub(crate) PubliclyVerifiableSS<E, crate::Aggregated>,
);

impl AggregatedTranscript {
    pub fn new(messages: &[ValidatorMessage]) -> Result<Self> {
        let pvss_list = messages
            .iter()
            .map(|(_, t)| t)
            .cloned()
            .collect::<Vec<PubliclyVerifiableSS<E>>>();
        Ok(AggregatedTranscript(crate::pvss::aggregate(&pvss_list)?))
    }

    pub fn verify(
        &self,
        validators_num: u32,
        messages: &[ValidatorMessage],
    ) -> Result<bool> {
        if validators_num < messages.len() as u32 {
            return Err(Error::InvalidAggregateVerificationParameters(
                validators_num,
                messages.len() as u32,
            ));
        }

        let pvss_params = PubliclyVerifiableParams::<E>::default();
        let domain =
            GeneralEvaluationDomain::<Fr>::new(validators_num as usize)
                .expect("Unable to construct an evaluation domain");

        let is_valid_optimistic = self.0.verify_optimistic();
        if !is_valid_optimistic {
            return Err(Error::InvalidTranscriptAggregate);
        }

        let pvss_map = make_pvss_map(messages);
        let validators: Vec<_> = messages
            .iter()
            .map(|(validator, _)| validator)
            .cloned()
            .collect();

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
        ciphertext_header: &CiphertextHeader,
        aad: &[u8],
        validator_keypair: &Keypair,
    ) -> Result<DecryptionSharePrecomputed> {
        // Prevent users from using the precomputed variant with improper DKG parameters
        if dkg.0.dkg_params.shares_num()
            != dkg.0.dkg_params.security_threshold()
        {
            return Err(Error::InvalidDkgParametersForPrecomputedVariant(
                dkg.0.dkg_params.shares_num(),
                dkg.0.dkg_params.security_threshold(),
            ));
        }
        self.0.make_decryption_share_simple_precomputed(
            &ciphertext_header.0,
            aad,
            &validator_keypair.decryption_key,
            dkg.0.me.share_index as usize,
            &dkg.0.domain_points(),
            &dkg.0.pvss_params.g_inv(),
        )
    }

    pub fn create_decryption_share_simple(
        &self,
        dkg: &Dkg,
        ciphertext_header: &CiphertextHeader,
        aad: &[u8],
        validator_keypair: &Keypair,
    ) -> Result<DecryptionShareSimple> {
        let share = self.0.make_decryption_share_simple(
            &ciphertext_header.0,
            aad,
            &validator_keypair.decryption_key,
            dkg.0.me.share_index as usize,
            &dkg.0.pvss_params.g_inv(),
        )?;
        let domain_point = dkg.0.get_domain_point(dkg.0.me.share_index)?;
        Ok(DecryptionShareSimple {
            share,
            domain_point,
        })
    }
}

#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecryptionShareSimple {
    share: ferveo_tdec::api::DecryptionShareSimple,
    #[serde_as(as = "serialization::SerdeAs")]
    domain_point: Fr,
}

#[serde_as]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DkgPublicParameters {
    #[serde_as(as = "serialization::SerdeAs")]
    pub(crate) g1_inv: G1Prepared,
}

impl Default for DkgPublicParameters {
    fn default() -> Self {
        DkgPublicParameters {
            g1_inv: PubliclyVerifiableParams::<E>::default().g_inv(),
        }
    }
}

impl DkgPublicParameters {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| e.into())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| e.into())
    }
}

pub fn combine_shares_simple(shares: &[DecryptionShareSimple]) -> SharedSecret {
    // Pick domain points that are corresponding to the shares we have.
    let domain_points: Vec<_> = shares.iter().map(|s| s.domain_point).collect();
    let lagrange_coefficients = prepare_combine_simple::<E>(&domain_points);

    let shares: Vec<_> = shares.iter().cloned().map(|s| s.share).collect();
    let shared_secret =
        share_combine_simple(&shares, &lagrange_coefficients[..]);
    SharedSecret(shared_secret)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedSecret(pub ferveo_tdec::api::SharedSecret<E>);

#[cfg(test)]
mod test_ferveo_api {
    use ferveo_tdec::SecretBox;
    use itertools::izip;
    use rand::{prelude::StdRng, SeedableRng};
    use test_case::test_case;

    use crate::{api::*, test_common::*};

    type TestInputs = (Vec<ValidatorMessage>, Vec<Validator>, Vec<Keypair>);

    fn make_test_inputs(
        rng: &mut StdRng,
        tau: u32,
        security_threshold: u32,
        shares_num: u32,
        validators_num: u32,
    ) -> TestInputs {
        let validator_keypairs = gen_keypairs(validators_num);
        let validators = validator_keypairs
            .iter()
            .enumerate()
            .map(|(i, keypair)| Validator {
                address: gen_address(i),
                public_key: keypair.public_key(),
                share_index: i as u32,
            })
            .collect::<Vec<_>>();

        // Each validator holds their own DKG instance and generates a transcript every
        // every validator, including themselves
        let messages: Vec<_> = validators
            .iter()
            .map(|sender| {
                let mut dkg = Dkg::new(
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

        (messages, validators, validator_keypairs)
    }

    #[test]
    fn test_dkg_pk_serialization() {
        let dkg_pk = DkgPublicKey::random();
        let serialized = dkg_pk.to_bytes().unwrap();
        let deserialized = DkgPublicKey::from_bytes(&serialized).unwrap();
        assert_eq!(serialized.len(), 48_usize);
        assert_eq!(dkg_pk, deserialized);
    }

    #[test_case(4, 4; "number of shares (validators) is a power of 2")]
    #[test_case(7, 7; "number of shares (validators) is not a power of 2")]
    #[test_case(4, 6; "number of validators greater than the number of shares")]
    fn test_server_api_tdec_precomputed(shares_num: u32, validators_num: u32) {
        let rng = &mut StdRng::seed_from_u64(0);

        // In precomputed variant, the security threshold is equal to the number of shares
        let security_threshold = shares_num;

        let (messages, validators, validator_keypairs) = make_test_inputs(
            rng,
            TAU,
            security_threshold,
            shares_num,
            validators_num,
        );

        // Now that every validator holds a dkg instance and a transcript for every other validator,
        // every validator can aggregate the transcripts
        let me = validators[0].clone();
        let mut dkg =
            Dkg::new(TAU, shares_num, security_threshold, &validators, &me)
                .unwrap();

        let pvss_aggregated = dkg.aggregate_transcripts(&messages).unwrap();
        assert!(pvss_aggregated.verify(validators_num, &messages).unwrap());

        // At this point, any given validator should be able to provide a DKG public key
        let dkg_public_key = dkg.public_key();

        // In the meantime, the client creates a ciphertext and decryption request
        let ciphertext =
            encrypt(SecretBox::new(MSG.to_vec()), AAD, &dkg_public_key)
                .unwrap();

        // Having aggregated the transcripts, the validators can now create decryption shares
        let decryption_shares: Vec<_> = izip!(&validators, &validator_keypairs)
            .map(|(validator, validator_keypair)| {
                // Each validator holds their own instance of DKG and creates their own aggregate
                let mut dkg = Dkg::new(
                    TAU,
                    shares_num,
                    security_threshold,
                    &validators,
                    validator,
                )
                .unwrap();
                let aggregate = dkg.aggregate_transcripts(&messages).unwrap();
                assert!(pvss_aggregated
                    .verify(validators_num, &messages)
                    .unwrap());

                // And then each validator creates their own decryption share
                aggregate
                    .create_decryption_share_precomputed(
                        &dkg,
                        &ciphertext.header().unwrap(),
                        AAD,
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
            AAD,
            &SharedSecret(shared_secret),
        )
        .unwrap();
        assert_eq!(plaintext, MSG);

        // Since we're using a precomputed variant, we need all the shares to be able to decrypt
        // So if we remove one share, we should not be able to decrypt
        let decryption_shares =
            decryption_shares[..shares_num as usize - 1].to_vec();

        let shared_secret = share_combine_precomputed(&decryption_shares);
        let result = decrypt_with_shared_secret(
            &ciphertext,
            AAD,
            &SharedSecret(shared_secret),
        );
        assert!(result.is_err());
    }

    #[test_case(4, 4; "number of shares (validators) is a power of 2")]
    #[test_case(7, 7; "number of shares (validators) is not a power of 2")]
    #[test_case(4, 6; "number of validators greater than the number of shares")]
    fn test_server_api_tdec_simple(shares_num: u32, validators_num: u32) {
        let rng = &mut StdRng::seed_from_u64(0);

        let security_threshold = shares_num / 2 + 1;

        let (messages, validators, validator_keypairs) = make_test_inputs(
            rng,
            TAU,
            security_threshold,
            shares_num,
            validators_num,
        );

        // Now that every validator holds a dkg instance and a transcript for every other validator,
        // every validator can aggregate the transcripts
        let mut dkg = Dkg::new(
            TAU,
            shares_num,
            security_threshold,
            &validators,
            &validators[0],
        )
        .unwrap();

        let pvss_aggregated = dkg.aggregate_transcripts(&messages).unwrap();
        assert!(pvss_aggregated.verify(validators_num, &messages).unwrap());

        // At this point, any given validator should be able to provide a DKG public key
        let public_key = dkg.public_key();

        // In the meantime, the client creates a ciphertext and decryption request
        let ciphertext =
            encrypt(SecretBox::new(MSG.to_vec()), AAD, &public_key).unwrap();

        // Having aggregated the transcripts, the validators can now create decryption shares
        let decryption_shares: Vec<_> = izip!(&validators, &validator_keypairs)
            .map(|(validator, validator_keypair)| {
                // Each validator holds their own instance of DKG and creates their own aggregate
                let mut dkg = Dkg::new(
                    TAU,
                    shares_num,
                    security_threshold,
                    &validators,
                    validator,
                )
                .unwrap();
                let aggregate = dkg.aggregate_transcripts(&messages).unwrap();
                assert!(aggregate.verify(validators_num, &messages).unwrap());
                aggregate
                    .create_decryption_share_simple(
                        &dkg,
                        &ciphertext.header().unwrap(),
                        AAD,
                        validator_keypair,
                    )
                    .unwrap()
            })
            .collect();

        // Now, the decryption share can be used to decrypt the ciphertext
        // This part is part of the client API

        // In simple variant, we only need `security_threshold` shares to be able to decrypt
        let decryption_shares =
            decryption_shares[..security_threshold as usize].to_vec();

        let shared_secret = combine_shares_simple(&decryption_shares);
        let plaintext =
            decrypt_with_shared_secret(&ciphertext, AAD, &shared_secret)
                .unwrap();
        assert_eq!(plaintext, MSG);

        // Let's say that we've only received `security_threshold - 1` shares
        // In this case, we should not be able to decrypt
        let decryption_shares =
            decryption_shares[..security_threshold as usize - 1].to_vec();

        let shared_secret = combine_shares_simple(&decryption_shares);
        let result =
            decrypt_with_shared_secret(&ciphertext, AAD, &shared_secret);
        assert!(result.is_err());
    }

    // Note that the server and client code are using the same underlying
    // implementation for aggregation and aggregate verification.
    // Here, we focus on testing user-facing APIs for server and client users.

    #[test_case(4, 4; "number of shares (validators) is a power of 2")]
    #[test_case(7, 7; "number of shares (validators) is not a power of 2")]
    #[test_case(4, 6; "number of validators greater than the number of shares")]
    fn server_side_local_verification(shares_num: u32, validators_num: u32) {
        let rng = &mut StdRng::seed_from_u64(0);
        let security_threshold = shares_num / 2 + 1;

        let (messages, validators, _) = make_test_inputs(
            rng,
            TAU,
            security_threshold,
            shares_num,
            validators_num,
        );

        // Now that every validator holds a dkg instance and a transcript for every other validator,
        // every validator can aggregate the transcripts
        let me = validators[0].clone();
        let mut dkg =
            Dkg::new(TAU, shares_num, security_threshold, &validators, &me)
                .unwrap();

        let good_aggregate = dkg.aggregate_transcripts(&messages).unwrap();
        assert!(good_aggregate.verify(validators_num, &messages).is_ok());

        // Test negative cases

        // Notice that the dkg instance is mutable, so we need to get a fresh one
        // for every test case

        // Should fail if the number of validators is less than the number of messages
        assert!(matches!(
            good_aggregate.verify(messages.len() as u32 - 1, &messages),
            Err(Error::InvalidAggregateVerificationParameters(_, _))
        ));

        // Should fail if no transcripts are provided
        let mut dkg =
            Dkg::new(TAU, shares_num, security_threshold, &validators, &me)
                .unwrap();
        assert!(matches!(
            dkg.aggregate_transcripts(&[]),
            Err(Error::NoTranscriptsToAggregate)
        ));

        // Not enough transcripts
        let mut dkg =
            Dkg::new(TAU, shares_num, security_threshold, &validators, &me)
                .unwrap();
        let not_enough_messages = &messages[..security_threshold as usize - 1];
        assert!(not_enough_messages.len() < security_threshold as usize);
        let insufficient_aggregate =
            dkg.aggregate_transcripts(not_enough_messages).unwrap();
        assert!(matches!(
            insufficient_aggregate.verify(validators_num, &messages),
            Err(Error::InvalidTranscriptAggregate)
        ));

        // Unexpected transcripts in the aggregate or transcripts from a different ritual
        // Using same DKG parameters, but different DKG instances and validators
        let mut dkg =
            Dkg::new(TAU, shares_num, security_threshold, &validators, &me)
                .unwrap();
        let (bad_messages, _, _) = make_test_inputs(
            rng,
            TAU,
            security_threshold,
            shares_num,
            validators_num,
        );
        let mixed_messages = [&messages[..2], &bad_messages[..1]].concat();
        let bad_aggregate = dkg.aggregate_transcripts(&mixed_messages).unwrap();
        assert!(matches!(
            bad_aggregate.verify(validators_num, &messages),
            Err(Error::InvalidTranscriptAggregate)
        ));
    }

    #[test_case(4, 4; "number of shares (validators) is a power of 2")]
    #[test_case(7, 7; "number of shares (validators) is not a power of 2")]
    #[test_case(4, 6; "number of validators greater than the number of shares")]
    fn client_side_local_verification(shares_num: u32, validators_num: u32) {
        let rng = &mut StdRng::seed_from_u64(0);
        let security_threshold = shares_num / 2 + 1;

        let (messages, _, _) = make_test_inputs(
            rng,
            TAU,
            security_threshold,
            shares_num,
            validators_num,
        );

        // We only need `security_threshold` transcripts to aggregate
        let messages = &messages[..security_threshold as usize];

        // Create an aggregated transcript on the client side
        let good_aggregate = AggregatedTranscript::new(messages).unwrap();

        // We are separating the verification from the aggregation since the client may fetch
        // the aggregate from a side-channel or decide to persist it and verify it later

        // Now, the client can verify the aggregated transcript
        let result = good_aggregate.verify(validators_num, messages);
        assert!(result.is_ok());
        assert!(result.unwrap());

        // Test negative cases

        // Should fail if the number of validators is less than the number of messages
        assert!(matches!(
            good_aggregate.verify(messages.len() as u32 - 1, messages),
            Err(Error::InvalidAggregateVerificationParameters(_, _))
        ));

        // Should fail if no transcripts are provided
        assert!(matches!(
            AggregatedTranscript::new(&[]),
            Err(Error::NoTranscriptsToAggregate)
        ));

        // Not enough transcripts
        let not_enough_messages = &messages[..security_threshold as usize - 1];
        assert!(not_enough_messages.len() < security_threshold as usize);
        let insufficient_aggregate =
            AggregatedTranscript::new(not_enough_messages).unwrap();
        let _result = insufficient_aggregate.verify(validators_num, messages);
        assert!(matches!(
            insufficient_aggregate.verify(validators_num, messages),
            Err(Error::InvalidTranscriptAggregate)
        ));

        // Unexpected transcripts in the aggregate or transcripts from a different ritual
        // Using same DKG parameters, but different DKG instances and validators
        let (bad_messages, _, _) = make_test_inputs(
            rng,
            TAU,
            security_threshold,
            shares_num,
            validators_num,
        );
        let mixed_messages = [&messages[..2], &bad_messages[..1]].concat();
        let bad_aggregate = AggregatedTranscript::new(&mixed_messages).unwrap();
        assert!(matches!(
            bad_aggregate.verify(validators_num, messages),
            Err(Error::InvalidTranscriptAggregate)
        ));
    }
}
