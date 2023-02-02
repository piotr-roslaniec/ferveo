use ark_poly::EvaluationDomain;
use group_threshold_cryptography as tpke;
use rand::thread_rng;

pub type E = ark_bls12_381::Bls12_381;

#[derive(Clone)]
pub struct Validator(ferveo_common::ExternalValidator<E>);

#[derive(Clone)]
pub struct Transcript(crate::PubliclyVerifiableSS<E>);

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

    pub fn generate_transcript(&self) -> Transcript {
        let rng = &mut thread_rng();
        Transcript(self.0.create_share(rng).unwrap())
    }

    pub fn aggregate_transcripts(
        &self,
        messages: Vec<(Validator, Transcript)>,
    ) -> AggregatedTranscript {
        // Avoid mutating current state
        // TODO: Rewrite `apply_message` to not require mutability after validating this API design
        let mut dkg = self.0.clone();
        for (validator, transcript) in messages {
            dkg.apply_message(validator.0, crate::Message::Deal(transcript.0))
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
