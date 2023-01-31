pub type E = ark_bls12_381::Bls12_381;

#[derive(Clone)]
pub struct ExternalValidator(ferveo_common::ExternalValidator<E>);

pub struct PubliclyVerifiableDkg(crate::PubliclyVerifiableDkg<E>);

impl PubliclyVerifiableDkg {
    pub fn new(
        validators: Vec<ExternalValidator>,
        me: ExternalValidator,
        // session_keypair: ferveo_common::Keypair<E>,
        // tau: u32,
        security_threshold: u32,
        shares_num: u32,
        // retry_after: u32,
    ) -> Self {
        let validators = validators
            .into_iter()
            .map(|v| v.0)
            .collect::<Vec<ferveo_common::ExternalValidator<E>>>();
        let me = me.0;
        let params = crate::Params {
            tau: 0,
            security_threshold,
            shares_num,
            retry_after: 0,
        };
        let session_keypair = ferveo_common::Keypair::<E> {
            decryption_key: ark_ff::UniformRand::rand(&mut ark_std::test_rng()),
        };
        let dkg = crate::PubliclyVerifiableDkg::<E>::new(
            validators,
            params,
            &me,
            session_keypair,
        )
        .unwrap();
        Self(dkg)
    }
}
