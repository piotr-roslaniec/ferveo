/// Factory functions and variables for testing
use std::str::FromStr;

pub use ark_bls12_381::Bls12_381 as E;
use ark_ec::pairing::Pairing;
use ferveo_common::Keypair;
use rand::seq::SliceRandom;

use crate::{DkgParams, EthereumAddress, PubliclyVerifiableDkg, Validator};

pub type ScalarField = <E as Pairing>::ScalarField;
pub type G1 = <E as Pairing>::G1Affine;
pub type G2 = <E as Pairing>::G2Affine;
pub type TargetField = <E as Pairing>::TargetField;

pub const TAU: u32 = 0;
pub const MSG: &[u8] = b"my-msg";
pub const AAD: &[u8] = b"my-aad";
pub const SECURITY_THRESHOLD: u32 = 3;
pub const SHARES_NUM: u32 = 4;

pub fn gen_keypairs(n: u32) -> Vec<Keypair<E>> {
    let rng = &mut ark_std::test_rng();
    (0..n).map(|_| Keypair::<E>::new(rng)).collect()
}

pub fn gen_address(i: usize) -> EthereumAddress {
    EthereumAddress::from_str(&format!("0x{i:040}")).unwrap()
}

pub fn gen_validators(keypairs: &[Keypair<E>]) -> Vec<Validator<E>> {
    keypairs
        .iter()
        .enumerate()
        .map(|(i, keypair)| Validator {
            address: gen_address(i),
            public_key: keypair.public_key(),
            share_index: i as u32,
        })
        .collect()
}

pub type TestSetup = (PubliclyVerifiableDkg<E>, Vec<Keypair<E>>);

pub fn setup_dkg_for_n_validators(
    security_threshold: u32,
    shares_num: u32,
    my_validator_index: usize,
) -> TestSetup {
    let keypairs = gen_keypairs(shares_num);
    let validators = gen_validators(keypairs.as_slice());
    let me = validators[my_validator_index].clone();
    let dkg = PubliclyVerifiableDkg::new(
        &validators,
        &DkgParams::new(TAU, security_threshold, shares_num).unwrap(),
        &me,
    )
    .expect("Setup failed");
    (dkg, keypairs)
}

/// Create a test dkg
///
/// The [`crate::dkg::test_dkg_init`] module checks correctness of this setup
pub fn setup_dkg(my_validator_index: usize) -> TestSetup {
    setup_dkg_for_n_validators(
        SECURITY_THRESHOLD,
        SHARES_NUM,
        my_validator_index,
    )
}

/// Set up a dkg with enough pvss transcripts to meet the threshold
///
/// The correctness of this function is tested in the module [`crate::dkg::test_dealing`]
pub fn setup_dealt_dkg() -> TestSetup {
    setup_dealt_dkg_with(SECURITY_THRESHOLD, SHARES_NUM)
}

pub fn setup_dealt_dkg_with(
    security_threshold: u32,
    shares_num: u32,
) -> TestSetup {
    let rng = &mut ark_std::test_rng();

    // Gather everyone's transcripts
    let mut messages: Vec<_> = (0..shares_num)
        .map(|my_index| {
            let (mut dkg, _) = setup_dkg_for_n_validators(
                security_threshold,
                shares_num,
                my_index as usize,
            );
            let me = dkg.me.validator.clone();
            let message = dkg.share(rng).unwrap();
            (me, message)
        })
        .collect();

    // Create a test DKG instance
    let (mut dkg, keypairs) =
        setup_dkg_for_n_validators(security_threshold, shares_num, 0);

    // The ordering of messages should not matter
    messages.shuffle(rng);
    messages.iter().for_each(|(sender, message)| {
        dkg.apply_message(sender, message).expect("Setup failed");
    });
    (dkg, keypairs)
}
