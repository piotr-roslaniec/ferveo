#![allow(non_snake_case)]
#![allow(dead_code)]

use crate::hash_to_curve::htp_bls12381_g2;
use ark_ec::{msm::FixedBaseMSM, AffineCurve, PairingEngine};
use ark_ff::{Field, One, PrimeField, ToBytes, UniformRand, Zero};
use ark_poly::{univariate::DensePolynomial, UVPolynomial};
use ark_poly::{EvaluationDomain, Polynomial};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use itertools::izip;
use subproductdomain::SubproductDomain;

use rand_core::RngCore;
use std::usize;
use thiserror::Error;

mod ciphertext;
mod combine;
mod context;
mod decryption;
mod hash_to_curve;
mod key_share;

pub use ciphertext::*;
pub use combine::*;
pub use context::*;
pub use decryption::*;
pub use key_share::*;

// TODO: Turn into a crate features
pub mod api;
pub mod serialization;

pub trait ThresholdEncryptionParameters {
    type E: PairingEngine;
}

#[derive(Debug, Error)]
pub enum ThresholdEncryptionError {
    /// Error
    #[error("ciphertext verification failed")]
    CiphertextVerificationFailed,

    /// Error
    #[error("Decryption share verification failed")]
    DecryptionShareVerificationFailed,

    /// Hashing to curve failed
    #[error("Could not hash to curve")]
    HashToCurveError,

    #[error("plaintext verification failed")]
    PlaintextVerificationFailed,
}

pub type Result<T> = std::result::Result<T, ThresholdEncryptionError>;

fn hash_to_g2<T: ark_serialize::CanonicalDeserialize>(message: &[u8]) -> T {
    let mut point_ser: Vec<u8> = Vec::new();
    let point = htp_bls12381_g2(message);
    point.serialize(&mut point_ser).unwrap();
    T::deserialize(&point_ser[..]).unwrap()
}

fn construct_tag_hash<E: PairingEngine>(
    u: E::G1Affine,
    stream_ciphertext: &[u8],
    aad: &[u8],
) -> E::G2Affine {
    let mut hash_input = Vec::<u8>::new();
    u.write(&mut hash_input).unwrap();
    hash_input.extend_from_slice(stream_ciphertext);
    hash_input.extend_from_slice(aad);

    hash_to_g2(&hash_input)
}

pub fn setup<E: PairingEngine>(
    threshold: usize,
    shares_num: usize,
    rng: &mut impl RngCore,
) -> (E::G1Affine, E::G2Affine, Vec<PrivateDecryptionContext<E>>) {
    assert!(shares_num >= threshold);

    // Generators G∈G1, H∈G2
    let g = E::G1Affine::prime_subgroup_generator();
    let h = E::G2Affine::prime_subgroup_generator();

    // The dealer chooses a uniformly random polynomial f of degree t-1
    let threshold_poly = DensePolynomial::<E::Fr>::rand(threshold - 1, rng);
    // Domain, or omega Ω
    let fft_domain =
        ark_poly::Radix2EvaluationDomain::<E::Fr>::new(shares_num).unwrap();
    // `evals` are evaluations of the polynomial f over the domain, omega: f(ω_j) for ω_j in Ω
    let evals = threshold_poly.evaluate_over_domain_by_ref(fft_domain);

    let mut domain_points = Vec::with_capacity(shares_num);
    let mut point = E::Fr::one();
    let mut domain_points_inv = Vec::with_capacity(shares_num);
    let mut point_inv = E::Fr::one();

    // domain_points are the powers of the generator g
    // domain_points_inv are the powers of the inverse of the generator g
    // It seems like domain points are being used in "share partitioning"
    // https://nikkolasg.github.io/ferveo/dkginit.html#share-partitioning
    // There's also a mention of this operation here:
    // "DKG.PartitionDomain({ek_i, s_i}) -> {(ek_i, Omega_i)}"
    // https://nikkolasg.github.io/ferveo/tpke-concrete.html
    for _ in 0..shares_num {
        // domain_points is the share domain of the i-th participant (?)
        domain_points.push(point); // 1, t, t^2, t^3, ...; where t is a scalar generator fft_domain.group_gen
        point *= fft_domain.group_gen;
        domain_points_inv.push(point_inv);
        point_inv *= fft_domain.group_gen_inv;
    }

    let window_size = FixedBaseMSM::get_mul_window_size(100);
    let scalar_bits = E::Fr::size_in_bits();

    // A - public key shares of participants
    let pubkey_shares =
        subproductdomain::fast_multiexp(&evals.evals, g.into_projective());
    let pubkey_share = g.mul(evals.evals[0]);
    assert!(pubkey_shares[0] == E::G1Affine::from(pubkey_share));

    // Y, but only when b = 1 - private key shares of participants
    let privkey_shares =
        subproductdomain::fast_multiexp(&evals.evals, h.into_projective());
    // h^{f(omega)}

    // a_0
    let x = threshold_poly.coeffs[0];

    // F_0 - The commitment to the constant term, and is the public key output Y from PVDKG
    // TODO: It seems like the rest of the F_i are not computed?
    let pubkey = g.mul(x);
    let privkey = h.mul(x);

    let mut private_contexts = vec![];
    let mut public_contexts = vec![];

    // (domain, domain_inv, A, Y)
    for (index, (domain, domain_inv, public, private)) in izip!(
        // Since we're assigning only one key share to one entity we can use chunks(1)
        // This is a quick workaround to avoid refactoring all related entities that assume there are multiple key shares
        // TODO: Refactor this code and all related code
        domain_points.chunks(1),
        domain_points_inv.chunks(1),
        pubkey_shares.chunks(1),
        privkey_shares.chunks(1)
    )
    .enumerate()
    {
        let private_key_share = PrivateKeyShare::<E> {
            private_key_shares: private.to_vec(),
        };
        let b = E::Fr::one(); // TODO: Not blinding for now
        let mut blinded_key_shares = private_key_share.blind(b);
        blinded_key_shares.multiply_by_omega_inv(domain_inv);
        // TODO: Is `blinded_key_shares` equal to [b]Z_{i,omega_i})?
        // Z_{i,omega_i}) = [dk_{i}^{-1}]*\hat{Y}_{i_omega_j}]
        /*blinded_key_shares.window_tables =
        blinded_key_shares.get_window_table(window_size, scalar_bits, domain_inv);*/
        private_contexts.push(PrivateDecryptionContext::<E> {
            index,
            b,
            b_inv: b.inverse().unwrap(),
            private_key_share,
            public_decryption_contexts: vec![],
            g,
            g_inv: E::G1Prepared::from(-g),
            h_inv: E::G2Prepared::from(-h),
            scalar_bits,
            window_size,
        });
        public_contexts.push(PublicDecryptionContext::<E> {
            domain: domain.to_vec(),
            public_key_shares: PublicKeyShares::<E> {
                public_key_shares: public.to_vec(),
            },
            blinded_key_shares,
            lagrange_n_0: domain.iter().product::<E::Fr>(),
        });
    }
    for private in private_contexts.iter_mut() {
        private.public_decryption_contexts = public_contexts.clone();
    }

    (pubkey.into(), privkey.into(), private_contexts)
}

pub fn setup_simple<E: PairingEngine>(
    threshold: usize,
    shares_num: usize,
    rng: &mut impl RngCore,
) -> (
    E::G1Affine,
    E::G2Affine,
    Vec<PrivateDecryptionContextSimple<E>>,
) {
    assert!(shares_num >= threshold);

    let g = E::G1Affine::prime_subgroup_generator();
    let h = E::G2Affine::prime_subgroup_generator();

    // The delear chooses a uniformly random polynomial f of degree t-1
    let threshold_poly = DensePolynomial::<E::Fr>::rand(threshold - 1, rng);
    // Domain, or omega Ω
    let fft_domain =
        ark_poly::Radix2EvaluationDomain::<E::Fr>::new(shares_num).unwrap();
    // `evals` are evaluations of the polynomial f over the domain, omega: f(ω_j) for ω_j in Ω
    let evals = threshold_poly.evaluate_over_domain_by_ref(fft_domain);

    let shares_x = fft_domain.elements().collect::<Vec<_>>();

    // A - public key shares of participants
    let pubkey_shares =
        subproductdomain::fast_multiexp(&evals.evals, g.into_projective());
    let pubkey_share = g.mul(evals.evals[0]);
    assert!(pubkey_shares[0] == E::G1Affine::from(pubkey_share));

    // Y, but only when b = 1 - private key shares of participants
    // Z_i = h^{f(omega)} ?
    let privkey_shares =
        subproductdomain::fast_multiexp(&evals.evals, h.into_projective());

    // a_0
    let x = threshold_poly.coeffs[0];
    // F_0
    // TODO: It seems like the rest of the F_i are not computed?
    let pubkey = g.mul(x);
    let privkey = h.mul(x);

    let secret = threshold_poly.evaluate(&E::Fr::zero());
    assert_eq!(secret, x);

    let mut private_contexts = vec![];
    let mut public_contexts = vec![];

    // (domain, A, Y)
    for (index, (domain, public, private)) in izip!(
        // Since we're assigning only one key share to one entity we can use chunks(1)
        // This is a quick workaround to avoid refactoring all related entities that assume there are multiple key shares
        // TODO: Refactor this code and all related code
        shares_x.chunks(1),
        pubkey_shares.chunks(1),
        privkey_shares.chunks(1)
    )
    .enumerate()
    {
        let private_key_share = PrivateKeyShare::<E> {
            private_key_shares: private.to_vec(),
        };
        // let b = E::Fr::rand(rng);
        let b = E::Fr::one(); // TODO: Not blinding for now
        let blinded_key_shares = private_key_share.blind(b);
        private_contexts.push(PrivateDecryptionContextSimple::<E> {
            index,
            b,
            b_inv: b.inverse().unwrap(),
            private_key_share,
            public_decryption_contexts: vec![],
            g,
            g_inv: E::G1Prepared::from(-g),
            h_inv: E::G2Prepared::from(-h),
        });
        public_contexts.push(PublicDecryptionContextSimple::<E> {
            domain: domain[0],
            public_key_shares: PublicKeyShares::<E> {
                public_key_shares: public.to_vec(),
            },
            blinded_key_shares,
        });
    }
    for private in private_contexts.iter_mut() {
        private.public_decryption_contexts = public_contexts.clone();
    }

    (pubkey.into(), privkey.into(), private_contexts)
}

pub fn generate_random<R: RngCore, E: PairingEngine>(
    n: usize,
    rng: &mut R,
) -> Vec<E::Fr> {
    (0..n).map(|_| E::Fr::rand(rng)).collect::<Vec<_>>()
}

#[cfg(test)]
mod tests {
    use crate::*;
    use ark_std::test_rng;

    type E = ark_bls12_381::Bls12_381;

    #[test]
    fn ciphertext_serialization() {
        let mut rng = test_rng();
        let threshold = 3;
        let shares_num = 8;
        let msg: &[u8] = "abc".as_bytes();
        let aad: &[u8] = "aad".as_bytes();

        let (pubkey, _privkey, _) = setup::<E>(threshold, shares_num, &mut rng);

        let ciphertext =
            encrypt::<rand::rngs::StdRng, E>(msg, aad, &pubkey, &mut rng);

        let serialized = ciphertext.to_bytes();
        let deserialized: Ciphertext<E> = Ciphertext::from_bytes(&serialized);

        assert_eq!(serialized, deserialized.to_bytes())
    }

    #[test]
    fn decryption_share_serialization() {
        let decryption_share = DecryptionShare::<E> {
            decrypter_index: 1,
            decryption_share: ark_bls12_381::G1Affine::prime_subgroup_generator(
            ),
        };

        let serialized = decryption_share.to_bytes();
        let deserialized: DecryptionShare<E> =
            DecryptionShare::from_bytes(&serialized);
        assert_eq!(serialized, deserialized.to_bytes())
    }

    #[test]
    fn symmetric_encryption() {
        let mut rng = test_rng();
        let threshold = 3;
        let shares_num = 8;
        let msg: &[u8] = "abc".as_bytes();
        let aad: &[u8] = "my-aad".as_bytes();

        let (pubkey, privkey, _) = setup::<E>(threshold, shares_num, &mut rng);

        let ciphertext =
            encrypt::<rand::rngs::StdRng, E>(msg, aad, &pubkey, &mut rng);
        let plaintext = checked_decrypt(&ciphertext, aad, privkey);

        assert_eq!(msg, plaintext)
    }

    // Source: https://stackoverflow.com/questions/26469715/how-do-i-write-a-rust-unit-test-that-ensures-that-a-panic-has-occurred
    // TODO: Remove after adding proper error handling to the library

    use itertools::Itertools;
    use std::panic;

    fn catch_unwind_silent<F: FnOnce() -> R + panic::UnwindSafe, R>(
        f: F,
    ) -> std::thread::Result<R> {
        let prev_hook = panic::take_hook();
        panic::set_hook(Box::new(|_| {}));
        let result = panic::catch_unwind(f);
        panic::set_hook(prev_hook);
        result
    }

    fn test_ciphertext_validation_fails<E: PairingEngine>(
        msg: &[u8],
        aad: &[u8],
        ciphertext: &Ciphertext<E>,
        shared_secret: &E::Fqk,
    ) {
        // So far, the ciphertext is valid
        let plaintext =
            checked_decrypt_with_shared_secret(ciphertext, aad, shared_secret)
                .unwrap();
        assert_eq!(plaintext, msg);

        // Malformed the ciphertext
        let mut ciphertext = ciphertext.clone();
        ciphertext.ciphertext[0] += 1;
        assert!(checked_decrypt_with_shared_secret(
            &ciphertext,
            aad,
            shared_secret,
        )
        .is_err());

        // Malformed the AAD
        let aad = "bad aad".as_bytes();
        assert!(checked_decrypt_with_shared_secret(
            &ciphertext,
            aad,
            shared_secret,
        )
        .is_err());
    }

    #[test]
    fn ciphertext_validity_check() {
        let mut rng = test_rng();
        let threshold = 3;
        let shares_num = 8;
        let msg: &[u8] = "abc".as_bytes();
        let aad: &[u8] = "my-aad".as_bytes();

        let (pubkey, _privkey, _) = setup::<E>(threshold, shares_num, &mut rng);
        let mut ciphertext =
            encrypt::<rand::rngs::StdRng, E>(msg, aad, &pubkey, &mut rng);

        // So far, the ciphertext is valid
        assert!(check_ciphertext_validity(&ciphertext, aad));

        // Malformed the ciphertext
        ciphertext.ciphertext[0] += 1;
        assert!(!check_ciphertext_validity(&ciphertext, aad));

        // Malformed the AAD
        let aad = "bad aad".as_bytes();
        assert!(!check_ciphertext_validity(&ciphertext, aad));
    }

    #[test]
    fn fast_threshold_encryption() {
        let mut rng = &mut test_rng();
        let threshold = 16 * 2 / 3;
        let shares_num = 16;
        let msg: &[u8] = "abc".as_bytes();
        let aad: &[u8] = "my-aad".as_bytes();

        let (pubkey, _privkey, contexts) =
            setup::<E>(threshold, shares_num, &mut rng);
        let ciphertext = encrypt::<_, E>(msg, aad, &pubkey, rng);

        let mut shares: Vec<DecryptionShare<E>> = vec![];
        for context in contexts.iter() {
            shares.push(context.create_share(&ciphertext));
        }

        /*for pub_context in contexts[0].public_decryption_contexts.iter() {
            assert!(pub_context
                .blinded_key_shares
                .verify_blinding(&pub_context.public_key_shares, rng));
        }*/
        let prepared_blinded_key_shares =
            prepare_combine(&contexts[0].public_decryption_contexts, &shares);
        let shared_secret =
            share_combine(&shares, &prepared_blinded_key_shares);

        test_ciphertext_validation_fails(msg, aad, &ciphertext, &shared_secret);
    }

    #[test]
    fn simple_threshold_decryption() {
        let mut rng = &mut test_rng();
        let threshold = 16 * 2 / 3;
        let shares_num = 16;
        let msg: &[u8] = "abc".as_bytes();
        let aad: &[u8] = "my-aad".as_bytes();

        let (pubkey, _, contexts) =
            setup_simple::<E>(threshold, shares_num, &mut rng);

        // Ciphertext.commitment is already computed to match U
        let ciphertext = encrypt::<_, E>(msg, aad, &pubkey, rng);

        // Creating decryption shares
        let decryption_shares: Vec<_> = contexts
            .iter()
            .map(|context| context.create_share(&ciphertext))
            .collect();

        let lagrange = prepare_combine_simple::<E>(
            &contexts[0].public_decryption_contexts,
        );

        let shared_secret =
            share_combine_simple::<E>(&decryption_shares, &lagrange);

        test_ciphertext_validation_fails(msg, aad, &ciphertext, &shared_secret);
    }

    #[test]
    fn simple_threshold_decryption_precomputed() {
        let mut rng = &mut test_rng();
        let threshold = 16 * 2 / 3;
        let shares_num = 16;
        let msg: &[u8] = "abc".as_bytes();
        let aad: &[u8] = "my-aad".as_bytes();

        let (pubkey, _, contexts) =
            setup_simple::<E>(threshold, shares_num, &mut rng);

        let ciphertext = encrypt::<_, E>(msg, aad, &pubkey, rng);

        let lagrange_coeffs = prepare_combine_simple::<E>(
            &contexts[0].public_decryption_contexts,
        );

        let decryption_shares: Vec<_> = contexts
            .iter()
            .zip_eq(lagrange_coeffs.iter())
            .map(|(context, lagrange_coeff)| {
                context.create_share_precomputed(&ciphertext, lagrange_coeff)
            })
            .collect();

        let shared_secret =
            share_combine_simple_precomputed::<E>(&decryption_shares);

        test_ciphertext_validation_fails(msg, aad, &ciphertext, &shared_secret);
    }
}
