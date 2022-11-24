#![allow(non_snake_case)]
#![allow(dead_code)]
use crate::hash_to_curve::htp_bls12381_g2;
use ark_ec::{msm::FixedBaseMSM, AffineCurve, PairingEngine};
use ark_ff::{Field, One, PrimeField, ToBytes, UniformRand, Zero};
use ark_poly::EvaluationDomain;
use ark_poly::{univariate::DensePolynomial, UVPolynomial};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use itertools::izip;
use subproductdomain::SubproductDomain;

use rand_core::RngCore;
use std::usize;
use thiserror::Error;

mod ciphertext;
mod hash_to_curve;
pub use ciphertext::*;
mod key_share;
pub use key_share::*;
mod decryption;
pub use decryption::*;
mod combine;
pub use combine::*;
mod context;
pub use context::*;

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
    num_entities: usize,
    rng: &mut impl RngCore,
) -> (E::G1Affine, E::G2Affine, Vec<PrivateDecryptionContext<E>>) {
    assert!(shares_num >= threshold);

    let g = E::G1Affine::prime_subgroup_generator();
    let h = E::G2Affine::prime_subgroup_generator();

    let threshold_poly = DensePolynomial::<E::Fr>::rand(threshold - 1, rng);
    let fft_domain =
        ark_poly::Radix2EvaluationDomain::<E::Fr>::new(shares_num).unwrap();
    let evals = threshold_poly.evaluate_over_domain_by_ref(fft_domain);

    let mut domain_points = Vec::with_capacity(shares_num);
    let mut point = E::Fr::one();
    let mut domain_points_inv = Vec::with_capacity(shares_num);
    let mut point_inv = E::Fr::one();

    // TODO: Why do we need to compute these?
    // domain_points are the powers of the generator g
    // domain_points_inv are the powers of the inverse of the generator g
    for _ in 0..shares_num {
        domain_points.push(point); // 1, t, t^2, t^3, ...; where t is a scalar genrator fft_domain.group_gen
        point *= fft_domain.group_gen;
        domain_points_inv.push(point_inv);
        point_inv *= fft_domain.group_gen_inv;
    }

    let window_size = FixedBaseMSM::get_mul_window_size(100);
    let scalar_bits = E::Fr::size_in_bits();

    let pubkey_shares =
        subproductdomain::fast_multiexp(&evals.evals, g.into_projective());
    let privkey_shares =
        subproductdomain::fast_multiexp(&evals.evals, h.into_projective());

    let x = threshold_poly.coeffs[0];
    let pubkey = g.mul(x);
    let privkey = h.mul(x);

    let mut private_contexts = vec![];
    let mut public_contexts = vec![];

    for (index, (domain, domain_inv, public, private)) in izip!(
        domain_points.chunks(shares_num / num_entities),
        domain_points_inv.chunks(shares_num / num_entities),
        pubkey_shares.chunks(shares_num / num_entities),
        privkey_shares.chunks(shares_num / num_entities)
    )
    .enumerate()
    {
        let private_key_share = PrivateKeyShare::<E> {
            private_key_shares: private.to_vec(),
        };
        let b = E::Fr::rand(rng);
        let mut blinded_key_shares = private_key_share.blind(b);
        blinded_key_shares.multiply_by_omega_inv(domain_inv);
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
        let mut lagrange_n_0 = domain.iter().product::<E::Fr>();
        if domain.len() % 2 == 1 {
            lagrange_n_0 = -lagrange_n_0;
        }
        public_contexts.push(PublicDecryptionContext::<E> {
            domain: domain.to_vec(),
            public_key_shares: PublicKeyShares::<E> {
                public_key_shares: public.to_vec(),
            },
            blinded_key_shares,
            lagrange_n_0,
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
    num_entities: usize,
    rng: &mut impl RngCore,
) -> (
    E::G1Affine,
    E::G2Affine,
    Vec<PrivateDecryptionContextSimple<E>>,
) {
    assert!(shares_num >= threshold);

    let g = E::G1Affine::prime_subgroup_generator();
    let h = E::G2Affine::prime_subgroup_generator();

    // Dense polynomial is just a vector of coefficients
    // So this is the polynomial that we're going to split among the participants
    let threshold_poly = DensePolynomial::<E::Fr>::rand(threshold - 1, rng);
    // The evaluation domain is the set of points at which the polynomial is evaluated
    // Radix-2 is a special case of FFT that is faster for polynomials of size 2^n
    // We need to evaluate the polynomial at 2^n points
    let fft_domain =
        ark_poly::Radix2EvaluationDomain::<E::Fr>::new(shares_num).unwrap();
    // Evaluate the polynomial at the points in the evaluation domain
    let evals = threshold_poly.evaluate_over_domain_by_ref(fft_domain);
    // So no we 1) have the polynomial and 2) the evaluations of the polynomial at 2^n points

    let mut domain_points = Vec::with_capacity(shares_num);
    let mut point = E::Fr::one();
    let mut domain_points_inv = Vec::with_capacity(shares_num);
    let mut point_inv = E::Fr::one();

    for _ in 0..shares_num {
        // domain_points are the powers of the generator g
        domain_points.push(point); // 1, t, t^2, t^3, ...; where t is a scalar genrator fft_domain.group_gen
        point *= fft_domain.group_gen;
        // domain_points_inv are the powers of the inverse of the generator g
        domain_points_inv.push(point_inv);
        point_inv *= fft_domain.group_gen_inv;
    }

    // Precomputing some parts of the Lagrange interpolation
    // A
    let pubkey_shares =
        subproductdomain::fast_multiexp(&evals.evals, g.into_projective());
    // Y, but only when b = 1
    let privkey_shares =
        subproductdomain::fast_multiexp(&evals.evals, h.into_projective());

    // The secret key is the constant term of the polynomial
    let x = threshold_poly.coeffs[0];
    let pubkey = g.mul(x);
    let privkey = h.mul(x);

    let mut private_contexts = vec![];
    let mut public_contexts = vec![];

    for (index, (domain, domain_inv, public, private)) in izip!(
        domain_points.chunks(shares_num / num_entities),
        domain_points_inv.chunks(shares_num / num_entities),
        pubkey_shares.chunks(shares_num / num_entities),
        privkey_shares.chunks(shares_num / num_entities)
    )
    .enumerate()
    {
        let private_key_share = PrivateKeyShare::<E> {
            private_key_shares: private.to_vec(),
        };
        let b = E::Fr::one(); // Great success!
        let blinded_key_shares = private_key_share.blind(b);
        // blinded_key_shares.multiply_by_omega_inv(domain_inv);
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
        let mut lagrange_n_0 = domain.iter().product::<E::Fr>();
        if domain.len() % 2 == 1 {
            lagrange_n_0 = -lagrange_n_0;
        }
        public_contexts.push(PublicDecryptionContext::<E> {
            domain: domain.to_vec(),
            public_key_shares: PublicKeyShares::<E> {
                public_key_shares: public.to_vec(),
            },
            blinded_key_shares,
            lagrange_n_0,
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
        let shares_num = 5;
        let num_entities = 5;
        let msg: &[u8] = "abc".as_bytes();
        let aad: &[u8] = "aad".as_bytes();

        let (pubkey, _privkey, _) =
            setup::<E>(threshold, shares_num, num_entities, &mut rng);

        let ciphertext = encrypt::<ark_std::rand::rngs::StdRng, E>(
            msg, aad, &pubkey, &mut rng,
        );

        let serialized = ciphertext.to_bytes();
        let deserialized: Ciphertext<E> = Ciphertext::from_bytes(&serialized);

        assert!(serialized == deserialized.to_bytes())
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
        let shares_num = 5;
        let num_entities = 5;
        let msg: &[u8] = "abc".as_bytes();
        let aad: &[u8] = "my-aad".as_bytes();

        let (pubkey, privkey, _) =
            setup::<E>(threshold, shares_num, num_entities, &mut rng);

        let ciphertext = encrypt::<ark_std::rand::rngs::StdRng, E>(
            msg, aad, &pubkey, &mut rng,
        );
        let plaintext = checked_decrypt(&ciphertext, aad, privkey);

        assert_eq!(msg, plaintext)
    }

    // Source: https://stackoverflow.com/questions/26469715/how-do-i-write-a-rust-unit-test-that-ensures-that-a-panic-has-occurred
    // TODO: Remove after adding proper error handling to the library
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

    #[test]
    fn threshold_encryption() {
        let mut rng = &mut test_rng();
        let threshold = 16 * 2 / 3;
        let shares_num = 16;
        let num_entities = 5;
        let msg: &[u8] = "abc".as_bytes();
        let aad: &[u8] = "my-aad".as_bytes();

        let (pubkey, _privkey, contexts) =
            setup::<E>(threshold, shares_num, num_entities, &mut rng);
        let mut ciphertext = encrypt::<_, E>(msg, aad, &pubkey, rng);

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
        let s = share_combine(&shares, &prepared_blinded_key_shares);

        // So far, the ciphertext is valid
        let plaintext =
            checked_decrypt_with_shared_secret(&ciphertext, aad, &s);
        assert_eq!(plaintext, msg);

        // Malformed the ciphertext
        ciphertext.ciphertext[0] += 1;
        let result = std::panic::catch_unwind(|| {
            checked_decrypt_with_shared_secret(&ciphertext, aad, &s)
        });
        assert!(result.is_err());

        // Malformed the AAD
        let aad = "bad aad".as_bytes();
        let result = std::panic::catch_unwind(|| {
            checked_decrypt_with_shared_secret(&ciphertext, aad, &s)
        });
        assert!(result.is_err());
    }

    #[test]
    fn ciphertext_validity_check() {
        let mut rng = test_rng();
        let threshold = 3;
        let shares_num = 5;
        let num_entities = 5;
        let msg: &[u8] = "abc".as_bytes();
        let aad: &[u8] = "my-aad".as_bytes();

        let (pubkey, _privkey, _) =
            setup::<E>(threshold, shares_num, num_entities, &mut rng);
        let mut ciphertext = encrypt::<ark_std::rand::rngs::StdRng, E>(
            msg, aad, &pubkey, &mut rng,
        );

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
    fn simple_threshold_setup_and_complete_flow_from_scratch() {
        let mut rng = &mut test_rng();
        let threshold = 16 * 2 / 3;
        let shares_num = 16;
        let num_entities = 5;
        let msg: &[u8] = "abc".as_bytes();
        let aad: &[u8] = "my-aad".as_bytes();

        // To be updated
        let (pubkey, _privkey, contexts) =
            setup_simple::<E>(threshold, shares_num, num_entities, &mut rng);

        // Stays the same
        // Ciphertext.commitment is already computed to match U
        let ciphertext = encrypt::<_, E>(msg, aad, &pubkey, rng);

        let shares = contexts
            .iter()
            .map(|context| {
                let u = ciphertext.commitment;
                let i = context.index;
                let z_i = context.private_key_share.clone();
                // Really want to call E::pairing here to avoid heavy computations on client side
                let c_i = E::pairing(u, z_i.private_key_shares[0]); // Simplifying to just one key share per node
                DecryptionShareSimple {
                    decrypter_index: i,
                    decryption_share: c_i,
                }
            })
            .collect::<Vec<_>>();

        let public_decryption_contexts =
            contexts[0].public_decryption_contexts.clone();

        let lagrange =
            prepare_combine_simple(&public_decryption_contexts, &shares);

        let s = share_combine_simple::<E>(&shares, &lagrange);

        // So far, the ciphertext is valid
        let plaintext =
            checked_decrypt_with_shared_secret(&ciphertext, aad, &s);
        assert_eq!(plaintext, msg);

        // // Malformed the ciphertext
        // ciphertext.ciphertext[0] += 1;
        // let result = std::panic::catch_unwind(|| {
        //     checked_decrypt_with_shared_secret(&ciphertext, aad, &s)
        // });
        // assert!(result.is_err());

        // // Malformed the AAD
        // let aad = "bad aad".as_bytes();
        // let result = std::panic::catch_unwind(|| {
        //     checked_decrypt_with_shared_secret(&ciphertext, aad, &s)
        // });
        // assert!(result.is_err());
    }
}
