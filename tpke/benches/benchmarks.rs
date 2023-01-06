use ark_bls12_381::{Fr, G1Affine, G2Affine};
use criterion::{
    black_box, criterion_group, criterion_main, BenchmarkId, Criterion,
};
use group_threshold_cryptography::*;
use rand::prelude::StdRng;
use rand_core::RngCore;

const SHARES_NUM_CASES: [usize; 6] = [4, 8, 16, 32, 64, 128];
const MSG_SIZE: usize = 256;

type E = ark_bls12_381::Bls12_381;
type G2Prepared = ark_ec::bls12::G2Prepared<ark_bls12_381::Parameters>;

#[allow(dead_code)]
struct SetupShared {
    threshold: usize,
    shares_num: usize,
    msg: Vec<u8>,
    aad: Vec<u8>,
    pubkey: G1Affine,
    privkey: G2Affine,
    ciphertext: Ciphertext<E>,
}

struct SetupFast {
    shared: SetupShared,
    contexts: Vec<PrivateDecryptionContext<E>>,
    pub_contexts: Vec<PublicDecryptionContext<E>>,
    decryption_shares: Vec<DecryptionShare<E>>,
    prepared_key_shares: Vec<G2Prepared>,
}

impl SetupFast {
    pub fn new(shares_num: usize, rng: &mut StdRng) -> Self {
        let threshold = shares_num * 2 / 3;
        let mut msg: Vec<u8> = vec![0u8; MSG_SIZE];
        rng.fill_bytes(&mut msg[..]);
        let aad: &[u8] = "my-aad".as_bytes();

        let (pubkey, privkey, contexts) =
            setup::<E>(threshold, shares_num, rng);
        let ciphertext = encrypt::<_, E>(&msg, aad, &pubkey, rng);

        let mut decryption_shares: Vec<DecryptionShare<E>> = vec![];
        for context in contexts.iter() {
            decryption_shares.push(context.create_share(&ciphertext));
        }

        let pub_contexts = contexts[0].clone().public_decryption_contexts;
        let prepared_key_shares =
            prepare_combine(&pub_contexts, &decryption_shares);

        let shared = SetupShared {
            threshold,
            shares_num,
            msg: msg.to_vec(),
            aad: aad.to_vec(),
            pubkey,
            privkey,
            ciphertext,
        };
        Self {
            shared,
            contexts,
            pub_contexts,
            decryption_shares,
            prepared_key_shares,
        }
    }
}

struct SetupSimple {
    shared: SetupShared,
    contexts: Vec<PrivateDecryptionContextSimple<E>>,
    pub_contexts: Vec<PublicDecryptionContextSimple<E>>,
    decryption_shares: Vec<DecryptionShareSimple<E>>,
    lagrange: Vec<Fr>,
}

impl SetupSimple {
    pub fn new(shares_num: usize, rng: &mut StdRng) -> Self {
        let threshold = shares_num * 2 / 3;
        let mut msg: Vec<u8> = vec![0u8; MSG_SIZE];
        rng.fill_bytes(&mut msg[..]);
        let aad: &[u8] = "my-aad".as_bytes();

        let (pubkey, privkey, contexts) =
            setup_simple::<E>(threshold, shares_num, rng);

        // Ciphertext.commitment is already computed to match U
        let ciphertext = encrypt::<_, E>(&msg, aad, &pubkey, rng);

        // Creating decryption shares
        let decryption_shares: Vec<_> = contexts
            .iter()
            .map(|context| context.create_share(&ciphertext))
            .collect();

        let pub_contexts = contexts[0].clone().public_decryption_contexts;
        let lagrange = prepare_combine_simple::<E>(&pub_contexts);

        let shared = SetupShared {
            threshold,
            shares_num,
            msg: msg.to_vec(),
            aad: aad.to_vec(),
            pubkey,
            privkey,
            ciphertext,
        };
        Self {
            shared,
            contexts,
            pub_contexts,
            decryption_shares,
            lagrange,
        }
    }
}

pub fn bench_create_decryption_share(c: &mut Criterion) {
    use rand::SeedableRng;

    let rng = &mut StdRng::seed_from_u64(0);
    let mut group = c.benchmark_group("SHARE CREATE");

    for shares_num in SHARES_NUM_CASES {
        let fast = {
            let setup = SetupFast::new(shares_num, rng);
            move || {
                black_box({
                    // TODO: Consider running benchmarks for a single iteration and not for all iterations.
                    // This way we could test the performance of this method for a single participant.
                    setup
                        .contexts
                        .iter()
                        .map(|ctx| ctx.create_share(&setup.shared.ciphertext))
                        .collect::<Vec<_>>()
                })
            }
        };
        let simple = {
            let setup = SetupSimple::new(shares_num, rng);
            move || {
                black_box({
                    // TODO: Consider running benchmarks for a single iteration and not for all iterations.
                    // This way we could test the performance of this method for a single participant.
                    setup
                        .contexts
                        .iter()
                        .map(|ctx| ctx.create_share(&setup.shared.ciphertext))
                        .collect::<Vec<_>>()
                })
            }
        };

        group.sample_size(10);
        group.bench_function(
            BenchmarkId::new("share_create_fast", shares_num),
            |b| {
                #[allow(clippy::redundant_closure)]
                b.iter(|| fast())
            },
        );
        group.bench_function(
            BenchmarkId::new("share_create_simple", shares_num),
            |b| {
                #[allow(clippy::redundant_closure)]
                b.iter(|| simple())
            },
        );
    }
}

pub fn bench_share_prepare(c: &mut Criterion) {
    use rand::SeedableRng;
    let rng = &mut StdRng::seed_from_u64(0);
    let mut group = c.benchmark_group("SHARE PREPARE");

    for shares_num in SHARES_NUM_CASES {
        let fast = {
            let setup = SetupFast::new(shares_num, rng);
            move || {
                black_box(prepare_combine(
                    &setup.pub_contexts,
                    &setup.decryption_shares,
                ))
            }
        };
        let simple = {
            let setup = SetupSimple::new(shares_num, rng);
            move || black_box(prepare_combine_simple(&setup.pub_contexts))
        };

        group.sample_size(10);
        group.bench_function(
            BenchmarkId::new("share_prepare_fast", shares_num),
            |b| {
                #[allow(clippy::redundant_closure)]
                b.iter(|| fast())
            },
        );
        group.bench_function(
            BenchmarkId::new("share_prepare_simple", shares_num),
            |b| {
                #[allow(clippy::redundant_closure)]
                b.iter(|| simple())
            },
        );
    }
}

pub fn bench_share_combine(c: &mut Criterion) {
    use rand::SeedableRng;

    let rng = &mut StdRng::seed_from_u64(0);
    let mut group = c.benchmark_group("SHARE COMBINE");

    for shares_num in SHARES_NUM_CASES {
        let fast = {
            let setup = SetupFast::new(shares_num, rng);
            move || {
                black_box(share_combine(
                    &setup.decryption_shares,
                    &setup.prepared_key_shares,
                ));
            }
        };
        let simple = {
            let setup = SetupSimple::new(shares_num, rng);
            move || {
                black_box(share_combine_simple::<E>(
                    &setup.decryption_shares,
                    &setup.lagrange,
                ));
            }
        };

        group.sample_size(10);
        group.bench_function(
            BenchmarkId::new("share_combine_fast", shares_num),
            |b| {
                #[allow(clippy::redundant_closure)]
                b.iter(|| fast())
            },
        );
        group.bench_function(
            BenchmarkId::new("share_combine_simple", shares_num),
            |b| {
                #[allow(clippy::redundant_closure)]
                b.iter(|| simple())
            },
        );
    }
}

criterion_group!(
    benches,
    bench_create_decryption_share,
    bench_share_prepare,
    bench_share_combine
);
criterion_main!(benches);
