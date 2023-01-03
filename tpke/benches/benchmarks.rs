use criterion::{black_box, criterion_group, criterion_main, Criterion};
use group_threshold_cryptography::*;

const NUM_SHARES_CASES: [usize; 8] = [2, 4, 8, 16, 32, 64, 128, 256];
const MSG_SIZE: usize = 256;

type E = ark_bls12_381::Bls12_381;

pub fn bench_threshold_decryption_fast(c: &mut Criterion) {
    use rand::SeedableRng;
    use rand_core::RngCore;

    fn share_combine_bench(num_shares: usize) -> impl Fn() {
        let mut rng = &mut rand::rngs::StdRng::seed_from_u64(0);

        let threshold = num_shares * 2 / 3;
        let mut msg: Vec<u8> = vec![0u8; MSG_SIZE];
        rng.fill_bytes(&mut msg[..]);
        let aad: &[u8] = "my-aad".as_bytes();

        let (pubkey, _, contexts) = setup::<E>(threshold, num_shares, &mut rng);

        let ciphertext = encrypt::<_, E>(&msg, aad, &pubkey, rng);

        let decryption_shares: Vec<_> = contexts
            .iter()
            .map(|context| context.create_share(&ciphertext))
            .collect();

        let prepared_blinded_key_shares = prepare_combine(
            &contexts[0].public_decryption_contexts,
            &decryption_shares,
        );

        move || {
            black_box(share_combine(
                &decryption_shares,
                &prepared_blinded_key_shares,
            ));
        }
    }

    let mut group = c.benchmark_group("TPKE_FAST");
    group.sample_size(10);

    for num_shares in NUM_SHARES_CASES {
        let a = share_combine_bench(num_shares);
        group.measurement_time(core::time::Duration::new(30, 0));
        group.bench_function(
            format!(
                "share_combine: {} shares threshold 2/3 - msg-size = {} bytes",
                num_shares, MSG_SIZE
            ),
            |b| {
                #[allow(clippy::redundant_closure)]
                b.iter(|| a())
            },
        );
    }
}

pub fn bench_threshold_decryption_simple(c: &mut Criterion) {
    use rand::SeedableRng;
    use rand_core::RngCore;

    #[allow(dead_code)]
    const NUM_OF_TX: usize = 1000;

    fn share_combine_bench(num_shares: usize) -> impl Fn() {
        let mut rng = &mut rand::rngs::StdRng::seed_from_u64(0);

        let threshold = num_shares * 2 / 3;
        let mut msg: Vec<u8> = vec![0u8; MSG_SIZE];
        rng.fill_bytes(&mut msg[..]);
        let aad: &[u8] = "my-aad".as_bytes();

        let (pubkey, _, contexts) =
            setup_simple::<E>(threshold, num_shares, &mut rng);

        let ciphertext = encrypt::<_, E>(&msg, aad, &pubkey, rng);

        let decryption_shares: Vec<_> = contexts
            .iter()
            .map(|context| context.create_share(&ciphertext))
            .collect();

        let lagrange =
            prepare_combine_simple(&contexts[0].public_decryption_contexts);

        move || {
            black_box(share_combine_simple::<E>(&decryption_shares, &lagrange));
        }
    }

    let mut group = c.benchmark_group("TPKE_SIMPLE");
    group.sample_size(10);

    for num_shares in NUM_SHARES_CASES {
        let a = share_combine_bench(num_shares);
        group.measurement_time(core::time::Duration::new(30, 0));
        group.bench_function(
            format!(
                "share_combine: {} shares threshold 2/3 - msg-size = {} bytes",
                num_shares, MSG_SIZE
            ),
            |b| {
                #[allow(clippy::redundant_closure)]
                b.iter(|| a())
            },
        );
    }
}

criterion_group!(
    benches,
    bench_threshold_decryption_fast,
    bench_threshold_decryption_simple
);
criterion_main!(benches);
