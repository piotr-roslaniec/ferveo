use criterion::{black_box, criterion_group, criterion_main, Criterion};

pub fn bench_encrypt_combine(c: &mut Criterion) {
    use tpke_wasm::*;

    fn bench_encrypt(
        num_shares: usize,
        num_entities: usize,
        threshold: usize,
    ) -> impl Fn() {
        let message = "my-secret-message".as_bytes().to_vec();
        let aad = "my-aad".as_bytes().to_vec();
        let setup = Setup::new(threshold, num_shares, num_entities);
        move || {
            let message = message.clone();
            let aad = aad.clone();
            black_box(encrypt(&message, &aad, &setup.public_key));
        }
    }

    fn bench_combine(
        num_shares: usize,
        num_entities: usize,
        threshold: usize,
    ) -> impl Fn() {
        let message = "my-secret-message".as_bytes().to_vec();
        let aad = "my-aad".as_bytes().to_vec();
        let setup = Setup::new(threshold, num_shares, num_entities);
        let ciphertext = encrypt(&message.to_vec(), &aad, &setup.public_key);
        let participant_payloads: Vec<ParticipantPayload> = setup
            .decrypter_indexes()
            .iter()
            .map(|index| {
                ParticipantPayload::new(
                    &setup.private_context_at(*index),
                    &ciphertext.clone(),
                )
            })
            .collect();
        let decryption_shares: Vec<DecryptionShare> = participant_payloads
            .iter()
            .map(|p| p.to_decryption_share())
            .collect();

        move || {
            let setup = setup.clone();
            let decryption_shares = decryption_shares.clone();
            black_box({
                let mut ss_builder = SharedSecretBuilder::new(&setup);
                for share in decryption_shares {
                    ss_builder.add_decryption_share(&share);
                }
                ss_builder.build();
            })
        }
    }

    let mut group = c.benchmark_group("TPKE-WASM");
    group.sample_size(10);

    for num_shares in [8, 16, 32, 64, 128].iter() {
        let encrypt_fn = bench_encrypt(*num_shares, *num_shares, *num_shares);
        group.measurement_time(core::time::Duration::new(30, 0));
        group.bench_function(format!("tpke-wasm::encrypt - num_shares={}, num_entities={}, threshold={}", num_shares, num_shares, num_shares), |b| {
                b.iter(|| encrypt_fn())
            });

        let combine_fn = bench_combine(*num_shares, *num_shares, *num_shares);
        group.measurement_time(core::time::Duration::new(30, 0));
        group.bench_function(format!("tpke-wasm::combine - num_shares={}, num_entities={}, threshold={}", num_shares, num_shares, num_shares), |b| {
                    b.iter(|| combine_fn())
                });
    }
}

criterion_group!(benches, bench_encrypt_combine);
criterion_main!(benches);
