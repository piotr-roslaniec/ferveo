#![allow(non_snake_case)]

use ark_bls12_381::*;
use ark_ec::*;
use criterion::{black_box, criterion_group, Criterion};

use ark_ff::Field;
use ark_std::UniformRand;

pub fn lagrange(c: &mut Criterion) {
    let rng = &mut ark_std::test_rng();
    let mut group = c.benchmark_group("lagrange running time");
    group.sample_size(10);

    group.measurement_time(core::time::Duration::new(30, 0));
    let mut u = vec![];
    for _ in 0..(8192 * 2 / 3) {
        u.push(ScalarField::rand(rng));
    }
    group.bench_function("BLS12-381 Fr 8192*2/3 lagrange coefficients", |b| {
        b.iter(|| {
            black_box(
                subproductdomain::SubproductDomain::<ScalarField>::new(u.clone())
                    .inverse_lagrange_coefficients(),
            )
        })
    });

    use ark_ed_on_bls12_381 as jubjub;

    let mut u = vec![];
    for _ in 0..(8192 * 2 / 3) {
        u.push(jubjub::ScalarField::rand(rng));
    }

    group.bench_function("Jubjub Fr 8192*2/3 lagrange coefficients", |b| {
        b.iter(|| {
            black_box(
                subproductdomain::SubproductDomain::<jubjub::ScalarField>::new(
                    u.clone(),
                )
                    .inverse_lagrange_coefficients(),
            )
        })
    });
}

pub fn pairing(c: &mut Criterion) {
    let rng = &mut ark_std::test_rng();
    let mut group = c.benchmark_group("pairing running time");
    group.sample_size(10);

    type G1Prepared = <Bls12_381 as Pairing>::G1Prepared;
    type G2Prepared = <Bls12_381 as Pairing>::G2Prepared;

    let P = (0..100)
        .map(|_| {
            G1Affine::generator()
                .mul(ScalarField::rand(rng))
                .into_affine()
        })
        .collect::<Vec<G1Affine>>();
    let Q = (0..100)
        .map(|_| {
            G2Affine::generator()
                .mul(ScalarField::rand(rng))
                .into_affine()
        })
        .collect::<Vec<G2Affine>>();
    group.measurement_time(core::time::Duration::new(10, 0));
    group.bench_function("BLS12-381 pairing", |b| {
        b.iter(|| black_box(Bls12_381::pairing(P[0], Q[0])))
    });
    let PQ = &P
        .iter()
        .zip(Q.iter())
        .map(|(i, j)| (G1Prepared::from(*i), G2Prepared::from(*j)))
        .collect::<Vec<(G1Prepared, G2Prepared)>>();

    group.bench_function("BLS12-381 G1Prepared", |b| {
        b.iter(|| {
            black_box(
                P.iter().map(|i| G1Prepared::from(*i)).collect::<Vec<_>>(),
            )
        })
    });
    group.bench_function("BLS12-381 G2Prepared", |b| {
        b.iter(|| {
            black_box(
                Q.iter().map(|i| G2Prepared::from(*i)).collect::<Vec<_>>(),
            )
        })
    });
    group.bench_function("BLS12-381 product_of_pairing G2 prepared", |b| {
        b.iter(|| {
            (
                black_box(
                    P.iter().map(|i| G1Prepared::from(*i)).collect::<Vec<_>>(),
                ),
                black_box(Bls12_381::multi_pairing(PQ.iter())),
            )
        })
    });
    group.bench_function("BLS12-381 product_of_pairing both prepared", |b| {
        b.iter(|| black_box(Bls12_381::multi_pairing(PQ.iter())))
    });

    let Q_j = G2Affine::generator()
        .mul(ScalarField::rand(rng))
        .into_affine();
    let r = ScalarField::rand(rng);

    group.bench_function("BLS12-381 100 linear combine G1", |b| {
        b.iter(|| black_box(P.iter().map(|i| i.mul(r)).sum::<G1>()))
    });

    group.bench_function("BLS12-381 100 linear combine G2", |b| {
        b.iter(|| black_box(Q.iter().map(|i| i.mul(r)).sum::<G2Projective>()))
    });

    let P = (0..(8192 * 2 / 3))
        .map(|_| {
            G1Affine::generator()
                .mul(ScalarField::rand(rng))
                .into_affine()
        })
        .collect::<Vec<G1Affine>>();

    let mut u = vec![];
    for _ in 0..(8192 * 2 / 3) {
        u.push(ScalarField::rand(rng));
    }

    let lagrange = subproductdomain::SubproductDomain::<ScalarField>::new(u.clone())
        .inverse_lagrange_coefficients()
        .iter()
        .map(|x| x.inverse().unwrap())
        .collect::<Vec<_>>();

    group.bench_function("BLS12-381 8192*2/3 share combine G1", |b| {
        b.iter(|| {
            black_box(
                P.iter()
                    .zip(lagrange.iter())
                    .map(|(i, lambda)| i.mul(*lambda))
                    .sum::<G1>()
                    .into_affine(),
            )
        })
    });

    use ark_ec::msm::FixedBase;
    let window_size = FixedBase::get_mul_window_size(3000);

    use ark_ff::PrimeField;
    let scalar_bits = ScalarField::size_in_bits();
    let base_table = FixedBase::get_window_table(
        scalar_bits,
        window_size,
        Q_j.into_group(),
    );
    group.measurement_time(core::time::Duration::new(30, 0));

    group.bench_function("BLS12-381 100 MSM linear combine G2", |b| {
        b.iter(|| {
            black_box(
                Q.iter()
                    .map(|_| {
                        FixedBase::msm::<G2Projective>(
                            scalar_bits,
                            window_size,
                            &base_table,
                            &[r],
                        )[0]
                    })
                    .sum::<G2Projective>(),
            )
        })
    });

    let Q = (0..(8192 * 2 / 3))
        .map(|_| {
            G2Affine::generator()
                .mul(ScalarField::rand(rng))
                .into_affine()
        })
        .collect::<Vec<G2Affine>>();

    group.bench_function("BLS12-381 8192*2/3 G2Prepared", |b| {
        b.iter(|| {
            black_box(
                Q.iter().map(|i| G2Prepared::from(*i)).collect::<Vec<_>>(),
            )
        })
    });
    let _base_tables = Q
        .iter()
        .map(|q| {
            FixedBase::get_window_table(
                scalar_bits,
                window_size,
                q.into_group(),
            )
        })
        .collect::<Vec<_>>();

    group.bench_function("BLS12-381 share combine precompute", |b| {
        b.iter(|| {
            black_box(
                Q.iter()
                    .zip(lagrange.iter())
                    .map(|(_, lambda)| {
                        FixedBase::msm::<G2Projective>(
                            scalar_bits,
                            window_size,
                            &base_table,
                            &[*lambda],
                        )[0]
                    })
                    .sum::<G2Projective>(),
            )
        })
    });

    use ark_ed_on_bls12_381 as jubjub;
    let P = (0..(8192 * 2 / 3))
        .map(|_| {
            jubjub::EdwardsAffine::generator()
                .mul(jubjub::ScalarField::rand(rng))
                .into_affine()
        })
        .collect::<Vec<_>>();

    let mut u = vec![];
    for _ in 0..(8192 * 2 / 3) {
        u.push(jubjub::ScalarField::rand(rng));
    }
    /*let lagrange = ferveo::SubproductDomain::<jubjub::ScalarField>::new(u.clone())
    .inverse_lagrange_coefficients()
    .iter()
    .map(|x| x.inverse().unwrap())
    .collect::<Vec<_>>();*/

    group.bench_function("8192*2/3 share combine Jubjub", |b| {
        b.iter(|| {
            black_box(
                P.iter()
                    .zip(u.iter())
                    .map(|(i, lambda)| i.mul(*lambda))
                    .sum::<jubjub::EdwardsProjective>()
                    .into_affine(),
            )
        })
    });
}

pub fn bench_batch_inverse(c: &mut Criterion) {
    let rng = &mut ark_std::test_rng();
    let n = 8192 * 2 / 3;
    let a = (0..n)
        .map(|_| ark_bls12_381::ScalarField::rand(rng))
        .collect::<Vec<_>>();

    let mut group = c.benchmark_group("BLS12-381 Batch inverse");
    group.sample_size(10);
    group.measurement_time(core::time::Duration::new(30, 0));
    group.bench_with_input(
        criterion::BenchmarkId::new("BLS12-381 Batch inverse", n),
        &a,
        |b, a| {
            #[allow(clippy::unit_arg)]
            b.iter(|| black_box(ark_ff::batch_inversion(&mut a.clone())));
        },
    );
}

criterion_group!(
    ec,
    pairing,
    lagrange,
    bench_batch_inverse
);

criterion_group!(micro, bench_batch_inverse);
