use criterion::criterion_main;

mod benchmarks;

criterion_main! {
    // benchmarks::pairing::micro,
    // bench_batch_inverse,
    // benchmarks::pairing::ec,
    benchmarks::validity_checks::validity_checks,
    benchmarks::eval_domain::eval_domain,
}
