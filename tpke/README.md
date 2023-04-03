# tpke

## Benchmarks

### Benchmarking WASM

Based on `centurion.rs` (docs)[https://github.com/bheisler/criterion.rs/blob/version-0.4/book/src/user_guide/wasi.md#webasseblywasi-benchmarking]

### Setup

```bash
cargo install cargo-wasi
npm install -g @wasmer/cli

cargo wasi build --bench=benchmarks --release
cp `ls -t ../target/wasm32-wasi/release/deps/*.wasm | head -n 1` benchmarks.wasm
```

### Running

```bash
wasmer-js run --dir=. benchmarks.wasm -- --bench
```