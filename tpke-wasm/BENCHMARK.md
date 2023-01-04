# Benchmarks

## Hardware

Benchmarks produced on:

- Intel® Core™ i7-10875H CPU @ 2.30GHz × 16 (single-threaded),
- Version 107.0.5304.110 (Official Build) (64-bit),
- Pop!\_OS 22.04 LTS (64-bit),

## Benchmarking WASM

This time we may not use [`centurion.rs`](https://github.com/bheisler/criterion.rs/blob/version-0.4/book/src/user_guide/wasi.md#webasseblywasi-benchmarking) because `wasm32-wasi` is incompatible with `wasm_bindgen` ([1](https://github.com/rustwasm/wasm-bindgen/issues/2554), [2](https://github.com/bevyengine/bevy/discussions/5908?sort=new)). Instead, we're going to measure performance directly in the browser.

### Setup

```bash
wasm-pack build --release --target web

cd js-benches
ln -s ../pkg .
```

### Running

```bash
npx http-server
# Visit localhost:8080/index.html
```

## Benchmarking Rust

```bash
cargo bench
```

## Results

Using fixed values, such that `shares=num_entities=threshold`.

Rounding to nearest ms.

### WASM Results

```
encrypt: shares=8:   71 ms
encrypt: shares=16:  70 ms
encrypt: shares=32:  70 ms
encrypt: shares=64:  70 ms
encrypt: shares=128: 72 ms

combine: shares=8:   145 ms
combine: shares=16:  278 ms
combine: shares=32:  554 ms
combine: shares=64:  1079 ms
combine: shares=128: 2253 ms
```

### Rust Results

Results rewritten for clarity:

```
encrypt: shares=8:   5 ms
encrypt: shares=16:  5 ms
encrypt: shares=32:  5 ms
encrypt: shares=64:  5 ms
encrypt: shares=128: 5 ms

combine: shares=8:   10 ms
combine: shares=16:  20 ms
combine: shares=32:  39 ms
combine: shares=64:  82 ms
combine: shares=128: 162 ms
```

Raw results from `cargo bench`:

```
TPKE-WASM/tpke-wasm::encrypt - num_shares=8, num_entities=8, threshold=8
time: [4.8288 ms 4.9155 ms 5.0219 ms]
TPKE-WASM/tpke-wasm::combine - num_shares=8, num_entities=8, threshold=8
time: [10.197 ms 10.452 ms 10.994 ms]

TPKE-WASM/tpke-wasm::encrypt - num_shares=16, num_entities=16, threshold=16
time: [4.9404 ms 5.0003 ms 5.1142 ms]
TPKE-WASM/tpke-wasm::combine - num_shares=16, num_entities=16, threshold=16
time: [19.536 ms 20.278 ms 20.924 ms]

TPKE-WASM/tpke-wasm::encrypt - num_shares=32, num_entities=32, threshold=32
time: [4.8744 ms 5.0070 ms 5.1049 ms]
TPKE-WASM/tpke-wasm::combine - num_shares=32, num_entities=32, threshold=32
time: [38.619 ms 39.276 ms 39.939 ms]

TPKE-WASM/tpke-wasm::encrypt - num_shares=64, num_entities=64, threshold=64
time: [5.0275 ms 5.1389 ms 5.2306 ms]
TPKE-WASM/tpke-wasm::combine - num_shares=64, num_entities=64, threshold=64
time: [76.279 ms 82.054 ms 87.068 ms]

TPKE-WASM/tpke-wasm::encrypt - num_shares=128, num_entities=128, threshold=128
time: [4.9211 ms 5.0305 ms 5.1302 ms]
TPKE-WASM/tpke-wasm::combine - num_shares=128, num_entities=128, threshold=128
time: [155.29 ms 162.48 ms 174.21 ms]
```
