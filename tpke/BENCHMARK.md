# Benchmarks

## Hardware

Benchmarks produced on:

- Intel® Core™ i7-10875H CPU @ 2.30GHz × 16 (single-threaded),
- Version 107.0.5304.110 (Official Build) (64-bit),
- Pop!\_OS 22.04 LTS (64-bit),

````bash

## Benchmarking WASM

Based on `centurion.rs` (docs)[https://github.com/bheisler/criterion.rs/blob/version-0.4/book/src/user_guide/wasi.md#webasseblywasi-benchmarking]

### Setup

```bash
cargo install cargo-wasi
npm install -g @wasmer/cli

cargo wasi build --bench=benchmarks --release
cp `ls -t ../target/wasm32-wasi/release/deps/*.wasm | head -n 1` benchmarks.wasm
````

### Running

```bash
wasmer-js run --dir=. benchmarks.wasm -- --bench
```

## Benchmarking Rust

```bash
cargo bench
```

## Results

### WASM Results

```
TPKE/share_combine: 100 validators threshold 1024*2/3 - #msg 1 - msg-size = 100 bytes
                        time:   [203.07 ms 203.63 ms 204.31 ms]
TPKE/share_combine: 100 validators threshold 2048*2/3 - #msg 1 - msg-size = 100 bytes
                        time:   [202.04 ms 202.49 ms 203.37 ms]
TPKE/share_combine: 100 validators threshold 4096*2/3 - #msg 1 - msg-size = 100 bytes
                        time:   [201.94 ms 202.74 ms 203.32 ms]
TPKE/share_combine: 100 validators threshold 8192*2/3 - #msg 1 - msg-size = 100 bytes
                        time:   [194.89 ms 195.44 ms 196.43 ms]
TPKE/share_combine: 150 validators threshold 1024*2/3 - #msg 1 - msg-size = 100 bytes
                        time:   [291.00 ms 291.93 ms 292.94 ms]
TPKE/share_combine: 150 validators threshold 2048*2/3 - #msg 1 - msg-size = 100 bytes
                        time:   [287.92 ms 291.28 ms 293.63 ms]
TPKE/share_combine: 150 validators threshold 4096*2/3 - #msg 1 - msg-size = 100 bytes
                        time:   [291.20 ms 291.94 ms 292.61 ms]
TPKE/share_combine: 150 validators threshold 8192*2/3 - #msg 1 - msg-size = 100 bytes
                        time:   [292.36 ms 293.98 ms 295.60 ms]
TPKE/share_combine: 200 validators threshold 1024*2/3 - #msg 1 - msg-size = 100 bytes
                        time:   [429.51 ms 431.92 ms 434.20 ms]
TPKE/share_combine: 200 validators threshold 2048*2/3 - #msg 1 - msg-size = 100 bytes
                        time:   [427.99 ms 429.13 ms 430.25 ms]
TPKE/share_combine: 200 validators threshold 4096*2/3 - #msg 1 - msg-size = 100 bytes
                        time:   [428.54 ms 429.52 ms 430.93 ms]
TPKE/share_combine: 200 validators threshold 8192*2/3 - #msg 1 - msg-size = 100 bytes
                        time:   [413.68 ms 426.59 ms 434.22 ms]
```

### Rust Results

```
TPKE/share_combine: 100 validators threshold 1024*2/3 - #msg 1 - msg-size = 100 bytes
                        time:   [39.402 ms 39.933 ms 40.442 ms]
                        change: [-78.967% -78.479% -78.003%] (p = 0.00 < 0.05)
TPKE/share_combine: 100 validators threshold 2048*2/3 - #msg 1 - msg-size = 100 bytes
                        time:   [36.905 ms 37.714 ms 38.555 ms]
                        change: [-79.026% -78.298% -77.409%] (p = 0.00 < 0.05)
                        Performance has improved.
TPKE/share_combine: 100 validators threshold 4096*2/3 - #msg 1 - msg-size = 100 bytes
                        time:   [38.335 ms 39.103 ms 40.138 ms]
                        change: [-79.030% -78.666% -78.289%] (p = 0.00 < 0.05)
                        Performance has improved.
TPKE/share_combine: 100 validators threshold 8192*2/3 - #msg 1 - msg-size = 100 bytes
                        time:   [37.560 ms 39.477 ms 41.840 ms]
                        change: [-78.908% -78.079% -77.420%] (p = 0.00 < 0.05)
                        Performance has improved.
TPKE/share_combine: 150 validators threshold 1024*2/3 - #msg 1 - msg-size = 100 bytes
                        time:   [59.445 ms 60.015 ms 60.918 ms]
                        change: [-77.813% -77.500% -77.138%] (p = 0.00 < 0.05)
                        Performance has improved.
TPKE/share_combine: 150 validators threshold 2048*2/3 - #msg 1 - msg-size = 100 bytes
                        time:   [57.400 ms 58.897 ms 59.917 ms]
                        change: [-79.208% -78.475% -77.800%] (p = 0.00 < 0.05)
                        Performance has improved.
TPKE/share_combine: 150 validators threshold 4096*2/3 - #msg 1 - msg-size = 100 bytes
                        time:   [55.343 ms 56.937 ms 59.751 ms]
                        change: [-79.182% -78.302% -77.213%] (p = 0.00 < 0.05)
                        Performance has improved.
TPKE/share_combine: 150 validators threshold 8192*2/3 - #msg 1 - msg-size = 100 bytes
                        time:   [58.516 ms 59.499 ms 60.542 ms]
                        change: [-79.088% -78.442% -77.787%] (p = 0.00 < 0.05)
                        Performance has improved.
TPKE/share_combine: 200 validators threshold 1024*2/3 - #msg 1 - msg-size = 100 bytes
                        time:   [78.889 ms 79.303 ms 79.871 ms]
                        change: [-79.477% -78.764% -78.196%] (p = 0.00 < 0.05)
                        Performance has improved.
TPKE/share_combine: 200 validators threshold 2048*2/3 - #msg 1 - msg-size = 100 bytes
                        time:   [78.631 ms 79.323 ms 79.960 ms]
                        change: [-78.776% -78.250% -77.742%] (p = 0.00 < 0.05)
                        Performance has improved.
TPKE/share_combine: 200 validators threshold 4096*2/3 - #msg 1 - msg-size = 100 bytes
                        time:   [76.580 ms 77.272 ms 78.058 ms]
                        change: [-78.700% -78.253% -77.767%] (p = 0.00 < 0.05)
                        Performance has improved.
TPKE/share_combine: 200 validators threshold 8192*2/3 - #msg 1 - msg-size = 100 bytes
                        time:   [76.676 ms 77.459 ms 78.123 ms]
                        change: [-80.315% -79.559% -78.876%] (p = 0.00 < 0.05)
                        Performance has improved.
```
