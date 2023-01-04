# Benchmarks

## Hardware

Benchmarks produced on:

- Intel® Core™ i7-10875H CPU @ 2.30GHz × 16 (single-threaded),
- Version 107.0.5304.110 (Official Build) (64-bit),
- Pop!\_OS 22.04 LTS (64-bit),

### Setup

First, build the WASM target and make inputs for Python benchmarks:

```bash
cd tpke-wasm
wasm-pack build --release --target nodejs # Notice the target
node scripts/make-python-bench-inputs.js
```

Then, build and install the Python package:

```bash
cd tpke-python
pip install -e .
```

### Running

```bash
cd tpke-python
python py-benches/benchmark.py

```

## Results

Using fixed values, such that `shares=num_entities=threshold`.

Rounding to nearest ms.

### Python Results

Filename refers to the number of shares.

```
participant-payloads-8.json:   2 ms
participant-payloads-16.json:  3 ms
participant-payloads-32.json:  6 ms
participant-payloads-64.json:  12 ms
participant-payloads-128.json: 25 ms
```
