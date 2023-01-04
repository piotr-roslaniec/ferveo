import os
import time
import json
import statistics
from tpke import ParticipantPayload

# First, load pre-generated data

inputs_path = 'py-benches/inputs'

inputs = {}
for file_name in os.listdir(inputs_path):
    with open(os.path.join(inputs_path, file_name)) as f:
        payloads = []
        for payload_hex in json.load(f):
            payload = ParticipantPayload.from_bytes(bytes.fromhex(payload_hex))
            payloads.append(payload)
        inputs[file_name] = payloads


# Now, benchmark

def bench_fn(fn, inputs):
    BENCHMARK_TRIALS = 25

    times = []
    for _ in range(BENCHMARK_TRIALS):
        start_time = time.perf_counter()
        fn(inputs)
        end_time = time.perf_counter()
        execution_time = (end_time - start_time)
        times.append(execution_time)
    return statistics.median(times)


for file_name, payloads in inputs.items():
    def fn(inputs): return [p.to_decryption_share() for p in inputs]
    median_time = bench_fn(fn, payloads)
    print(f"{file_name}: {int(median_time * 1000)} ms")  # Rounding to ms
