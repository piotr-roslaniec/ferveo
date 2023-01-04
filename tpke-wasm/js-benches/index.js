import init, {
  Setup,
  encrypt,
  ParticipantPayload,
  SharedSecretBuilder,
} from "./pkg/tpke_wasm.js";

const BENCHMARK_TRIALS = 10;

const median = (arr) => {
  const mid = Math.floor(arr.length / 2),
    nums = [...arr].sort((a, b) => a - b);
  return arr.length % 2 !== 0 ? nums[mid] : (nums[mid - 1] + nums[mid]) / 2;
};

function benchmark_encrypt(setup) {
  const message = Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
  const aad = Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);

  const perf = Array.from({ length: BENCHMARK_TRIALS }, (_, _i) => {
    const t0 = performance.now();
    encrypt(message, aad, setup.public_key);
    const t1 = performance.now();
    return t1 - t0;
  });
  return `${median(perf)} ms`;
}

function benchmark_combine(setup) {
  const message = Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
  const aad = Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
  const ciphertext = encrypt(message, aad, setup.public_key);
  // Using a push to array here instead of map because somehow map breaks 
  // DecryptionShare into Uint8Array during iteration
  const decryptionShares = [];
  setup.decrypter_indexes().forEach((index) => {
    const decryptionContext = setup.private_context_at(index);
    const share = new ParticipantPayload(
      decryptionContext,
      ciphertext
    ).to_decryption_share();
    decryptionShares.push(share);
  });

  const perf = Array.from({ length: BENCHMARK_TRIALS }, (_, _i) => {
    const t0 = performance.now();
    const ssBuilder = new SharedSecretBuilder(setup);
    decryptionShares.forEach((share) => ssBuilder.add_decryption_share(share));
    ssBuilder.build();
    const t1 = performance.now();
    return t1 - t0;
  });
  return `${median(perf)} ms`;
}

const runBenchmarks = async () => {
  console.log("Initializing ...");

  const numShares = [8, 16, 32, 64, 128];
  for (const shares of numShares) {
    const setup = new Setup(shares, shares, shares);

    const encrypt_results = benchmark_encrypt(setup);
    console.log(`encrypt: shares=${shares}: ${encrypt_results}`);

    const combine_results = benchmark_combine(setup);
    console.log(`combine: shares=${shares}: ${combine_results}`);
  }
  console.log("Done!");
};

init()
  .then(runBenchmarks)
  .catch((err) => console.error(err));
