import {
  decryptWithSharedSecret,
  Dkg,
  ferveoEncrypt,
  DecryptionShareSimple,
  Keypair,
  Validator,
  AggregatedTranscript,
  combineDecryptionSharesSimple,
  ValidatorMessage,
  DecryptionSharePrecomputed,
  combineDecryptionSharesPrecomputed,
  EthereumAddress,
} from "ferveo-wasm";

const zip = <A1, A2>(a: Array<A1>, b: Array<A2>): Array<[A1, A2]> =>
  a.map((k: A1, i: number) => [k, b[i]]);

const genEthAddr = (i: number) => {
  const ethAddr =
    "0x" + "0".repeat(40 - i.toString(16).length) + i.toString(16);
  return EthereumAddress.fromString(ethAddr);
};

function setupTest() {
  const tau = 1;
  const sharesNum = 4;
  const threshold = Math.floor((sharesNum * 2) / 3);

  const validatorKeypairs: Keypair[] = [];
  const validators: Validator[] = [];
  for (let i = 0; i < sharesNum; i++) {
    const keypair = Keypair.random();
    validatorKeypairs.push(keypair);
    const validator = new Validator(genEthAddr(i), keypair.publicKey);
    validators.push(validator);
  }

  // Each validator holds their own DKG instance and generates a transcript every
  // validator, including themselves
  const messages: ValidatorMessage[] = [];
  validators.forEach((sender) => {
    const dkg = new Dkg(tau, sharesNum, threshold, validators, sender);
    const transcript = dkg.generateTranscript();
    const message = new ValidatorMessage(sender, transcript);
    messages.push(message);
  });

  // Now that every validator holds a dkg instance and a transcript for every other validator,
  // every validator can aggregate the transcripts
  const dkg = new Dkg(tau, sharesNum, threshold, validators, validators[0]);

  const serverAggregate = dkg.aggregateTranscript(messages);
  expect(serverAggregate.verify(sharesNum, messages)).toBe(true);

  // Client can also aggregate the transcripts and verify them
  const clientAggregate = new AggregatedTranscript(messages);
  expect(clientAggregate.verify(sharesNum, messages)).toBe(true);

  // In the meantime, the client creates a ciphertext and decryption request
  const msg = Buffer.from("my-msg");
  const aad = Buffer.from("my-aad");
  const ciphertext = ferveoEncrypt(msg, aad, dkg.publicKey());

  return {
    tau,
    sharesNum,
    threshold,
    validatorKeypairs,
    validators,
    dkg,
    messages,
    msg,
    aad,
    ciphertext,
  };
}

// This test suite replicates tests from ferveo-wasm/tests/node.rs
describe("ferveo-wasm", () => {
  it("simple tdec variant", () => {
    const {
      tau,
      sharesNum,
      threshold,
      validatorKeypairs,
      validators,
      messages,
      msg,
      aad,
      ciphertext,
    } = setupTest();

    // Having aggregated the transcripts, the validators can now create decryption shares
    const decryptionShares: DecryptionShareSimple[] = [];
    zip(validators, validatorKeypairs).forEach(([validator, keypair]) => {
      expect(validator.publicKey.equals(keypair.publicKey)).toBe(true);

      const dkg = new Dkg(tau, sharesNum, threshold, validators, validator);
      const aggregate = dkg.aggregateTranscript(messages);
      const isValid = aggregate.verify(sharesNum, messages);
      expect(isValid).toBe(true);

      const decryptionShare = aggregate.createDecryptionShareSimple(
        dkg,
        ciphertext.header,
        aad,
        keypair
      );
      decryptionShares.push(decryptionShare);
    });

    // Now, the decryption share can be used to decrypt the ciphertext
    // This part is in the client API

    const sharedSecret = combineDecryptionSharesSimple(
      decryptionShares,
    );

    // The client should have access to the public parameters of the DKG

    const plaintext = decryptWithSharedSecret(
      ciphertext,
      aad,
      sharedSecret,
    );
    expect(Buffer.from(plaintext)).toEqual(msg);
  });

  it("precomputed tdec variant", () => {
    const {
      tau,
      sharesNum,
      threshold,
      validatorKeypairs,
      validators,
      messages,
      msg,
      aad,
      ciphertext,
    } = setupTest();

    // Having aggregated the transcripts, the validators can now create decryption shares
    const decryptionShares: DecryptionSharePrecomputed[] = [];
    zip(validators, validatorKeypairs).forEach(([validator, keypair]) => {
      const dkg = new Dkg(tau, sharesNum, threshold, validators, validator);
      const aggregate = dkg.aggregateTranscript(messages);
      const isValid = aggregate.verify(sharesNum, messages);
      expect(isValid).toBe(true);

      const decryptionShare = aggregate.createDecryptionSharePrecomputed(
        dkg,
        ciphertext.header,
        aad,
        keypair
      );
      decryptionShares.push(decryptionShare);
    });

    // Now, the decryption share can be used to decrypt the ciphertext
    // This part is in the client API

    const sharedSecret = combineDecryptionSharesPrecomputed(decryptionShares);

    // The client should have access to the public parameters of the DKG

    const plaintext = decryptWithSharedSecret(
      ciphertext,
      aad,
      sharedSecret,
    );
    expect(Buffer.from(plaintext)).toEqual(msg);
  });
});
