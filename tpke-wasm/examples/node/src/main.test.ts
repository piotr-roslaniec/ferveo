import {
    Ciphertext,
    decryptWithSharedSecret,
    Dkg,
    encrypt,
    SharedSecretSimpleBuilder,
    DecryptionShareSimple,
} from "tpke-wasm";

const zip = <T>(a: Array<T>, b: Array<T>) => a.map((k: T, i: number) => [k, b[i]]);

// This test suite replicates tests from tpke-wasm/tests/node.rs
describe("tpke", () => {
    it("performs simple tdec", () => {
        const sharesNum = 16;
        const threshold = (sharesNum * 2) / 3;
        const msg = Buffer.from("my-msg");
        const aad = Buffer.from("my-aad");

        const dkg = new Dkg(threshold, sharesNum);

        //
        // On the client side
        //

        // Encrypt the message
        const ciphertext = encrypt(msg, aad, dkg.public_key);

        // Serialize and send to validators
        const ciphertext_bytes = ciphertext.toBytes();

        //
        // On the server side
        //

        const ciphertext2 = Ciphertext.fromBytes(ciphertext_bytes);
        expect(ciphertext2.toBytes()).toEqual(ciphertext.toBytes());

        // Create decryption shares

        const decryptionShares = [];
        for (let i = 0; i < threshold; i++) {
            const share = dkg.makeDecryptionShareSimple(ciphertext, aad, i);
            decryptionShares.push(share);
        }

        const domainPoints = [];
        for (let i = 0; i < threshold; i++) {
            const point = dkg.getDomainPoint(i);
            domainPoints.push(point);
        }

        // Serialize and send back to client
        const decryptionSharesBytes = decryptionShares.map((s) => s.toBytes());

        //
        // On the client side
        //

        const decryptionShares2 = decryptionSharesBytes.map((b) =>
            DecryptionShareSimple.fromBytes(b)
        );
        zip(decryptionShares, decryptionShares2).map(([s1, s2]) =>
            expect(s1.toBytes()).toEqual(s2.toBytes())
        )

        // Combine shares into a shared secret
        const ssBuilder = new SharedSecretSimpleBuilder(threshold);
        decryptionShares.forEach((share) => ssBuilder.addDecryptionShare(share));

        domainPoints.forEach((point) => ssBuilder.addDomainPoint(point));

        const shared_secret = ssBuilder.build();

        // Decrypt the message
        const plaintext = decryptWithSharedSecret(
            ciphertext,
            aad,
            shared_secret,
            dkg.gInv
        );
        expect(Buffer.from(plaintext)).toEqual(msg);
    });
});
