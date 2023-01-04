const {
    Setup,
    encrypt,
    ParticipantPayload,
} = require("../pkg/tpke_wasm.js");
const fs = require("fs");

// Convert a byte array to a hex string
function bytesToHex(bytes) {
    for (var hex = [], i = 0; i < bytes.length; i++) {
        var current = bytes[i] < 0 ? bytes[i] + 256 : bytes[i];
        hex.push((current >>> 4).toString(16));
        hex.push((current & 0xF).toString(16));
    }
    return hex.join("");
}

function persist(filePath, data) {
    try {
        fs.writeFileSync(filePath, data);
    } catch (err) {
        console.error(err);
    }
}

const makeParticipantPayloads = (setup) => {
    const message = Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    const aad = Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    const ciphertext = encrypt(message, aad, setup.public_key);

    // Using a push to array here instead of map because somehow map breaks 
    // DecryptionShare into Uint8Array during iteration
    const payloads = [];
    setup.decrypter_indexes().forEach((index) => {
        const decryptionContext = setup.private_context_at(index);
        const payload = new ParticipantPayload(
            decryptionContext,
            ciphertext
        ).to_bytes()
        payloads.push(payload);
    });
    return payloads;
}

const makeInputs = async () => {
    console.log("Running");

    const numShares = [8, 16, 32, 64, 128];
    for (const shares of numShares) {
        const setup = new Setup(shares, shares, shares);

        const payloads = makeParticipantPayloads(setup).map(bytesToHex);
        const filePath = `../tpke-python/py-benches/inputs/participant-payloads-${shares}.json`;
        
        console.log(`Writing ${filePath}`);
        persist(filePath, JSON.stringify(payloads));

    }
    console.log("Done!");
};

makeInputs()
    .catch((err) => console.error(err));
