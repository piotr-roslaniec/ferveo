import { Keypair } from "ferveo-wasm";

// Just testing that the WASM module is loaded correctly
// JS tests are already written in the examples/node

Keypair.random();

console.log("Success! 🎉");
