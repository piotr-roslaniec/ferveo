use crate::*;

#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct Dkg {
    pub public_key: PublicKey,
    pub private_key: PrivateKey,
    private_contexts: Vec<tpke::api::TpkePrivateDecryptionContext>,
}

#[wasm_bindgen]
impl Dkg {
    #[wasm_bindgen(constructor)]
    pub fn new(threshold: usize, shares_num: usize) -> Self {
        set_panic_hook();

        let mut rng = rand::thread_rng();
        let (public_key, private_key, private_contexts) =
            tpke::setup_simple::<tpke::api::E>(threshold, shares_num, &mut rng);
        Self {
            public_key: PublicKey(public_key),
            private_key: PrivateKey(private_key),
            private_contexts,
        }
    }

    #[wasm_bindgen]
    pub fn make_decryption_share(
        &self,
        ciphertext: &Ciphertext,
        aad: &[u8],
        validator_index: usize,
    ) -> DecryptionShare {
        set_panic_hook();
        DecryptionShare(tpke::api::DecryptionShare(
            self.private_contexts[validator_index]
                .create_share_precomputed(&ciphertext.0 .0, aad)
                .unwrap(),
        ))
    }
}
