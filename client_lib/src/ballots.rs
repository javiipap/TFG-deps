use wasm_bindgen::prelude::*;

use crate::errors::JsError;

#[wasm_bindgen(getter_with_clone)]
pub struct ExportedKeyPair {
    pub public: Vec<u8>,
    pub private: Vec<u8>,
}

#[wasm_bindgen]
pub fn generate_elgamal_keypair() -> Result<ExportedKeyPair, JsError> {
    let keypair = primitives::ballots::generate_elgamal_keypair();

    Ok(ExportedKeyPair {
        public: keypair.0,
        private: keypair.1,
    })
}

#[wasm_bindgen]
pub fn encrypt_vote(
    pub_key_bytes: Vec<u8>,
    choice: usize,
    options_count: usize,
) -> Result<Vec<u8>, JsError> {
    Ok(primitives::ballots::encrypt_vote(
        &pub_key_bytes,
        choice,
        options_count,
    )?)
}

#[wasm_bindgen]
pub fn decrypt_result(secret_key: Vec<u8>, raw_result: Vec<u8>) -> Result<Vec<u64>, JsError> {
    Ok(primitives::ballots::decrypt_result(
        &secret_key,
        &raw_result,
    )?)
}
