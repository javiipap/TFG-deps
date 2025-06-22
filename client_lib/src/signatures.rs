use crate::errors::JsError;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn rsa_encrypt(public_key: Vec<u8>, msg: Vec<u8>) -> Result<Vec<u8>, JsError> {
    Ok(primitives::signatures::rsa_encrypt(public_key, msg)?)
}

#[wasm_bindgen]
pub fn rsa_verify(public_key: Vec<u8>, signature: Vec<u8>, hash: Vec<u8>) -> Result<(), JsError> {
    primitives::signatures::rsa_verify(public_key, hash, signature)?;

    Ok(())
}

#[wasm_bindgen]
pub fn rsa_decrypt(private_key: Vec<u8>, ecnrypted: Vec<u8>) -> Result<Vec<u8>, JsError> {
    Ok(primitives::signatures::rsa_decrypt(private_key, ecnrypted)?)
}
