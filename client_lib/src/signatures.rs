use crate::errors::JsError;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
/// Encrypts a message using RSA-PKCS1v15.
///
/// # Arguments
/// * `public_key` - The RSA public key in DER format.
/// * `msg` - The message bytes to encrypt.
///
/// # Returns
/// * `Result<Vec<u8>, JsError>` - The encrypted message, or an error.
pub fn rsa_encrypt(public_key: Vec<u8>, msg: Vec<u8>) -> Result<Vec<u8>, JsError> {
    Ok(primitives::signatures::rsa_encrypt(&public_key, &msg)?)
}

#[wasm_bindgen]
/// Verifies an RSA-PKCS1v15 signature.
///
/// # Arguments
/// * `public_key` - The RSA public key in DER format.
/// * `signature` - The signature bytes to verify.
/// * `hash` - The message/hash that was signed.
///
/// # Returns
/// * `Result<(), JsError>` - Ok if valid, Error if invalid.
pub fn rsa_verify(public_key: Vec<u8>, signature: Vec<u8>, hash: Vec<u8>) -> Result<(), JsError> {
    primitives::signatures::rsa_verify(&public_key, &hash, &signature)?;

    Ok(())
}

#[wasm_bindgen]
/// Decrypts a message using RSA-PKCS1v15.
///
/// # Arguments
/// * `private_key` - The RSA private key in PKCS#8 DER format.
/// * `ecnrypted` - The encrypted message bytes.
///
/// # Returns
/// * `Result<Vec<u8>, JsError>` - The decrypted message, or an error.
pub fn rsa_decrypt(private_key: Vec<u8>, ecnrypted: Vec<u8>) -> Result<Vec<u8>, JsError> {
    Ok(primitives::signatures::rsa_decrypt(&private_key, &ecnrypted)?)
}


