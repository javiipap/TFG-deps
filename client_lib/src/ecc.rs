use wasm_bindgen::prelude::*;

#[wasm_bindgen]
/// Encrypts a message using Elliptic Curve Integrated Encryption Scheme (ECIES).
///
/// # Arguments
/// * `pk` - The recipient's public key.
/// * `msg` - The message bytes to encrypt.
///
/// # Returns
/// * `Vec<u8>` - The encrypted message bytes.
///
/// # Panics
/// Panics if the encryption fails.
pub fn ecc_encrypt(pk: Vec<u8>, msg: Vec<u8>) -> Vec<u8> {
    primitives::ecc::ecc_encrypt(&pk, &msg).unwrap()
}
#[wasm_bindgen]

/// Decrypts a message using Elliptic Curve Integrated Encryption Scheme (ECIES).
///
/// # Arguments
/// * `sk` - The recipient's secret key.
/// * `encrypted` - The encrypted message bytes.
///
/// # Returns
/// * `Vec<u8>` - The decrypted message bytes.
///
/// # Panics
/// Panics if the decryption fails.
pub fn ecc_decrypt(sk: Vec<u8>, encrypted: Vec<u8>) -> Vec<u8> {
    primitives::ecc::ecc_decrypt(&sk, &encrypted).unwrap()
}


