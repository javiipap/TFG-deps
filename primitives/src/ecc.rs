/// Encrypts a message using ECIES (Elliptic Curve Integrated Encryption Scheme).
///
/// # Arguments
///
/// * `pk` - The public key as a byte vector.
/// * `msg` - The message to encrypt as a byte vector.
///
/// # Returns
///
/// Returns a `Result` containing the encrypted message as a `Vec<u8>` on success,
/// or a `String` error message on failure.
pub fn ecc_encrypt(pk: &Vec<u8>, msg: &Vec<u8>) -> Result<Vec<u8>, String> {
    ecies::encrypt(&pk, &msg)
        .map(Into::into)
        .map_err(|e| e.to_string())
}

/// Decrypts a message using ECIES (Elliptic Curve Integrated Encryption Scheme).
///
/// # Arguments
///
/// * `sk` - The secret key as a byte vector.
/// * `encrypted` - The encrypted message as a byte vector.
///
/// # Returns
///
/// Returns a `Result` containing the decrypted message as a `Vec<u8>` on success,
/// or a `String` error message on failure.
pub fn ecc_decrypt(sk: &Vec<u8>, encrypted: &Vec<u8>) -> Result<Vec<u8>, String> {
    ecies::decrypt(&sk, &encrypted)
        .map(Into::into)
        .map_err(|e| e.to_string())
}
