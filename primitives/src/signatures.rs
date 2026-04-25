use blind_rsa_signatures::{DefaultRng, Deterministic, KeyPair, PSS, Sha384};
use rand_legacy::thread_rng;
use rsa::RsaPrivateKey;
use rsa::pkcs1v15::{Signature, SigningKey, VerifyingKey};
use rsa::sha2::Sha256;
use rsa::signature::{SignatureEncoding, Verifier};
use rsa::{
    Pkcs1v15Encrypt, RsaPublicKey, pkcs8::DecodePrivateKey, pkcs8::DecodePublicKey,
    signature::SignerMut,
};
use std::error::Error;

/// Generates a new RSA key pair.
///
/// Use 2048-bit keys.
///
/// # Returns
///
/// Returns a `Result` containing the public and secret keys as DER-encoded `Vec<u8>`.
pub fn generate_rsa_keypair() -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
    let keypair = KeyPair::<Sha384, PSS, Deterministic>::generate(&mut DefaultRng, 2048)?;

    Ok((keypair.pk.to_der()?, keypair.sk.to_der()?))
}

/// Encrypts a message using RSA-PKCS1v15.
///
/// # Arguments
///
/// * `public_key` - DER-encoded public key.
/// * `msg` - Message to encrypt.
///
/// # Returns
///
/// Returns the encrypted message as `Vec<u8>`.
pub fn rsa_encrypt(public_key: &Vec<u8>, msg: &Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
    let public_key = RsaPublicKey::from_public_key_der(&public_key)?;
    let mut rng = thread_rng();
    Ok(public_key.encrypt(&mut rng, Pkcs1v15Encrypt, &msg)?)
}

/// Decrypts a message using RSA-PKCS1v15.
///
/// # Arguments
///
/// * `private_key` - DER-encoded private key.
/// * `ecnrypted` - Encrypted message.
///
/// # Returns
///
/// Returns the decrypted message as `Vec<u8>`.
pub fn rsa_decrypt(private_key: &Vec<u8>, ecnrypted: &Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
    let secret_key = RsaPrivateKey::from_pkcs8_der(&private_key)?;

    Ok(secret_key.decrypt(Pkcs1v15Encrypt, &ecnrypted)?)
}

/// Signs a message using RSA-PKCS1v15 (SHA-256).
///
/// # Arguments
///
/// * `private_key` - DER-encoded private key.
/// * `msg` - Message to sign.
///
/// # Returns
///
/// Returns the signature as `Vec<u8>`.
pub fn rsa_sign(private_key: &Vec<u8>, msg: &Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
    let private_key = RsaPrivateKey::from_pkcs8_der(&private_key)?;
    let mut signing_key = SigningKey::<Sha256>::new(private_key);

    let signature = signing_key.sign(&msg.as_slice());

    Ok(signature.to_bytes().to_vec())
}

/// Verifies a signature using RSA-PKCS1v15 (SHA-256).
///
/// # Arguments
///
/// * `public_key` - DER-encoded public key.
/// * `msg` - Message to verify.
/// * `signature` - Signature to verify.
///
/// # Returns
///
/// Returns `Ok(())` if valid, or an error if invalid.
pub fn rsa_verify(
    public_key: &Vec<u8>,
    msg: &Vec<u8>,
    signature: &Vec<u8>,
) -> Result<(), Box<dyn Error>> {
    let public_key = RsaPublicKey::from_public_key_der(&public_key)?;
    let verifying_key = VerifyingKey::<Sha256>::new(public_key);

    let decoded = Signature::try_from(signature.as_slice())?;
    verifying_key.verify(msg.as_slice(), &decoded)?;

    Ok(())
}
