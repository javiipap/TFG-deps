use blind_rsa_signatures::KeyPair;
use rand::thread_rng;
use rsa::RsaPrivateKey;
use rsa::pkcs1v15::{Signature, SigningKey, VerifyingKey};
use rsa::sha2::Sha256;
use rsa::signature::{SignatureEncoding, Verifier};
use rsa::{
    Pkcs1v15Encrypt, RsaPublicKey, pkcs1::DecodeRsaPrivateKey, pkcs8::DecodePublicKey,
    signature::SignerMut,
};
use std::error::Error;

pub fn generate_rsa_keypair() -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
    let mut rng = thread_rng();

    let keypair = KeyPair::generate(&mut rng, 2048)?;

    Ok((keypair.pk.to_der()?, keypair.sk.to_der()?))
}

pub fn rsa_encrypt(public_key: Vec<u8>, msg: Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut rng = rand::thread_rng();
    let public_key = RsaPublicKey::from_public_key_der(&public_key)?;
    Ok(public_key.encrypt(&mut rng, Pkcs1v15Encrypt, &msg)?)
}

pub fn rsa_decrypt(private_key: Vec<u8>, ecnrypted: Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
    let secret_key = RsaPrivateKey::from_pkcs1_der(&private_key)?;

    Ok(secret_key.decrypt(Pkcs1v15Encrypt, &ecnrypted)?)
}

pub fn rsa_sign(private_key: Vec<u8>, msg: Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
    let private_key = RsaPrivateKey::from_pkcs1_der(&private_key)?;
    let mut signing_key = SigningKey::<Sha256>::new(private_key);

    let signature = signing_key.sign(&msg.as_slice());

    Ok(signature.to_bytes().to_vec())
}

pub fn rsa_verify(
    public_key: Vec<u8>,
    msg: Vec<u8>,
    signature: Vec<u8>,
) -> Result<(), Box<dyn Error>> {
    let public_key = RsaPublicKey::from_public_key_der(&public_key)?;
    let verifying_key = VerifyingKey::<Sha256>::new(public_key);

    let decoded = Signature::try_from(signature.as_slice())?;
    verifying_key.verify(msg.as_slice(), &decoded)?;

    Ok(())
}

#[test]
fn it_works() -> Result<(), Box<dyn Error>> {
    let keypair = generate_rsa_keypair()?;

    let msg = Vec::from("hola que tal".as_bytes());

    let signature = rsa_sign(keypair.1, msg.clone())?;
    rsa_verify(keypair.0, msg, signature)?;
    Ok(())
}
