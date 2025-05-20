use blind_rsa_signatures::KeyPair;
use rand::thread_rng;
use rsa::{
    Pkcs1v15Encrypt, Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey, pkcs1::DecodeRsaPrivateKey,
    pkcs8::DecodePublicKey, sha2::Sha256,
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

pub fn rsa_verify(
    public_key: Vec<u8>,
    signature: Vec<u8>,
    hash: Vec<u8>,
) -> Result<(), Box<dyn Error>> {
    let public_key = RsaPublicKey::from_public_key_der(&public_key)?;

    let scheme = Pkcs1v15Sign::new::<Sha256>();

    public_key.verify(scheme, &hash, &signature)?;

    Ok(())
}

pub fn rsa_decrypt(public_key: Vec<u8>, ecnrypted: Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
    let secret_key = RsaPrivateKey::from_pkcs1_der(&public_key)?;

    Ok(secret_key.decrypt(Pkcs1v15Encrypt, &ecnrypted)?)
}

#[test]
fn it_works() -> Result<(), Box<dyn Error>> {
    let pem = "-----BEGIN RSA PUBLIC KEY-----
MIICCgKCAgEAumjwzZYoPGh/eSOVBR+F5ZFFi76n2bbYyr/GSfWFNNDkPRVCWZg4
m6Y/o7eB0gwsD7vDAIDFso6Ph8ZNQJ03yzLxcJe8ynSbyt1YeldTXM4siqkRmvut
AhmHb7qR87kCyaNnW5OqUNcWcsdqK4L0DkXvWroU+hE/dwxAKh/Cv/U6R2+DZ+/2
tH/ZSU+HhlRvWhmPgx/G1DWPOGyeE3ngAecp2BfpjiMVeS7vrYNO++IgDRRA3lbd
yvQIZKC+onDWglIDydZmjD8ZziWzqMeXck0F3Fr3PUQ3dIc/sp2ICe7FrmjqB/eo
pBl3kElc6VO5P1DHMwJe7DMXfRh8B2EvGhNdDIGaKbJ4SYMzvTWlhYUwrBjOvLvY
fuV91Ik4YHhlmgRjagOobijoqRbcU3EfG8ro92/AQKoZ+MBhRNctYjSIvPudr8RL
lDsozxubqljePsljRcAQzrPNwhzyKpcicvFL0xR1vOc7DSfG31TPCK3yCxus+NZT
RAI3LHVG2TGJogAkO8lDE2PHKf3UFfCDgMUaxQICdGiMFHzhaL9EZkCkXyt0NfVU
dEef1FOW2guOEakK8qo2zhxlDuv4Y7zeK7dUe7ZhfULRd3huXn11mjOLq1nq17gH
D4z+wT+pcMNIh4d/CpUWm+d3mHKFFLyskInrFo4PwOQMTT5dCXWEBvECAwEAAQ==
-----END RSA PUBLIC KEY-----";

    let secret = "-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----";

    // let result = rsa_encrypt(
    //     pem,
    //     "0x0148018c6c63839199af8e2b9e69fbe78d8e518a9d31b8b01257759c104beb02".to_string(),
    // )?;

    // println!("{:?}", result);

    // let decrypted = rsa_decrypt(secret.to_string(), result)?;

    // println!("{}", decrypted.len());

    // println!("{:?}", decrypted);

    Ok(())
}
