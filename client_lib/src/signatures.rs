use rsa::{pkcs8::DecodePublicKey, sha2::Sha256, Pkcs1v15Encrypt, Pkcs1v15Sign, RsaPublicKey};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn rsa_encrypt(pem: String, msg: String) -> Box<[u8]> {
    let mut rng = rand::thread_rng();
    let public_key = RsaPublicKey::from_public_key_pem(&pem).unwrap();

    public_key
        .encrypt(&mut rng, Pkcs1v15Encrypt, msg.as_bytes())
        .unwrap()
        .into_boxed_slice()
}

#[wasm_bindgen]
pub fn rsa_verify(pem: String, signature: Box<[u8]>, hash: Box<[u8]>) -> bool {
    let public_key = RsaPublicKey::from_public_key_pem(&pem).unwrap();

    let scheme = Pkcs1v15Sign::new::<Sha256>();

    match public_key.verify(scheme, &hash, &signature) {
        Ok(_) => true,
        Err(_) => false,
    }
}
