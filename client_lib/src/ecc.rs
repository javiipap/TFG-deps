use wasm_bindgen::prelude::*;

#[wasm_bindgen]

pub fn ecc_encrypt(pk: Box<[u8]>, msg: Box<[u8]>) -> Box<[u8]> {
    let encrypted = ecies::encrypt(&pk, &msg).unwrap();

    encrypted.into_boxed_slice()
}
#[wasm_bindgen]

pub fn ecc_decrypt(sk: Box<[u8]>, encrypted: Box<[u8]>) -> Box<[u8]> {
    let decrypted = ecies::decrypt(&sk, &encrypted).unwrap();

    decrypted.into_boxed_slice()
}
