use wasm_bindgen::prelude::*;

#[wasm_bindgen]

pub fn ecc_encrypt(pk: Vec<u8>, msg: Vec<u8>) -> Vec<u8> {
    primitives::ecc::ecc_encrypt(pk, msg).unwrap()
}
#[wasm_bindgen]

pub fn ecc_decrypt(sk: Vec<u8>, encrypted: Vec<u8>) -> Vec<u8> {
    primitives::ecc::ecc_decrypt(sk, encrypted).unwrap()
}
