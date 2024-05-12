use std::u64::MAX;

use elastic_elgamal::app::{ChoiceParams, EncryptedChoice, SingleChoice};
use elastic_elgamal::group::Ristretto;
use elastic_elgamal::{Ciphertext, DiscreteLogTable, Keypair, PublicKey, SecretKey};
use rand::thread_rng;
use serde_json;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(getter_with_clone)]
pub struct ExportedKeyPair {
    pub public: Box<[u8]>,
    pub secret: Box<[u8]>,
}

#[wasm_bindgen]
pub fn generate_elgamal_keypair() -> ExportedKeyPair {
    let mut rng = thread_rng();
    let key_pair = Keypair::<Ristretto>::generate(&mut rng);

    ExportedKeyPair {
        public: key_pair.public().as_bytes().into(),
        secret: Vec::from(key_pair.secret().expose_scalar().as_bytes()).into_boxed_slice(),
    }
}

#[wasm_bindgen]
pub fn encrypt_vote(pub_key_bytes: Vec<u8>, choice: usize, options_count: usize) -> String {
    let rng = &mut thread_rng();
    let receiver = PublicKey::<Ristretto>::from_bytes(&pub_key_bytes).unwrap();
    let params = ChoiceParams::single(receiver, options_count);
    let ballot = EncryptedChoice::single(&params, choice, rng);

    serde_json::to_string(&ballot).unwrap()
}

#[wasm_bindgen]
pub fn verify_vote(
    pub_key_bytes: Vec<u8>,
    vote: String,
    options_count: usize,
) -> Result<(), String> {
    let receiver = match PublicKey::<Ristretto>::from_bytes(&pub_key_bytes) {
        Ok(res) => res,
        Err(e) => return Err(format!("{e}")),
    };
    let params = ChoiceParams::single(receiver, options_count);
    let ballot: EncryptedChoice<Ristretto, SingleChoice> = match serde_json::from_str(&vote) {
        Ok(res) => res,
        Err(e) => return Err(format!("{e}")),
    };

    match ballot.verify(&params) {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("{e}")),
    }
}

#[wasm_bindgen]
pub fn decrypt_result(secret_key: Vec<u8>, raw_result: String) -> Result<Vec<u64>, String> {
    let result: Vec<Ciphertext<Ristretto>> = match serde_json::from_str(&raw_result) {
        Ok(res) => res,
        Err(e) => return Err(format!("{e}")),
    };

    let sk = match SecretKey::<Ristretto>::from_bytes(&secret_key) {
        Some(res) => res,
        None => return Err("Unexpected error".to_string()),
    };

    let lookup_table = DiscreteLogTable::new(0..=100);

    Ok(result
        .iter()
        .map(|choice| sk.decrypt(*choice, &lookup_table).unwrap())
        .collect::<Vec<u64>>())
}

#[test]
fn it_works() {
    let result = "[{\"random_element\":\"gE0hppKFT0T8vSbsm4faGkXttWROUwS8fZeHGdX7tgQ\",\"blinded_element\":\"tvCZzqr-iNY0e3aV7IrWaFDTncuYfpqh4LPo_Vx62S4\"}]";
    let sk: [u8; 32] = [
        0xa6, 0x06, 0x80, 0x7d, 0x4b, 0xb4, 0x76, 0x49, 0x7d, 0xae, 0xf7, 0x00, 0xb0, 0xdd, 0xd6,
        0xda, 0xe0, 0x75, 0x10, 0x0d, 0xd1, 0x16, 0x69, 0x16, 0x9f, 0x47, 0x69, 0x22, 0x60, 0x69,
        0x2b, 0x0a,
    ];

    match decrypt_result(Vec::from(sk), result.into()) {
        Ok(res) => println!("{:?}", res),
        Err(e) => eprint!("{e}"),
    };
}
