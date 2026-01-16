use wasm_bindgen::prelude::*;

use crate::errors::JsError;

#[wasm_bindgen(getter_with_clone)]
#[derive(Clone)]
pub struct FlatVec {
    pub data: Vec<u8>,
    pub component_size: usize,
}

#[wasm_bindgen(getter_with_clone)]
pub struct ExportedKeyPair {
    pub public: Vec<u8>,
    pub private: FlatVec,
}

#[wasm_bindgen]
pub fn generate_elgamal_keypair(k: usize, n: usize) -> Result<ExportedKeyPair, JsError> {
    let keypair = primitives::ballots::generate_elgamal_keypair();

    let shares = primitives::secret_sharing::split_secret(keypair.1, k, n);
    let share_size = shares[0].len();
    let mut flat_shares = Vec::new();

    for share in shares {
        flat_shares.extend_from_slice(&share);
    }

    Ok(ExportedKeyPair {
        public: keypair.0,
        private: FlatVec {
            data: flat_shares,
            component_size: share_size,
        },
    })
}

#[wasm_bindgen]
pub fn encrypt_vote(
    pub_key_bytes: Vec<u8>,
    choice: usize,
    options_count: usize,
) -> Result<Vec<u8>, JsError> {
    Ok(primitives::ballots::encrypt_vote(
        &pub_key_bytes,
        choice,
        options_count,
    )?)
}

#[wasm_bindgen]
pub fn decrypt_result(
    flat_vec: Vec<u8>,
    component_size: usize,
    k: usize,
    raw_result: Vec<u8>,
) -> Result<Vec<u64>, JsError> {
    let mut shares = Vec::new();

    let mut current_share = Vec::with_capacity(component_size);

    for el in flat_vec {
        current_share.push(el);

        if current_share.len() == component_size {
            shares.push(current_share);
            current_share = Vec::with_capacity(component_size);
        }
    }

    println!("{:?}", shares);

    let secret_key = primitives::secret_sharing::recover_secret(shares, k).unwrap();
    Ok(primitives::ballots::decrypt_result(
        &secret_key,
        &raw_result,
    )?)
}
