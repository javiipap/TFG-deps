use wasm_bindgen::prelude::*;

use crate::errors::JsError;

#[wasm_bindgen(getter_with_clone)]
#[derive(Clone)]
/// Structure representing a flattened vector of shares.
///
/// This is used to pass vector of vectors across the Wasm boundary as a single flat vector.
///
/// # Fields
/// * `data` - The flattened data bytes.
/// * `component_size` - The size of each individual component (share).
pub struct FlatVec {
    pub data: Vec<u8>,
    pub component_size: usize,
}

#[wasm_bindgen(getter_with_clone)]
/// Structure representing an exported ElGamal key pair.
///
/// Contains the public key and the private key shares (in a flattened format).
///
/// # Fields
/// * `public` - The public key bytes.
/// * `private` - The private key shares flattened in `FlatVec`.
pub struct ExportedKeyPair {
    pub public: Vec<u8>,
    pub private: FlatVec,
}

#[wasm_bindgen]
/// Generates an ElGamal key pair with threshold secret sharing.
///
/// # Arguments
/// * `k` - The threshold number of shares required to reconstruct the private key.
/// * `n` - The total number of shares to generate.
///
/// # Returns
/// * `Result<ExportedKeyPair, JsError>` - The generated key pair containing public key and private key shares, or an error.
pub fn generate_elgamal_keypair(k: usize, n: usize) -> Result<ExportedKeyPair, JsError> {
    let keypair = primitives::ballots::generate_elgamal_keypair();

    let shares = primitives::secret_sharing::split_secret(&keypair.1, k, n);
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
/// Encrypts a vote choice using ElGamal encryption.
///
/// # Arguments
/// * `pub_key_bytes` - The public key bytes.
/// * `choice` - The index of the chosen option.
/// * `options_count` - The total number of options available.
///
/// # Returns
/// * `Result<Vec<u8>, JsError>` - The encrypted ballot bytes, or an error.
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
/// Decrypts the election result using secret key shares.
///
/// Reconstructs the secret key from the provided shares and decrypts the aggregated result.
///
/// # Arguments
/// * `flat_vec` - The flattened vector of private key shares.
/// * `component_size` - The size of each share.
/// * `k` - The threshold associated with the secret sharing.
/// * `raw_result` - The aggregated encrypted result bytes.
///
/// # Returns
/// * `Result<Vec<u64>, JsError>` - A vector containing the tally for each option, or an error.
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

    let secret_key = primitives::secret_sharing::recover_secret(&shares, k).unwrap();
    Ok(primitives::ballots::decrypt_result(
        &secret_key,
        &raw_result,
        10_000,
    )?)
}
