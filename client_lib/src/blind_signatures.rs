use crate::errors::JsError;
use primitives::{alloy_primitives::U256, alloy_sol_types::SolValue};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(getter_with_clone)]
/// Structure representing the result of a blinding operation.
///
/// Contains the blinded message to be signed and the secret required to unblind the signature.
///
/// # Fields
/// * `blind_msg` - The blinded message bytes.
/// * `secret` - The blinding factor (secret) used for unblinding.
pub struct ExportedBlindingResult {
    pub blind_msg: Vec<u8>,
    pub secret: Vec<u8>,
}

#[wasm_bindgen]
/// Encodes a blinding request into a byte sequence.
///
/// This helper encoding is used to ensure the message format matches what the smart contract or server expects.
///
/// # Arguments
/// * `client_addr` - The client's address (e.g., Ethereum address).
/// * `election_id` - The unique identifier for the election.
/// * `iat` - Issued at timestamp.
///
/// # Returns
/// * `Vec<u8>` - The ABI-encoded sequence of inputs.
pub fn encoded_req(client_addr: String, election_id: String, iat: u32) -> Vec<u8> {
    (client_addr, election_id, U256::from(iat))
        .abi_encode_sequence()
        .to_vec()
}

#[wasm_bindgen]
/// Creates a blinded signing request.
///
/// Encodes the request parameters and blinds the resulting message using the election's public key.
///
/// # Arguments
/// * `public_key` - The signer's public key.
/// * `client_addr` - The client's address.
/// * `election_id` - The election ID.
/// * `iat` - Issued at timestamp.
///
/// # Returns
/// * `Result<ExportedBlindingResult, JsError>` - The blinded message and secret, or an error.
pub fn create_request(
    public_key: Vec<u8>,
    client_addr: String,
    election_id: String,
    iat: u32,
) -> Result<ExportedBlindingResult, JsError> {
    let encoded = (client_addr, election_id, U256::from(iat)).abi_encode_sequence();

    let request = primitives::blind_signatures::create_request(&public_key, &encoded)?;

    Ok(ExportedBlindingResult {
        blind_msg: request.0,
        secret: request.1,
    })
}

#[wasm_bindgen]
/// Unblinds a blind signature.
///
/// Verify and unblind the signature received from the signer using the original blinding secret.
///
/// # Arguments
/// * `public_key` - The signer's public key.
/// * `client_addr` - The client's address in the original request.
/// * `election_id` - The election ID in the original request.
/// * `iat` - Issued at timestamp in the original request.
/// * `secret` - The blinding secret generated during request creation.
/// * `blind_sig` - The blind signature received from the signer.
///
/// # Returns
/// * `Result<Vec<u8>, JsError>` - The unblinded, valid signature, or an error.
pub fn unblind(
    public_key: Vec<u8>,
    client_addr: String,
    election_id: String,
    iat: u32,
    secret: Vec<u8>,
    blind_sig: Vec<u8>,
) -> Result<Vec<u8>, JsError> {
    let msg = (client_addr, election_id, U256::from(iat)).abi_encode_sequence();

    Ok(primitives::blind_signatures::unblind(
        &public_key, &msg, secret, blind_sig,
    )?)
}
