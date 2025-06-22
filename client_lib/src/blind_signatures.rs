use crate::errors::JsError;
use alloy_primitives::U256;
use alloy_sol_types::SolValue;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(getter_with_clone)]
pub struct ExportedBlindingResult {
    pub blind_msg: Vec<u8>,
    pub secret: Vec<u8>,
}

#[wasm_bindgen]
pub fn encoded_req(client_addr: String, election_id: String, iat: u32) -> Vec<u8> {
    (client_addr, election_id, U256::from(iat))
        .abi_encode_sequence()
        .to_vec()
}

#[wasm_bindgen]
pub fn create_request(
    public_key: Vec<u8>,
    client_addr: String,
    election_id: String,
    iat: u32,
) -> Result<ExportedBlindingResult, JsError> {
    let encoded = (client_addr, election_id, U256::from(iat)).abi_encode_sequence();

    let request = primitives::blind_signatures::create_request(public_key, encoded)?;

    Ok(ExportedBlindingResult {
        blind_msg: request.0,
        secret: request.1,
    })
}

#[wasm_bindgen]
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
        public_key, msg, secret, blind_sig,
    )?)
}
