use crate::errors::JsError;
use alloy_primitives::U256;
use alloy_sol_types::SolValue;
use js_sys::ArrayBuffer;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(getter_with_clone)]
pub struct ExportedBlindingResult {
    pub blind_msg: Vec<u8>,
    pub secret: Vec<u8>,
}

#[wasm_bindgen]
pub fn create_request(
    public_key: Vec<u8>,
    client_addr: String,
    election_id: u32,
    iat_dellay: u32,
) -> Result<ExportedBlindingResult, JsError> {
    let encoded =
        (client_addr, U256::from(election_id), U256::from(iat_dellay)).abi_encode_sequence();

    let request = primitives::blind_signatures::create_request(public_key, encoded)?;

    Ok(ExportedBlindingResult {
        blind_msg: request.0,
        secret: request.1,
    })
}

#[wasm_bindgen]
pub fn unblind(
    public_key: Vec<u8>,
    msg: Vec<u8>,
    secret: Vec<u8>,
    blind_sig: Vec<u8>,
) -> Result<Vec<u8>, JsError> {
    Ok(primitives::blind_signatures::unblind(
        public_key, msg, secret, blind_sig,
    )?)
}
