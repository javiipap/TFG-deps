use napi::bindgen_prelude::*;
use napi::{Error, Result};
use napi_derive::napi;
use primitives::alloy_primitives::U256;
use primitives::alloy_sol_types::SolValue;

use crate::ExportedKeyPair;

#[napi(object)]
pub struct ExportedBlindingResult {
  pub blind_msg: Buffer,
  pub secret: Buffer,
}

#[napi]
pub fn create_request(
  public_key: Buffer,
  client_addr: String,
  iat_delay: u32,
  election_id: String,
) -> Result<ExportedBlindingResult> {
  let encoded = (client_addr, election_id, U256::from(iat_delay)).abi_encode_sequence();
  let public_key_vec: Vec<u8> = public_key.into();

  match primitives::blind_signatures::create_request(&public_key_vec, &encoded) {
    Ok(request) => Ok(ExportedBlindingResult {
      blind_msg: request.0.into(),
      secret: request.1.into(),
    }),
    Err(e) => Err(Error::from_reason(e.to_string())),
  }
}

#[napi]
pub fn generate_rsa_keypair() -> Result<ExportedKeyPair> {
  match primitives::signatures::generate_rsa_keypair() {
    Ok(keypair) => Ok(ExportedKeyPair {
      public: keypair.0.into(),
      private: keypair.1.into(),
    }),
    Err(e) => Err(Error::from_reason(e.to_string())),
  }
}

#[napi]
pub fn sign(secret_key: Buffer, blind_msg: Buffer) -> Result<Buffer> {
  let secret_key_vec: Vec<u8> = secret_key.into();
  let blind_msg_vec: Vec<u8> = blind_msg.into();
  primitives::blind_signatures::sign(&secret_key_vec, &blind_msg_vec)
    .map(Into::into)
    .map_err(|e| Error::from_reason(e.to_string()))
}

#[napi]
pub fn unblind(
  public_key: Buffer,
  secret: Buffer,
  blind_sig: Buffer,
  client_addr: String,
  iat_delay: u32,
  election_id: String,
) -> Result<Buffer> {
  let encoded = (client_addr, election_id, U256::from(iat_delay)).abi_encode_sequence();

  let public_key_vec: Vec<u8> = public_key.into();
  primitives::blind_signatures::unblind(&public_key_vec, &encoded, secret.into(), blind_sig.into())
    .map(Into::into)
    .map_err(|e| Error::from_reason(e.to_string()))
}

#[napi]
pub fn verify(public_key: Buffer, signature_bytes: Buffer, msg: Buffer) -> Result<()> {
  let public_key_vec: Vec<u8> = public_key.into();
  let msg_vec: Vec<u8> = msg.into();
  primitives::blind_signatures::verify(&public_key_vec, signature_bytes.into(), &msg_vec)
    .map(|_| ())
    .map_err(|e| Error::from_reason(e.to_string()))
}
