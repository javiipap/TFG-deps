use napi::bindgen_prelude::Buffer;
use napi::{Error, Result};
use napi_derive::napi;

use crate::ExportedKeyPair;

#[napi]
pub fn generate_elgamal_keypair() -> Result<ExportedKeyPair> {
  let keypair = primitives::ballots::generate_elgamal_keypair();

  Ok(ExportedKeyPair {
    public: keypair.0.into(),
    private: keypair.1.into(),
  })
}

#[napi]
pub fn encrypt_vote(pub_key_bytes: Buffer, choice: u32, options_count: u32) -> Result<Buffer> {
  primitives::ballots::encrypt_vote(
    &pub_key_bytes.into(),
    choice as usize,
    options_count as usize,
  )
  .map(Into::into)
  .map_err(|e| Error::from_reason(e.to_string()))
}
