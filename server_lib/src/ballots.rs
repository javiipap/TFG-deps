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

#[napi]
pub fn generate_acc(data: Buffer) -> Result<Buffer> {
  let data_vec: Vec<u8> = data.into();
  Ok(primitives::ballots::generate_acc(&data_vec).into())
}

#[napi]
pub fn add_votes(data: Buffer) -> Result<Buffer> {
  let data_vec: Vec<u8> = data.into();
  Ok(primitives::ballots::add_votes(&data_vec).into())
}

#[napi]
pub fn decrypt_result(secret_key: Buffer, raw_result: Buffer) -> Result<Vec<i64>> {
  let secret_key_vec: Vec<u8> = secret_key.into();
  let raw_result_vec: Vec<u8> = raw_result.into();
  primitives::ballots::decrypt_result(&secret_key_vec, &raw_result_vec, 10_000)
    .map(|v| v.into_iter().map(|x| x as i64).collect())
    .map_err(|e| Error::from_reason(e.to_string()))
}
