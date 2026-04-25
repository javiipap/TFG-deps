use napi::bindgen_prelude::*;
use napi_derive::napi;

#[napi]
pub fn ecc_encrypt(pk: Buffer, msg: Buffer) -> Result<Buffer> {
  let pk_vec: Vec<u8> = pk.into();
  let msg_vec: Vec<u8> = msg.into();
  primitives::ecc::ecc_encrypt(&pk_vec, &msg_vec)
    .map(Into::into)
    .map_err(|e| Error::from_reason(e))
}

#[napi]
pub fn ecc_decrypt(sk: Buffer, encrypted: Buffer) -> Result<Buffer> {
  let sk_vec: Vec<u8> = sk.into();
  let encrypted_vec: Vec<u8> = encrypted.into();
  primitives::ecc::ecc_decrypt(&sk_vec, &encrypted_vec)
    .map(Into::into)
    .map_err(|e| Error::from_reason(e))
}
