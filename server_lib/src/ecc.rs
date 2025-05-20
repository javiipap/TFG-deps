use napi::bindgen_prelude::*;
use napi_derive::napi;

#[napi]
pub fn ecc_encrypt(pk: Buffer, msg: Buffer) -> Result<Buffer> {
  primitives::ecc::ecc_encrypt(pk.into(), msg.into())
    .map(Into::into)
    .map_err(|e| Error::from_reason(e))
}

#[napi]
pub fn ecc_decrypt(sk: Buffer, encrypted: Buffer) -> Result<Buffer> {
  primitives::ecc::ecc_decrypt(sk.into(), encrypted.into())
    .map(Into::into)
    .map_err(|e| Error::from_reason(e))
}
