pub mod ballots;
pub mod ecc;
pub mod signatures;

use napi::bindgen_prelude::*;
use napi_derive::napi;

#[napi(object)]
pub struct ExportedKeyPair {
  pub public: Buffer,
  pub private: Buffer,
}
