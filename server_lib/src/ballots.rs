use elastic_elgamal::app::{ChoiceParams, EncryptedChoice};
use elastic_elgamal::group::Ristretto;
use elastic_elgamal::PublicKey;
use napi::bindgen_prelude::*;
use napi_derive::napi;
use rand::thread_rng;
use serde_json;

#[napi]
pub fn encrypt_vote(pub_key_bytes: Buffer, choice: u32, options_count: u32) -> String {
  let rng = &mut thread_rng();
  let receiver = PublicKey::<Ristretto>::from_bytes(&pub_key_bytes).unwrap();
  let params = ChoiceParams::single(receiver, options_count.try_into().unwrap());
  let ballot = EncryptedChoice::single(&params, choice.try_into().unwrap(), rng);

  serde_json::to_string(&ballot).unwrap()
}
