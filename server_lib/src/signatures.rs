use blind_rsa_signatures::{KeyPair, MessageRandomizer, Options, PublicKey, SecretKey, Signature};
use napi::bindgen_prelude::*;
use napi_derive::napi;
use rand::thread_rng;

#[napi(object)]
pub struct ExportedKeyPair {
  pub public: String,
  pub secret: String,
}

#[napi]
pub fn generate_rsa_keypair() -> ExportedKeyPair {
  let mut rng = thread_rng();

  let keypair = KeyPair::generate(&mut rng, 2048).unwrap();

  ExportedKeyPair {
    public: keypair.pk.to_pem().unwrap(),
    secret: keypair.sk.to_pem().unwrap(),
  }
}

#[napi]
pub fn sign(secret_key_pem: String, blind_msg: Buffer) -> Buffer {
  let options = Options::default();
  let private_key = SecretKey::from_pem(&secret_key_pem).unwrap();
  let mut rng = thread_rng();

  match private_key.blind_sign(&mut rng, &blind_msg, &options) {
    Ok(res) => res.0.into(),
    Err(e) => {
      println!("{e}");
      panic!("error")
    }
  }
}

#[napi]
pub fn verify(
  public_key_pem: String,
  signature_bytes: Buffer,
  msg_randomizer: Buffer,
  msg: String,
) -> bool {
  let public_key = PublicKey::from_pem(&public_key_pem).unwrap();
  let options = Options::default();

  let signature = Signature::new(signature_bytes.to_vec());

  let buff: [u8; 32] = msg_randomizer.to_vec().try_into().unwrap();

  match signature.verify(
    &public_key,
    Some(MessageRandomizer::new(buff)),
    msg,
    &options,
  ) {
    Ok(_) => true,
    Err(_) => false,
  }
}
