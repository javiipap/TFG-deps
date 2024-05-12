use blind_rsa_signatures::{BlindSignature, MessageRandomizer, Options, PublicKey, Secret};
use rand::thread_rng;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(getter_with_clone)]
pub struct ExportedBlindingResult {
    pub blind_msg: Box<[u8]>,
    pub secret: Box<[u8]>,
    pub msg_randomizer: Box<[u8]>,
}

#[wasm_bindgen]
pub fn create_request(public_key_pem: String, msg: String) -> ExportedBlindingResult {
    let options = Options::default();
    let mut rng = thread_rng();
    let public_key = PublicKey::from_pem(&public_key_pem).unwrap();

    let res = public_key.blind(&mut rng, msg, true, &options).unwrap();

    ExportedBlindingResult {
        blind_msg: res.blind_msg.0.into_boxed_slice(),
        secret: res.secret.0.into_boxed_slice(),
        msg_randomizer: Vec::from(res.msg_randomizer.unwrap().0).into_boxed_slice(),
    }
}

#[wasm_bindgen]
pub fn unblind(
    public_key_pem: String,
    msg: String,
    secret: Box<[u8]>,
    msg_randomizer: Box<[u8]>,
    blind_sig: Box<[u8]>,
) -> Box<[u8]> {
    let options = Options::default();
    let public_key = PublicKey::from_pem(&public_key_pem).unwrap();

    let buff: [u8; 32] = msg_randomizer.to_vec().try_into().unwrap();

    public_key
        .finalize(
            &BlindSignature::new(blind_sig.into()),
            &Secret::new(secret.to_vec().into()),
            Some(MessageRandomizer::new(buff)),
            msg,
            &options,
        )
        .unwrap()
        .0
        .into_boxed_slice()
}
