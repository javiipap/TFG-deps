use alloy_primitives::{Bytes, U256};
use alloy_sol_types::SolValue;
use bincode::{deserialize, serialize};
use blind_rsa_signatures::{MessageRandomizer, Signature};
use elastic_elgamal::app::{ChoiceParams, EncryptedChoice, SingleChoice};
use elastic_elgamal::group::Ristretto;
use elastic_elgamal::{Ciphertext, DiscreteLogTable, Keypair, PublicKey, SecretKey};
use rand::thread_rng;
use std::error::Error;

pub fn generate_elgamal_keypair() -> (Vec<u8>, Vec<u8>) {
    let mut rng = thread_rng();
    let key_pair = Keypair::<Ristretto>::generate(&mut rng);

    (
        key_pair.public().as_bytes().to_vec(),
        Vec::from(key_pair.secret().expose_scalar().as_bytes()),
    )
}

/// Generates vector of ciphertexts
pub fn generate_acc(data: &Vec<u8>) -> Vec<u8> {
    let candidate_count = <U256>::abi_decode(&data).unwrap();

    serialize(&vec![Ciphertext::<Ristretto>::zero(); candidate_count.to()]).unwrap()
}

pub fn encrypt_vote(
    pub_key_bytes: &Vec<u8>,
    choice: usize,
    options_count: usize,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let rng = &mut rand::thread_rng();
    let receiver = PublicKey::<Ristretto>::from_bytes(&pub_key_bytes)?;

    let params = ChoiceParams::single(receiver, options_count);
    let ballot = EncryptedChoice::single(&params, choice, rng);

    Ok(serialize(&ballot).unwrap())
}

/// Verifies vote validity
pub fn verify_vote(data: &Vec<u8>) -> Vec<u8> {
    let (candidate_count, public_key, ballot) =
        <(U256, Bytes, Bytes)>::abi_decode_sequence(&data).unwrap();

    let public_key = PublicKey::<Ristretto>::from_bytes(&public_key.to_vec()).unwrap();
    let ballot = deserialize::<EncryptedChoice<Ristretto, SingleChoice>>(&ballot.to_vec()).unwrap();

    let params = ChoiceParams::single(public_key, candidate_count.to());

    let mut output = vec![0; 32];

    if let Ok(_) = ballot.verify(&params) {
        output[31] = 1;
    };

    output
}

/// Add vote to result vector
pub fn add_votes(data: &Vec<u8>) -> Vec<u8> {
    let (acc, ballot) = <(Bytes, Bytes)>::abi_decode_sequence(&data).unwrap();

    let mut acc = deserialize::<Vec<Ciphertext<Ristretto>>>(&acc.to_vec()).unwrap();
    let ballot = deserialize::<EncryptedChoice<Ristretto, SingleChoice>>(&ballot.to_vec()).unwrap();

    for (i, choice) in ballot.choices_unchecked().iter().enumerate() {
        acc[i] += *choice;
    }

    serialize(&acc).unwrap()
}

pub fn verify(data: &Vec<u8>) -> Vec<u8> {
    let (public_key_pem, signature, msg) =
        <(String, Bytes, Bytes)>::abi_decode_sequence(&data).unwrap();

    let public_key = blind_rsa_signatures::PublicKey::from_pem(&public_key_pem).unwrap();
    let options = blind_rsa_signatures::Options::default();

    let (signature_raw, msg_randomizer) = deserialize::<(Vec<u8>, [u8; 32])>(&signature).unwrap();

    let signature = Signature::new(signature_raw);

    let mut output = vec![0; 32];

    if let Ok(_) = signature.verify(
        &public_key,
        Some(MessageRandomizer::new(msg_randomizer)),
        msg,
        &options,
    ) {
        output[31] = 1;
    }

    output
}

pub fn decrypt_result(
    secret_key: &Vec<u8>,
    raw_result: &Vec<u8>,
) -> Result<Vec<u64>, Box<dyn Error>> {
    let result = deserialize::<Vec<Ciphertext<Ristretto>>>(raw_result.as_slice())?;

    let sk = match SecretKey::<Ristretto>::from_bytes(&secret_key) {
        Some(res) => res,
        None => return Err(Box::from("Unexpected error")),
    };

    let max: u64 = 1 << 24;

    let lookup_table = DiscreteLogTable::new(0..=max);

    Ok(result
        .iter()
        .map(|choice| sk.decrypt(*choice, &lookup_table).unwrap())
        .collect::<Vec<u64>>())
}
