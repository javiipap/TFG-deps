use alloy_primitives::{Bytes, U256};
use alloy_sol_types::SolValue;
use blind_rsa_signatures::{Deterministic, MessageRandomizer, PSS, Sha384, Signature};
use elastic_elgamal::app::{ChoiceParams, EncryptedChoice, SingleChoice};
use elastic_elgamal::group::Ristretto;
use elastic_elgamal::{Ciphertext, DiscreteLogTable, Keypair, PublicKey, SecretKey};
use postcard::{from_bytes, to_allocvec};
use rand_legacy::thread_rng;
use std::error::Error;

/// Generates a new ElGamal key pair using the Ristretto group.
///
/// # Returns
///
/// Returns a tuple containing the public key and secret key as `Vec<u8>`.
pub fn generate_elgamal_keypair() -> (Vec<u8>, Vec<u8>) {
    let mut rng = thread_rng();
    let key_pair = Keypair::<Ristretto>::generate(&mut rng);

    (
        key_pair.public().as_bytes().to_vec(),
        Vec::from(key_pair.secret().expose_scalar().as_bytes()),
    )
}

/// Generates an accumulator vector of ciphertexts initialized to zero.
///
/// # Arguments
///
/// * `data` - Encoded candidate count as `Vec<u8>`.
///
/// # Returns
///
/// Returns the initialized accumulator as a `Vec<u8>`.
pub fn generate_acc(data: &Vec<u8>) -> Vec<u8> {
    let candidate_count = <U256>::abi_decode(&data).unwrap();

    to_allocvec(&vec![
        Ciphertext::<Ristretto>::zero();
        candidate_count.to::<usize>()
    ])
    .unwrap()
}

/// Encrypts a vote for a specific choice.
///
/// # Arguments
///
/// * `pub_key_bytes` - Public key of the election authority.
/// * `choice` - Index of the selected option.
/// * `options_count` - Total number of options available.
///
/// # Returns
///
/// Returns the encrypted vote (ballot) as `Result<Vec<u8>, Box<dyn Error>>`.
pub fn encrypt_vote(
    pub_key_bytes: &Vec<u8>,
    choice: usize,
    options_count: usize,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let rng = &mut thread_rng();
    let receiver = PublicKey::<Ristretto>::from_bytes(&pub_key_bytes)?;

    let params = ChoiceParams::single(receiver, options_count);
    let ballot = EncryptedChoice::single(&params, choice, rng);

    Ok(to_allocvec(&ballot).unwrap())
}

/// Verifies the validity of an encrypted vote using a Zero-Knowledge Proof.
///
/// # Arguments
///
/// * `data` - ABI encoded sequence of `(candidate_count, public_key, ballot)`.
///
/// # Returns
///
/// Returns a 32-byte vector where the last byte is 1 if valid, 0 otherwise.
pub fn verify_vote(data: &Vec<u8>) -> Vec<u8> {
    let (candidate_count, public_key, ballot) =
        <(U256, Bytes, Bytes)>::abi_decode_sequence(&data).unwrap();

    let public_key = PublicKey::<Ristretto>::from_bytes(&public_key.to_vec()).unwrap();
    let ballot = from_bytes::<EncryptedChoice<Ristretto, SingleChoice>>(&ballot.to_vec()).unwrap();

    let params = ChoiceParams::single(public_key, candidate_count.to::<usize>());

    let mut output = vec![0; 32];

    if let Ok(_) = ballot.verify(&params) {
        output[31] = 1;
    };

    output
}

/// Adds an encrypted vote to the current accumulator.
///
/// # Arguments
///
/// * `data` - ABI encoded sequence of `(accumulator, ballot)`.
///
/// # Returns
///
/// Returns the updated accumulator as `Vec<u8>`.
pub fn add_votes(data: &Vec<u8>) -> Vec<u8> {
    let (acc, ballot) = <(Bytes, Bytes)>::abi_decode_sequence(&data).unwrap();

    let mut acc = from_bytes::<Vec<Ciphertext<Ristretto>>>(&acc.to_vec()).unwrap();
    let ballot = from_bytes::<EncryptedChoice<Ristretto, SingleChoice>>(&ballot.to_vec()).unwrap();

    for (i, choice) in ballot.choices_unchecked().iter().enumerate() {
        acc[i] += *choice;
    }

    to_allocvec(&acc).unwrap()
}

/// Verifies a blinded signature against a message.
///
/// # Arguments
///
/// * `data` - ABI encoded sequence of `(public_key_pem, signature, msg)`.
///
/// # Returns
///
/// Returns a 32-byte vector where the last byte is 1 if valid, 0 otherwise.
pub fn verify(data: &Vec<u8>) -> Vec<u8> {
    let (public_key_pem, signature, msg) =
        <(String, Bytes, Bytes)>::abi_decode_sequence(&data).unwrap();

    let public_key =
        blind_rsa_signatures::PublicKey::<Sha384, PSS, Deterministic>::from_pem(&public_key_pem)
            .unwrap();

    let (signature_raw, msg_randomizer) = from_bytes::<(Vec<u8>, [u8; 32])>(&signature).unwrap();

    let signature = Signature::new(signature_raw);

    let mut output = vec![0; 32];

    if let Ok(_) = public_key.verify(
        &signature,
        Some(MessageRandomizer::new(msg_randomizer)),
        msg,
    ) {
        output[31] = 1;
    }

    output
}

/// Decrypts the final election results.
///
/// # Arguments
///
/// * `secret_key` - Secret key of the election authority.
/// * `raw_result` - The final accumulator containing aggregated votes.
/// * `max_count` - Upper bound for the discrete log lookup table. Must be at least
///   as large as the highest expected vote count per candidate.
///
/// # Returns
///
/// Returns a `Result` containing a vector of vote counts per option.
pub fn decrypt_result(
    secret_key: &Vec<u8>,
    raw_result: &Vec<u8>,
    max_count: u64,
) -> Result<Vec<u64>, Box<dyn Error>> {
    let result = from_bytes::<Vec<Ciphertext<Ristretto>>>(raw_result.as_slice())?;

    let sk = match SecretKey::<Ristretto>::from_bytes(&secret_key) {
        Some(res) => res,
        None => return Err(Box::from("Unexpected error")),
    };

    let lookup_table = DiscreteLogTable::new(0..=max_count);

    Ok(result
        .iter()
        .map(|choice| sk.decrypt(*choice, &lookup_table).unwrap())
        .collect::<Vec<u64>>())
}
