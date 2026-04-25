use alloy_primitives::{Bytes, U256};
use alloy_sol_types::SolValue;
use elastic_elgamal::app::{EncryptedChoice, SingleChoice};
use elastic_elgamal::group::Ristretto;
use postcard::from_bytes;
use primitives::ballots::{
    add_votes, decrypt_result, encrypt_vote, generate_acc, generate_elgamal_keypair,
};

/// Tests direct serialization of encrypted votes using postcard.
#[test]
fn test_serialization_isolation() {
    let (pk, _) = generate_elgamal_keypair();
    let options_count = 3;

    // Encrypt
    let vote_bytes = encrypt_vote(&pk, 0, options_count).expect("encrypt failed");

    // Deserialize directly
    let _: EncryptedChoice<Ristretto, SingleChoice> =
        from_bytes(&vote_bytes).expect("deserialization failed");
}

/// Tests serialization of the accumulator.
#[test]
fn test_acc_serialization() {
    let candidate_count = U256::from(3);
    let encoded_count = candidate_count.abi_encode();
    let acc = generate_acc(&encoded_count);

    // Deserialize directly
    let _: Vec<elastic_elgamal::Ciphertext<Ristretto>> =
        from_bytes(&acc).expect("acc deserialization failed");
}

/// Tests ABI encoding/decoding of accumulator and ballot sequences.
#[test]
fn test_abi_integrity() {
    let acc_bytes: Vec<u8> = vec![1, 2, 3, 4];
    let ballot_bytes: Vec<u8> = vec![5, 6, 7, 8];

    // Encode as bytes, bytes
    let input = (
        Bytes::from(acc_bytes.clone()),
        Bytes::from(ballot_bytes.clone()),
    )
        .abi_encode_sequence();

    // Decode checks
    let (acc, ballot) = <(Bytes, Bytes)>::abi_decode_sequence(&input).expect("decode failed");

    assert_eq!(acc.to_vec(), acc_bytes);
    assert_eq!(ballot.to_vec(), ballot_bytes);
}

/// Tests the full voting flow: key generation, vote encryption, aggregation, and decryption.
#[test]
fn test_ballot_flow() {
    let (pk, sk) = generate_elgamal_keypair();

    // 3 candidates
    let candidate_count = U256::from(3);
    let options_count = 3;

    // Initialize Accumulator
    let encoded_count = candidate_count.abi_encode();
    let acc = generate_acc(&encoded_count);

    // Vote for option 0
    let vote0 = encrypt_vote(&pk, 0, options_count).expect("failed to encrypt vote 0");

    // Vote for option 1
    let vote1 = encrypt_vote(&pk, 1, options_count).expect("failed to encrypt vote 1");

    // Vote for option 0 again
    let vote2 = encrypt_vote(&pk, 0, options_count).expect("failed to encrypt vote 2");

    // Add votes
    let mut current_acc = acc;

    // Add vote 0
    let input0 = (Bytes::from(current_acc.clone()), Bytes::from(vote0)).abi_encode_sequence();
    current_acc = add_votes(&input0);

    // Add vote 1
    let input1 = (Bytes::from(current_acc.clone()), Bytes::from(vote1)).abi_encode_sequence();
    current_acc = add_votes(&input1);

    // Add vote 2
    let input2 = (Bytes::from(current_acc.clone()), Bytes::from(vote2)).abi_encode_sequence();
    current_acc = add_votes(&input2);

    let results = decrypt_result(&sk, &current_acc, 1 << 5).expect("failed to decrypt");

    // Expected: Option 0: 2 votes, Option 1: 1 vote, Option 2: 0 votes
    assert_eq!(results[0], 2);
    assert_eq!(results[1], 1);
    assert_eq!(results[2], 0);
}
