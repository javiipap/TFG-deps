use napi::bindgen_prelude::Buffer;
use primitives::alloy_primitives::{Bytes, U256};
use primitives::alloy_sol_types::SolValue;
use server_utilities::ballots::{
  add_votes, decrypt_result, encrypt_vote, generate_acc, generate_elgamal_keypair,
};
use server_utilities::ExportedKeyPair;

#[test]
fn test_ballot_flow() {
  let ExportedKeyPair {
    public: pk,
    private: sk,
  } = generate_elgamal_keypair().expect("failed to generate keypair");

  // 3 candidates
  let candidate_count = U256::from(3);
  let options_count = 3;

  // Initialize Accumulator
  let encoded_count = candidate_count.abi_encode();
  let acc = generate_acc(Buffer::from(encoded_count)).expect("failed to generate acc");

  // Vote for option 0
  let vote0 =
    encrypt_vote(Buffer::from(pk.as_ref()), 0, options_count).expect("failed to encrypt vote 0");

  // Vote for option 1
  let vote1 =
    encrypt_vote(Buffer::from(pk.as_ref()), 1, options_count).expect("failed to encrypt vote 1");

  // Vote for option 0 again
  let vote2 =
    encrypt_vote(Buffer::from(pk.as_ref()), 0, options_count).expect("failed to encrypt vote 2");

  // Add votes
  let mut current_acc: Vec<u8> = acc.into();

  // Add vote 0
  let input0 = (
    Bytes::from(current_acc.clone()),
    Bytes::from(vote0.to_vec()),
  )
    .abi_encode_sequence();
  current_acc = add_votes(input0.into())
    .expect("failed to add vote 0")
    .into();

  // Add vote 1
  let input1 = (
    Bytes::from(current_acc.clone()),
    Bytes::from(vote1.to_vec()),
  )
    .abi_encode_sequence();
  current_acc = add_votes(input1.into())
    .expect("failed to add vote 1")
    .into();

  // Add vote 2
  let input2 = (
    Bytes::from(current_acc.clone()),
    Bytes::from(vote2.to_vec()),
  )
    .abi_encode_sequence();
  current_acc = add_votes(input2.into())
    .expect("failed to add vote 2")
    .into();

  let results = decrypt_result(sk, current_acc.into()).expect("failed to decrypt");

  // Expected: Option 0: 2 votes, Option 1: 1 vote, Option 2: 0 votes
  assert_eq!(results[0], 2);
  assert_eq!(results[1], 1);
  assert_eq!(results[2], 0);
}
