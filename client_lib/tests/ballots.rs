use blind_signatures::ballots::{encrypt_vote, decrypt_result, generate_elgamal_keypair};
use primitives::ballots::{generate_acc, add_votes};
use primitives::alloy_sol_types::SolValue;
use primitives::alloy_primitives::U256;

#[test]
fn test_ballots_flow() {
    let k = 2;
    let n = 3;
    let keypair = generate_elgamal_keypair(k, n).unwrap();
    
    let options_count = 5;
    let encoded_count = U256::from(options_count).abi_encode();
    let mut acc = generate_acc(&encoded_count);

    let choice = 1;
    let vote_bytes = encrypt_vote(keypair.public.clone(), choice, options_count).unwrap();
    
    let encoded_add = (acc.clone(), vote_bytes).abi_encode_sequence();
    acc = add_votes(&encoded_add);
    
    let result = decrypt_result(
        keypair.private.data, 
        keypair.private.component_size, 
        k, 
        acc
    ).unwrap();
    
    assert_eq!(result[choice], 1);
    assert_eq!(result[0], 0);
}
