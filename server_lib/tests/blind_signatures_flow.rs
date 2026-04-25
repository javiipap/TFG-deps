use server_utilities::ExportedKeyPair;
use server_utilities::signatures::{
    create_request, generate_rsa_keypair, sign, unblind, verify,
};

#[test]
fn test_blind_signature_flow() {
    let ExportedKeyPair {
        public: public_key,
        private: private_key,
    } = generate_rsa_keypair().expect("failed to generate keypair");

    // Dummy values required by server_utilities wrappers
    let client_addr = "0x0000000000000000000000000000000000000000".to_string();
    let election_id = "election_1".to_string();
    let iat_delay = 0;

    // 1. Create Request
    // Note: server_utilities::create_request internally encodes (client_addr, election_id, iat_delay) as the message
    let result = create_request(Buffer::from(public_key.as_ref()), client_addr.clone(), iat_delay, election_id.clone())
        .expect("failed to create request");
    
    let blinded_msg = result.blind_msg;
    let secret = result.secret;

    // 2. Sign (Blindly)
    // Server signs the blinded hash of the encoded message
    let blinded_signature = sign(private_key, blinded_msg).expect("failed to sign blinded msg");

    // 3. Unblind
    let signature = unblind(Buffer::from(public_key.as_ref()), secret, blinded_signature, client_addr.clone(), iat_delay, election_id.clone())
        .expect("failed to unblind");

    // 4. Verify
    // server_utilities::verify expects the raw message, which is the ABI encoded sequence.
    // However, verify's signature in server_utilities/src/signatures.rs:68 is:
    // verify(public_key, signature_bytes, msg)
    // In server_utilities, `create_request` CREATES the msg from inputs.
    // But `unblind` and `sign` don't return the original msg.
    // Verification requires the ORIGINAL message.
    // I need to reconstruct the message manually or expose a helper.
    // `server_utilities` does NOT expose the construction logic publicly easily, 
    // BUT I can manually construct it using `alloy_sol_types` as I have the dependencies.
    
    use primitives::alloy_primitives::U256;
    use primitives::alloy_sol_types::SolValue;
    use napi::bindgen_prelude::Buffer;
    
    let encoded_msg = (client_addr, election_id, U256::from(iat_delay)).abi_encode_sequence();
    
    let is_valid = verify(public_key, signature, Buffer::from(encoded_msg));
    assert!(is_valid.is_ok());
}
