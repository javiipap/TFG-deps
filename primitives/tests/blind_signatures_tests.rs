use primitives::blind_signatures::{
    ExportedKeyPair, create_request, generate_rsa_keypair, sign, unblind, verify,
};

#[test]
fn test_blind_signature_flow() {
    let ExportedKeyPair {
        public: public_key,
        private: private_key,
    } = generate_rsa_keypair().expect("failed to generate keypair");

    let public_key = &public_key;
    let private_key = &private_key;

    let msg = &b"blind message".to_vec();

    // 1. Create Request
    let (blinded_msg, secret) = create_request(public_key, msg).expect("failed to create request");

    // 2. Sign (Blindly)
    let blinded_signature = sign(&private_key, &blinded_msg).expect("failed to sign blinded msg");

    // 3. Unblind
    let signature = unblind(public_key, msg, secret, blinded_signature).expect("failed to unblind");

    // 4. Verify
    let is_valid = verify(public_key, signature, msg).expect("verification failed");
    assert!(is_valid);
}
