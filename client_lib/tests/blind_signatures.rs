use blind_signatures::blind_signatures::{create_request, encoded_req, unblind};
use primitives::blind_signatures::{generate_rsa_keypair, sign as blind_sign, verify as blind_verify};

#[test]
fn test_encoded_req() {
    let client_addr = "0x123".to_string();
    let election_id = "election1".to_string();
    let iat = 12345;
    
    let result = encoded_req(client_addr, election_id, iat);
    assert!(!result.is_empty());
}

#[test]
fn test_blind_signature_flow() {
    let keypair = generate_rsa_keypair().unwrap();
    
    let client_addr = "0x123".to_string();
    let election_id = "election1".to_string();
    let iat = 12345;

    let blinding_result = create_request(
        keypair.public.clone(),
        client_addr.clone(),
        election_id.clone(),
        iat
    ).unwrap();

    let blinded_sig = blind_sign(&keypair.private, &blinding_result.blind_msg).unwrap();
    
    let unblinded_sig = unblind(
        keypair.public.clone(),
        client_addr.clone(),
        election_id.clone(),
        iat,
        blinding_result.secret,
        blinded_sig
    ).unwrap();

    let msg = encoded_req(client_addr, election_id, iat);
    assert!(blind_verify(&keypair.public, unblinded_sig, &msg).unwrap());
}
