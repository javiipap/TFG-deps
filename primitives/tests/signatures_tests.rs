use primitives::signatures::{
    generate_rsa_keypair, rsa_decrypt, rsa_encrypt, rsa_sign, rsa_verify,
};

#[test]
fn test_rsa_sign_verify() {
    let keypair = generate_rsa_keypair().expect("failed to generate keypair");

    let msg = &b"test message".to_vec();

    let signature = rsa_sign(&keypair.1, msg).expect("failed to sign");
    rsa_verify(&keypair.0, msg, &signature).expect("failed to verify");
}

#[test]
fn test_rsa_encrypt_decrypt() {
    let keypair = generate_rsa_keypair().expect("failed to generate keypair");
    let msg = &b"secret rsa message".to_vec();

    let encrypted = rsa_encrypt(&keypair.0, msg).expect("failed to encrypt");
    let decrypted = rsa_decrypt(&keypair.1, &encrypted).expect("failed to decrypt");

    assert_eq!(msg.clone(), decrypted);
}
