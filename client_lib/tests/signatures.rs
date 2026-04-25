use blind_signatures::signatures::{rsa_encrypt, rsa_decrypt, rsa_verify};
use primitives::signatures::{generate_rsa_keypair, rsa_sign};

#[test]
fn test_rsa_encrypt_decrypt() {
    let (pk, sk) = generate_rsa_keypair().unwrap();
    let msg = b"Test Message".to_vec();
    
    let encrypted = rsa_encrypt(pk.clone(), msg.clone()).unwrap();
    let decrypted = rsa_decrypt(sk, encrypted).unwrap();
    
    assert_eq!(decrypted, msg);
}

#[test]
fn test_rsa_sign_verify() {
    let (pk, sk) = generate_rsa_keypair().unwrap();
    let msg = b"Test Message".to_vec();
    
    let signature = rsa_sign(&sk, &msg).unwrap();
    let result = rsa_verify(pk, signature, msg);
    
    assert!(result.is_ok());
}
