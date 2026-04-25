use blind_signatures::ecc::{ecc_encrypt, ecc_decrypt};

#[test]
fn test_ecc_encrypt_decrypt() {
    let (sk, pk) = ecies::utils::generate_keypair();
    let pk_vec = pk.serialize().to_vec();
    let sk_vec = sk.serialize().to_vec();

    let msg = b"Test Message".to_vec();
    let encrypted = ecc_encrypt(pk_vec, msg.clone());
    let decrypted = ecc_decrypt(sk_vec, encrypted);

    assert_eq!(decrypted, msg);
}
