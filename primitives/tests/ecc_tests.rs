use primitives::ecc::{ecc_decrypt, ecc_encrypt};

#[test]
fn test_ecc_encrypt_decrypt() {
    let (sk, pk) = ecies::utils::generate_keypair();
    let (sk, pk) = (sk.serialize().to_vec(), pk.serialize().to_vec());

    let msg = b"hello world".to_vec();

    let encrypted = ecc_encrypt(&pk, &msg).unwrap();
    let decrypted = ecc_decrypt(&sk, &encrypted).unwrap();

    assert_eq!(msg, decrypted);
}
