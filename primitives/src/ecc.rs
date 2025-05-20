pub fn ecc_encrypt(pk: Vec<u8>, msg: Vec<u8>) -> Result<Vec<u8>, String> {
    ecies::encrypt(&pk, &msg)
        .map(Into::into)
        .map_err(|e| e.to_string())
}

pub fn ecc_decrypt(sk: Vec<u8>, encrypted: Vec<u8>) -> Result<Vec<u8>, String> {
    ecies::decrypt(&sk, &encrypted)
        .map(Into::into)
        .map_err(|e| e.to_string())
}
