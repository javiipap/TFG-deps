use blind_rsa_signatures::{
    BlindSignature, KeyPair, Options, PublicKey, Secret, SecretKey, Signature,
};
use rand::thread_rng;
use std::error::Error;

pub struct ExportedKeyPair {
    pub public: Vec<u8>,
    pub secret: Vec<u8>,
}

pub fn generate_rsa_keypair() -> Result<ExportedKeyPair, Box<dyn Error>> {
    let mut rng = thread_rng();

    let keypair = KeyPair::generate(&mut rng, 2048)?;

    Ok(ExportedKeyPair {
        public: keypair.pk.to_der()?,
        secret: keypair.sk.to_der()?,
    })
}

pub struct ExportedBlindingResult {
    pub blind_msg: Vec<u8>,
    pub secret: Vec<u8>,
    pub msg_randomizer: Vec<u8>,
}

pub fn create_request(
    public_key: Vec<u8>,
    msg: Vec<u8>,
) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
    let options = Options::default();
    let mut rng = thread_rng();
    let public_key = PublicKey::from_der(&public_key)?;

    let res = public_key.blind(&mut rng, msg, false, &options)?;

    Ok((res.blind_msg.0, res.secret.0))
}

pub fn sign(secret_key: Vec<u8>, blind_msg: Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
    let options = Options::default();
    let private_key = SecretKey::from_der(&secret_key)?;
    let mut rng = thread_rng();

    Ok(private_key.blind_sign(&mut rng, &blind_msg, &options)?.0)
}

pub fn unblind(
    public_key: Vec<u8>,
    msg: Vec<u8>,
    secret: Vec<u8>,
    blind_sig: Vec<u8>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let options = Options::default();
    let public_key = PublicKey::from_der(&public_key)?;

    Ok(public_key
        .finalize(
            &BlindSignature::new(blind_sig),
            &Secret::new(secret),
            None,
            msg,
            &options,
        )?
        .0)
}

pub fn verify(
    public_key: Vec<u8>,
    signature_bytes: Vec<u8>,
    msg: Vec<u8>,
) -> Result<bool, Box<dyn Error>> {
    let public_key = PublicKey::from_der(&public_key)?;
    let options = Options::default();

    let signature = Signature::new(signature_bytes);

    match signature.verify(&public_key, None, msg, &options) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::{ExportedKeyPair, create_request, generate_rsa_keypair, sign, unblind, verify};

    #[test]
    fn it_works() -> Result<(), Box<dyn std::error::Error>> {
        let ExportedKeyPair {
            public: public_key,
            secret: private_key,
        } = generate_rsa_keypair()?;

        let msg = vec![0; 10];

        let req = create_request(public_key.clone(), msg.clone())?;

        let blinded_signature = sign(private_key, req.0.clone())?;

        let signature = unblind(
            public_key.clone(),
            msg.clone(),
            req.1.clone(),
            blinded_signature,
        )?;

        verify(public_key, signature, msg)?;

        Ok(())
    }
}
