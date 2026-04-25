use blind_rsa_signatures::{
    BlindMessage, BlindSignature, BlindingResult, DefaultRng, Deterministic, KeyPair, PSS,
    PublicKey, Secret, SecretKey, Sha384, Signature,
};
use std::error::Error;

/// Structure to hold exported RSA key pair.
pub struct ExportedKeyPair {
    pub public: Vec<u8>,
    pub private: Vec<u8>,
}

/// Generates a new RSA key pair for blind signatures.
///
/// Use 2048-bit keys.
///
/// # Returns
///
/// Returns an `ExportedKeyPair` with DER-encoded keys.
pub fn generate_rsa_keypair() -> Result<ExportedKeyPair, Box<dyn Error>> {
    let keypair = KeyPair::<Sha384, PSS, Deterministic>::generate(&mut DefaultRng, 2048)?;

    Ok(ExportedKeyPair {
        public: keypair.pk.to_der()?,
        private: keypair.sk.to_der()?,
    })
}

/// Deserializes a public key from DER format.
pub fn deserialize_pub(
    public_key: &Vec<u8>,
) -> Result<PublicKey<Sha384, PSS, Deterministic>, blind_rsa_signatures::Error> {
    PublicKey::<Sha384, PSS, Deterministic>::from_der(public_key)
}

/// Deserializes a private key from DER format.
pub fn deserialize_priv(
    private_key: &Vec<u8>,
) -> Result<SecretKey<Sha384, PSS, Deterministic>, blind_rsa_signatures::Error> {
    SecretKey::<Sha384, PSS, Deterministic>::from_der(private_key)
}

/// Structure to hold the result of blinding a message.
pub struct ExportedBlindingResult {
    pub blind_message: Vec<u8>,
    pub secret: Vec<u8>,
    pub msg_randomizer: Vec<u8>,
}

/// Creates a blind signature request.
///
/// # Arguments
///
/// * `public_key` - DER-encoded public key.
/// * `msg` - Message to be blinded.
///
/// # Returns
///
/// Returns a tuple containing the blinded message and the secret (blinding factor).
pub fn create_request(
    public_key: &Vec<u8>,
    msg: &Vec<u8>,
) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
    let public_key = deserialize_pub(&public_key)?;

    let res = public_key.blind(&mut DefaultRng, msg)?;

    Ok((res.blind_message.0, res.secret.0))
}

/// Signs a blinded message.
///
/// # Arguments
///
/// * `private_key` - DER-encoded private key.
/// * `blind_message` - The blinded message to sign.
///
/// # Returns
///
/// Returns the blinded signature as `Vec<u8>`.
pub fn sign(private_key: &Vec<u8>, blind_message: &Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
    let private_key = deserialize_priv(&private_key)?;

    Ok(private_key.blind_sign(&blind_message)?.0)
}

/// Unblinds a signature.
///
/// # Arguments
///
/// * `public_key` - DER-encoded public key.
/// * `msg` - Original message.
/// * `secret` - Blinding factor.
/// * `blind_sig` - Blinded signature.
///
/// # Returns
///
/// Returns the unblinded signature as `Vec<u8>`.
pub fn unblind(
    public_key: &Vec<u8>,
    msg: &Vec<u8>,
    secret: Vec<u8>,
    blind_sig: Vec<u8>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let public_key = deserialize_pub(&public_key)?;

    let blinding_result = BlindingResult {
        blind_message: BlindMessage(msg.clone()),
        secret: Secret(secret),
        msg_randomizer: None,
    };

    let blind_signature = BlindSignature::new(blind_sig);

    Ok(public_key
        .finalize(&blind_signature, &blinding_result, &msg)?
        .0)
}

/// Verifies a blind signature.
///
/// # Arguments
///
/// * `public_key` - DER-encoded public key.
/// * `signature_bytes` - The unblinded signature.
/// * `msg` - The original message.
///
/// # Returns
///
/// Returns `true` if valid, `false` otherwise.
pub fn verify(
    public_key: &Vec<u8>,
    signature_bytes: Vec<u8>,
    msg: &Vec<u8>,
) -> Result<bool, Box<dyn Error>> {
    let public_key = deserialize_pub(&public_key)?;

    let signature = Signature::new(signature_bytes);

    match public_key.verify(&signature, None, msg) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}
