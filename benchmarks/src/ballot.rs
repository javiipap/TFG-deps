use std::error::Error;

pub trait Ballot<PublicKey, SecretKey> {
    fn generate_kepair() -> (PublicKey, SecretKey);

    fn new(candidate: usize, num_candidates: usize, public_key: &PublicKey) -> Self;

    fn decrypt(
        &self,
        secret_key: &SecretKey,
        max: Option<usize>,
    ) -> Result<Vec<u64>, Box<dyn Error>>;
}
