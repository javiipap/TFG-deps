use sharks::{Share, Sharks};

/// Splits a secret into `n` shares using Shamir's Secret Sharing, where `k` shares are required to reconstruct.
///
/// # Arguments
///
/// * `secret` - The secret to split as a byte vector.
/// * `k` - The threshold number of shares required to recover the secret.
/// * `n` - The total number of shares to generate.
///
/// # Returns
///
/// Returns a vector of shares, where each share is a `Vec<u8>`.
pub fn split_secret(secret: &Vec<u8>, k: usize, n: usize) -> Vec<Vec<u8>> {
    let sharks = Sharks(k as u8);
    let dealer = sharks.dealer(&secret);

    dealer.take(n).map(|share| Vec::from(&share)).collect()
}

/// Recovers a secret from a set of shares using Shamir's Secret Sharing.
///
/// # Arguments
///
/// * `shares` - A vector of shares, where each share is a `Vec<u8>`.
/// * `k` - The threshold number of shares required to recover the secret.
///
/// # Returns
///
/// Returns a `Result` containing the recovered secret as a `Vec<u8>` on success,
/// or a `String` error message on failure.
pub fn recover_secret(shares: &Vec<Vec<u8>>, k: usize) -> Result<Vec<u8>, String> {
    let sharks = Sharks(k as u8);

    let parsed_shares = shares
        .into_iter()
        .map(|share| Share::try_from(share.as_slice()).unwrap())
        .collect::<Vec<Share>>();

    sharks.recover(&parsed_shares).map_err(String::from)
}
