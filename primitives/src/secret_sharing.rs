use sharks::{Share, Sharks};

pub fn split_secret(secret: Vec<u8>, k: usize, n: usize) -> Vec<Vec<u8>> {
    let sharks = Sharks(k as u8);
    let dealer = sharks.dealer(&secret);

    dealer.take(n).map(|share| Vec::from(&share)).collect()
}

pub fn recover_secret(shares: Vec<Vec<u8>>, k: usize) -> Result<Vec<u8>, String> {
    let sharks = Sharks(k as u8);

    let parsed_shares = shares
        .into_iter()
        .map(|share| Share::try_from(share.as_slice()).unwrap())
        .collect::<Vec<Share>>();

    sharks.recover(&parsed_shares).map_err(String::from)
}
