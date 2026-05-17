//! Measures the byte-level breakdown of a vote transaction for tab:vote-size.
//!
//! Components:
//!   1. Encrypted ballot (ElGamal ciphertexts only)
//!   2. ZKPs (range + sum proofs inside EncryptedChoice)
//!   3. Ticket + RSA blind signature
//!   4. Transaction metadata (EIP-1559 envelope excluding calldata)

use alloy_primitives::U256;
use alloy_sol_types::SolValue;
use elastic_elgamal::app::{EncryptedChoice, SingleChoice};
use elastic_elgamal::group::Ristretto;
use postcard::{from_bytes, to_allocvec};
use primitives::ballots::{encrypt_vote, generate_elgamal_keypair};
use primitives::blind_signatures;
use rand_legacy::rngs::StdRng;
use rand_legacy::{Rng, SeedableRng};

fn main() {
    let candidates: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);

    let seed: u64 = 42;
    let mut rng = StdRng::seed_from_u64(seed);
    let choice = rng.gen_range(0..candidates);

    // --- 1 & 2: Ballot + ZKP ---
    let (pk, _sk) = generate_elgamal_keypair();
    let encrypted = encrypt_vote(&pk, choice, candidates).expect("encrypt failed");
    let total_ballot_bytes = encrypted.len();

    // Deserialize to extract ciphertexts only
    let ballot = from_bytes::<EncryptedChoice<Ristretto, SingleChoice>>(&encrypted).unwrap();
    let ciphertexts_only = to_allocvec(&ballot.choices_unchecked().to_vec()).unwrap();
    let ciphertexts_size = ciphertexts_only.len();
    let zkp_size = total_ballot_bytes - ciphertexts_size;

    // --- 3: Ticket + RSA signature ---
    // The ticket is reconstructed on-chain: abi.encode(addr_string, id_, iat)
    // Only `iat` (uint256) and `signature` (bytes) are passed as calldata.
    let keypair = blind_signatures::generate_rsa_keypair().expect("keygen failed");

    // Simulate the blind signature flow
    let client_addr = "0x0000000000000000000000000000000000000001".to_string();
    let election_id = "election_1".to_string();
    let iat: u32 = 1700000000;
    let msg = (client_addr, election_id, U256::from(iat)).abi_encode_sequence();

    let (blind_msg, secret) =
        blind_signatures::create_request(&keypair.public, &msg).expect("blind failed");
    let blind_sig = blind_signatures::sign(&keypair.private, &blind_msg).expect("sign failed");
    let signature = blind_signatures::unblind(&keypair.public, &msg, secret, blind_sig)
        .expect("unblind failed");

    let signature_size = signature.len();
    // In the ABI calldata: iat is 32 bytes (uint256), signature is dynamic bytes
    // ABI encoding of signature: 32 (offset) + 32 (length) + ceil(sig_len/32)*32
    let iat_abi_size: usize = 32;
    let sig_abi_size: usize = 32 + 32 + ((signature_size + 31) / 32) * 32;
    let ticket_plus_sig_calldata = iat_abi_size + sig_abi_size;

    // --- 4: Transaction metadata (EIP-1559 envelope) ---
    // EIP-1559 tx fields (RLP-encoded sizes, typical values):
    //   type prefix:          1 byte
    //   chainId:              ~3 bytes (small private chain)
    //   nonce:                ~2 bytes (small values)
    //   maxPriorityFeePerGas: ~4 bytes
    //   maxFeePerGas:         ~5 bytes
    //   gasLimit:             ~3 bytes
    //   to (address):         21 bytes (20 + length prefix)
    //   value:                1 byte (0)
    //   accessList:           1 byte (empty)
    //   signature (v,r,s):    ~66 bytes (1 + 32 + 33 or similar)
    //   RLP overhead:         ~5 bytes (list headers)
    //
    // More precisely, let's compute from the actual EIP-1559 structure.
    // A typical vote tx with empty value and no access list:
    let tx_metadata_size = compute_eip1559_metadata_size();

    // --- Also compute the ABI calldata overhead ---
    // vote(bytes ballot, uint256 iat, bytes signature)
    // Function selector: 4 bytes
    // ABI head for ballot (offset): 32 bytes
    // ABI head for iat: 32 bytes (already counted above)
    // ABI head for signature (offset): 32 bytes
    // ABI body for ballot: 32 (length) + ceil(ballot_len/32)*32
    let selector_size: usize = 4;

    // Total calldata
    let total_calldata = selector_size
        + 32  // offset to ballot
        + 32  // iat value
        + 32  // offset to signature
        + 32 + ((total_ballot_bytes + 31) / 32) * 32  // ballot length + padded data
        + 32 + ((signature_size + 31) / 32) * 32; // sig length + padded data

    // --- Output ---
    println!(
        "=== Vote Transaction Size Breakdown ({} candidates) ===\n",
        candidates
    );
    println!(
        "1. Encrypted ballot (ElGamal ciphertexts): {} bytes",
        ciphertexts_size
    );
    println!(
        "2. ZKPs (range + sum proofs):              {} bytes",
        zkp_size
    );
    println!("3. Ticket + RSA signature:");
    println!(
        "     Raw RSA signature:                    {} bytes",
        signature_size
    );
    println!(
        "     iat (uint256, ABI-encoded):           {} bytes",
        iat_abi_size
    );
    println!(
        "     Subtotal (ABI-encoded calldata):      {} bytes",
        ticket_plus_sig_calldata
    );
    println!(
        "4. Transaction metadata (EIP-1559):        {} bytes",
        tx_metadata_size
    );
    println!();
    println!("--- Calldata breakdown ---");
    println!("   Function selector:                      4 bytes");
    println!(
        "   ABI-encoded ballot ({} raw):     {} bytes",
        total_ballot_bytes,
        32 + ((total_ballot_bytes + 31) / 32) * 32
    );
    println!("   ABI-encoded iat:                        32 bytes");
    println!(
        "   ABI-encoded signature ({} raw):  {} bytes",
        signature_size,
        32 + ((signature_size + 31) / 32) * 32
    );
    println!("   Offsets (3 dynamic params):             96 bytes");
    println!(
        "   Total calldata:                         {} bytes",
        total_calldata
    );
    println!();
    println!("--- Summary for tab:vote-size ---");
    println!(
        "   Encrypted ballot:                       {} bytes",
        ciphertexts_size
    );
    println!(
        "   ZKPs:                                   {} bytes",
        zkp_size
    );
    println!(
        "   Ticket + RSA signature:                 {} bytes",
        ticket_plus_sig_calldata
    );
    println!(
        "   Transaction metadata:                   {} bytes",
        tx_metadata_size
    );
    println!("   ─────────────────────────────────────────────────");
    println!(
        "   Total per vote:                         {} bytes",
        total_calldata + tx_metadata_size
    );

    // CSV output for easy parsing
    println!("\n--- CSV ---");
    println!("component,bytes");
    println!("encrypted_ballot,{}", ciphertexts_size);
    println!("zkps,{}", zkp_size);
    println!("ticket_rsa_signature,{}", ticket_plus_sig_calldata);
    println!("tx_metadata,{}", tx_metadata_size);
    println!("total_calldata,{}", total_calldata);
    println!("total_tx,{}", total_calldata + tx_metadata_size);
}

/// Computes the RLP-encoded size of EIP-1559 transaction metadata
/// (everything except the `data` field), using realistic values
/// for a private PoA chain vote transaction.
fn compute_eip1559_metadata_size() -> usize {
    // We compute the RLP encoding size of each field:
    // type byte: 1 (0x02 prefix, not RLP-encoded)
    // chainId: small value (e.g., 1337) → 2 bytes value + 1 length = ~3
    // nonce: small (0-65535) → ~2-3 bytes
    // maxPriorityFeePerGas: e.g., 1 gwei = 10^9 → 4 bytes + 1 = 5
    // maxFeePerGas: e.g., 10 gwei = 10^10 → 5 bytes + 1 = 6
    // gasLimit: e.g., 500000 → 3 bytes + 1 = 4
    // to: 20 bytes + 1 length = 21
    // value: 0 → 1 byte
    // data: (excluded - this is what we're measuring separately)
    // accessList: empty → 1 byte (0xc0)
    // v: 0 or 1 → 1 byte
    // r: 32 bytes + 1 = 33
    // s: 32 bytes + 1 = 33
    // RLP list header: ~3 bytes (for list > 55 bytes)
    //
    // Total metadata ≈ 1 + 3 + 3 + 5 + 6 + 4 + 21 + 1 + 1 + 1 + 33 + 33 + 3 = 115
    //
    // More precise calculation using actual RLP rules:
    let type_prefix = 1; // 0x02
    let chain_id = 3; // RLP(1337) = [0x82, 0x05, 0x39]
    let nonce = 2; // RLP(small nonce) ≈ 2 bytes avg
    let max_priority_fee = 5; // RLP(1_000_000_000) = [0x84, ...]
    let max_fee = 6; // RLP(10_000_000_000) = [0x85, ...]
    let gas_limit = 4; // RLP(500_000) = [0x83, ...]
    let to = 21; // RLP(20-byte address) = [0x94, ...20 bytes]
    let value = 1; // RLP(0) = [0x80]
    // data is excluded (measured separately as calldata)
    let access_list = 1; // RLP([]) = [0xc0]
    let v = 1; // RLP(0 or 1) = [0x00] or [0x01]
    let r = 33; // RLP(32-byte scalar) = [0xa0, ...32 bytes]
    let s = 33; // RLP(32-byte scalar) = [0xa0, ...32 bytes]
    let rlp_list_header = 3; // list header for payload > 55 bytes

    type_prefix
        + chain_id
        + nonce
        + max_priority_fee
        + max_fee
        + gas_limit
        + to
        + value
        + access_list
        + v
        + r
        + s
        + rlp_list_header
}
