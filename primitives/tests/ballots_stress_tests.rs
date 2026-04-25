use alloy_primitives::{Bytes, U256};
use alloy_sol_types::SolValue;
use primitives::ballots::{
    add_votes, decrypt_result, encrypt_vote, generate_acc, generate_elgamal_keypair,
};
use rand_legacy::rngs::StdRng;
use rand_legacy::Rng;
use rand_legacy::SeedableRng;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::time::{Duration, Instant};

// --- Parametrized vote counts (REQ-3) ---
const SINGLE_CANDIDATE_VOTES: usize = 2000;
const DISTRIBUTED_VOTES: usize = 2000;
const MANY_CANDIDATES_VOTES: usize = 2000;
const RANDOM_VOTES: usize = 2000;

const DISTRIBUTED_CANDIDATES: usize = 5;
const MANY_CANDIDATES: usize = 10;
const RANDOM_CANDIDATES: usize = 5;
const ZERO_VOTE_CANDIDATES: usize = 3;

const RESULTS_FILE: &str = "stress_test_results.txt";

// --- Resource tracking helpers ---

fn get_rss_kb() -> u64 {
    fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmRSS:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|v| v.parse().ok())
        })
        .unwrap_or(0)
}

fn get_cpu_times() -> (f64, f64) {
    // Returns (user_secs, system_secs) from /proc/self/stat
    let ticks_per_sec = 100.0_f64; // sysconf(_SC_CLK_TCK) is 100 on most Linux
    fs::read_to_string("/proc/self/stat")
        .ok()
        .and_then(|s| {
            let fields: Vec<&str> = s.split_whitespace().collect();
            // field 13 = utime, field 14 = stime (0-indexed)
            let utime: f64 = fields.get(13)?.parse().ok()?;
            let stime: f64 = fields.get(14)?.parse().ok()?;
            Some((utime / ticks_per_sec, stime / ticks_per_sec))
        })
        .unwrap_or((0.0, 0.0))
}

// --- Helpers (REQ-2) ---

fn record_timing(
    test_name: &str,
    phase: &str,
    duration: Duration,
    detail: &str,
    rss_before_kb: u64,
    rss_after_kb: u64,
    cpu_before: (f64, f64),
    cpu_after: (f64, f64),
) {
    let cpu_user = cpu_after.0 - cpu_before.0;
    let cpu_sys = cpu_after.1 - cpu_before.1;
    let line = format!(
        "{} | {} | wall={:.3}s | cpu_user={:.3}s cpu_sys={:.3}s | rss_before={}KB rss_after={}KB rss_delta={}KB | {}\n",
        test_name,
        phase,
        duration.as_secs_f64(),
        cpu_user,
        cpu_sys,
        rss_before_kb,
        rss_after_kb,
        rss_after_kb as i64 - rss_before_kb as i64,
        detail
    );
    print!("{}", line);

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(RESULTS_FILE)
        .expect("failed to open results file");
    file.write_all(line.as_bytes())
        .expect("failed to write results");
    file.flush().expect("failed to flush results");
}

/// Measures a phase: captures RSS and CPU before/after, wall time, then records.
fn measure_phase<F, T>(test_name: &str, phase: &str, detail: &str, f: F) -> T
where
    F: FnOnce() -> T,
{
    let rss_before = get_rss_kb();
    let cpu_before = get_cpu_times();
    let start = Instant::now();
    let result = f();
    let elapsed = start.elapsed();
    let cpu_after = get_cpu_times();
    let rss_after = get_rss_kb();
    record_timing(test_name, phase, elapsed, detail, rss_before, rss_after, cpu_before, cpu_after);
    result
}

struct StressResult {
    tallies: Vec<u64>,
}

fn run_voting_flow(test_name: &str, candidates: usize, votes: &[usize]) -> StressResult {
    let (pk, sk) = generate_elgamal_keypair();
    let encoded_count = U256::from(candidates).abi_encode();
    let mut acc = generate_acc(&encoded_count);
    let max_count = votes.len() as u64;

    // Phase 1: Encrypt all votes
    let encrypted = measure_phase(
        test_name,
        "encryption",
        &format!("{} votes, {} candidates", votes.len(), candidates),
        || {
            votes
                .iter()
                .map(|&choice| encrypt_vote(&pk, choice, candidates).expect("encrypt failed"))
                .collect::<Vec<Vec<u8>>>()
        },
    );

    // Phase 2: Homomorphic addition
    measure_phase(
        test_name,
        "addition",
        &format!("{} votes", votes.len()),
        || {
            for ballot in &encrypted {
                let input =
                    (Bytes::from(acc.clone()), Bytes::from(ballot.clone())).abi_encode_sequence();
                acc = add_votes(&input);
            }
        },
    );

    // Phase 3: Decryption
    let tallies = measure_phase(
        test_name,
        "decryption",
        &format!("{} candidates, max_count={}", candidates, max_count),
        || decrypt_result(&sk, &acc, max_count).expect("decrypt failed"),
    );

    StressResult { tallies }
}

// --- Tests ---

#[test]
fn test_stress_single_candidate() {
    let candidates = 3;
    let votes = vec![0; SINGLE_CANDIDATE_VOTES];

    let result = run_voting_flow("test_stress_single_candidate", candidates, &votes);

    assert_eq!(result.tallies[0], SINGLE_CANDIDATE_VOTES as u64);
    for i in 1..candidates {
        assert_eq!(result.tallies[i], 0);
    }
}

#[test]
fn test_stress_distributed() {
    let votes: Vec<usize> = (0..DISTRIBUTED_VOTES)
        .map(|i| i % DISTRIBUTED_CANDIDATES)
        .collect();

    let result = run_voting_flow("test_stress_distributed", DISTRIBUTED_CANDIDATES, &votes);

    let expected_per_candidate = (DISTRIBUTED_VOTES / DISTRIBUTED_CANDIDATES) as u64;
    for i in 0..DISTRIBUTED_CANDIDATES {
        assert_eq!(result.tallies[i], expected_per_candidate);
    }
}

#[test]
fn test_stress_many_candidates() {
    let votes: Vec<usize> = (0..MANY_CANDIDATES_VOTES)
        .map(|i| i % MANY_CANDIDATES)
        .collect();

    let result = run_voting_flow("test_stress_many_candidates", MANY_CANDIDATES, &votes);

    let expected_per_candidate = (MANY_CANDIDATES_VOTES / MANY_CANDIDATES) as u64;
    for i in 0..MANY_CANDIDATES {
        assert_eq!(result.tallies[i], expected_per_candidate);
    }
}

#[test]
fn test_stress_random() {
    let mut rng = StdRng::seed_from_u64(42);
    let mut expected = vec![0u64; RANDOM_CANDIDATES];
    let votes: Vec<usize> = (0..RANDOM_VOTES)
        .map(|_| {
            let choice = rng.gen_range(0..RANDOM_CANDIDATES);
            expected[choice] += 1;
            choice
        })
        .collect();

    let result = run_voting_flow("test_stress_random", RANDOM_CANDIDATES, &votes);

    for i in 0..RANDOM_CANDIDATES {
        assert_eq!(result.tallies[i], expected[i]);
    }
}

#[test]
fn test_stress_zero_votes() {
    let (_, sk) = generate_elgamal_keypair();
    let encoded_count = U256::from(ZERO_VOTE_CANDIDATES).abi_encode();
    let acc = generate_acc(&encoded_count);

    let tallies = measure_phase(
        "test_stress_zero_votes",
        "decryption",
        &format!("{} candidates, max_count=0", ZERO_VOTE_CANDIDATES),
        || decrypt_result(&sk, &acc, 0).expect("decrypt failed"),
    );

    for i in 0..ZERO_VOTE_CANDIDATES {
        assert_eq!(tallies[i], 0);
    }
}
