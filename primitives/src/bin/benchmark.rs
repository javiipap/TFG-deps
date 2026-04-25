use alloy_primitives::{Bytes, U256};
use alloy_sol_types::SolValue;
use primitives::ballots::{
    add_votes, decrypt_result, encrypt_vote, generate_acc, generate_elgamal_keypair, verify_vote,
};
use rand_legacy::rngs::StdRng;
use rand_legacy::Rng;
use rand_legacy::SeedableRng;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::time::Instant;

// --- Config ---

struct Config {
    ballots: Vec<usize>,
    candidates: Vec<usize>,
    runs: usize,
    output: String,
    seed: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            ballots: vec![100, 500, 1000, 2000],
            candidates: vec![3, 5, 10],
            runs: 5,
            output: "benchmark_results.csv".into(),
            seed: 42,
        }
    }
}

fn parse_csv_usize(s: &str) -> Vec<usize> {
    s.split(',')
        .map(|v| v.trim().parse().expect("invalid number"))
        .collect()
}

fn parse_args() -> Config {
    let args: Vec<String> = std::env::args().collect();
    let mut config = Config::default();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--ballots" => {
                i += 1;
                config.ballots = parse_csv_usize(&args[i]);
            }
            "--candidates" => {
                i += 1;
                config.candidates = parse_csv_usize(&args[i]);
            }
            "--runs" => {
                i += 1;
                config.runs = args[i].parse().expect("invalid runs");
            }
            "--output" => {
                i += 1;
                config.output = args[i].clone();
            }
            "--seed" => {
                i += 1;
                config.seed = args[i].parse().expect("invalid seed");
            }
            other => panic!("Unknown argument: {}", other),
        }
        i += 1;
    }
    config
}

// --- Resource tracking ---

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
    let ticks_per_sec = 100.0_f64;
    fs::read_to_string("/proc/self/stat")
        .ok()
        .and_then(|s| {
            let fields: Vec<&str> = s.split_whitespace().collect();
            let utime: f64 = fields.get(13)?.parse().ok()?;
            let stime: f64 = fields.get(14)?.parse().ok()?;
            Some((utime / ticks_per_sec, stime / ticks_per_sec))
        })
        .unwrap_or((0.0, 0.0))
}

struct PhaseMeasurement {
    wall_secs: f64,
    cpu_user_secs: f64,
    rss_delta_kb: i64,
}

fn measure<F, T>(f: F) -> (T, PhaseMeasurement)
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
    (
        result,
        PhaseMeasurement {
            wall_secs: elapsed.as_secs_f64(),
            cpu_user_secs: cpu_after.0 - cpu_before.0,
            rss_delta_kb: rss_after as i64 - rss_before as i64,
        },
    )
}

// --- Benchmark ---

struct RunResult {
    encryption: PhaseMeasurement,
    zkp: Option<PhaseMeasurement>,
    addition: PhaseMeasurement,
    decryption: PhaseMeasurement,
    correct: bool,
}

fn run_benchmark(ballots: usize, candidates: usize, zkp_enabled: bool, seed: u64) -> RunResult {
    let (pk, sk) = generate_elgamal_keypair();
    let encoded_count = U256::from(candidates).abi_encode();
    let mut acc = generate_acc(&encoded_count);
    let mut rng = StdRng::seed_from_u64(seed);
    let mut expected = vec![0u64; candidates];

    let votes: Vec<usize> = (0..ballots)
        .map(|_| {
            let c = rng.gen_range(0..candidates);
            expected[c] += 1;
            c
        })
        .collect();

    // Phase 1: Encryption
    let (encrypted, encryption) = measure(|| {
        votes
            .iter()
            .map(|&c| encrypt_vote(&pk, c, candidates).expect("encrypt failed"))
            .collect::<Vec<Vec<u8>>>()
    });

    // Phase 2: ZKP verification (optional)
    let zkp = if zkp_enabled {
        let (_, m) = measure(|| {
            for ballot in &encrypted {
                let input = (
                    U256::from(candidates),
                    Bytes::from(pk.clone()),
                    Bytes::from(ballot.clone()),
                )
                    .abi_encode_sequence();
                verify_vote(&input);
            }
        });
        Some(m)
    } else {
        None
    };

    // Phase 3: Homomorphic addition
    let (_, addition) = measure(|| {
        for ballot in &encrypted {
            let input =
                (Bytes::from(acc.clone()), Bytes::from(ballot.clone())).abi_encode_sequence();
            acc = add_votes(&input);
        }
    });

    // Phase 4: Decryption
    let (tallies, decryption) = measure(|| {
        decrypt_result(&sk, &acc, ballots as u64).expect("decrypt failed")
    });

    let correct = tallies.iter().zip(expected.iter()).all(|(a, b)| *a == *b);

    RunResult {
        encryption,
        zkp,
        addition,
        decryption,
        correct,
    }
}

// --- Statistics ---

fn mean(values: &[f64]) -> f64 {
    values.iter().sum::<f64>() / values.len() as f64
}

fn stddev(values: &[f64]) -> f64 {
    let m = mean(values);
    (values.iter().map(|v| (v - m).powi(2)).sum::<f64>() / values.len() as f64).sqrt()
}

// --- CSV output ---

fn write_csv_header(file: &mut fs::File) {
    writeln!(
        file,
        "ballots,candidates,zkp_enabled,phase,runs,mean_wall_s,stddev_wall_s,mean_cpu_user_s,stddev_cpu_user_s,mean_rss_delta_kb,stddev_rss_delta_kb"
    )
    .expect("failed to write header");
    file.flush().expect("failed to flush");
}

fn write_csv_row(
    file: &mut fs::File,
    ballots: usize,
    candidates: usize,
    zkp_enabled: bool,
    phase: &str,
    runs: usize,
    measurements: &[&PhaseMeasurement],
) {
    let walls: Vec<f64> = measurements.iter().map(|m| m.wall_secs).collect();
    let cpus: Vec<f64> = measurements.iter().map(|m| m.cpu_user_secs).collect();
    let rsss: Vec<f64> = measurements.iter().map(|m| m.rss_delta_kb as f64).collect();

    let line = format!(
        "{},{},{},{},{},{:.6},{:.6},{:.6},{:.6},{:.1},{:.1}",
        ballots,
        candidates,
        zkp_enabled,
        phase,
        runs,
        mean(&walls),
        stddev(&walls),
        mean(&cpus),
        stddev(&cpus),
        mean(&rsss),
        stddev(&rsss),
    );
    println!("  {}", line);
    writeln!(file, "{}", line).expect("failed to write row");
    file.flush().expect("failed to flush");
}

// --- Main ---

fn main() {
    let config = parse_args();

    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&config.output)
        .expect("failed to open output file");
    write_csv_header(&mut file);

    for &ballots in &config.ballots {
        for &candidates in &config.candidates {
            for zkp_enabled in [false, true] {
                println!(
                    "\n=== ballots={} candidates={} zkp={} ({} runs) ===",
                    ballots, candidates, zkp_enabled, config.runs
                );

                let mut results: Vec<RunResult> = Vec::with_capacity(config.runs);
                for run in 0..config.runs {
                    let seed = config.seed.wrapping_add(run as u64);
                    println!("  run {}/{}", run + 1, config.runs);
                    let r = run_benchmark(ballots, candidates, zkp_enabled, seed);
                    if !r.correct {
                        eprintln!("  WARNING: tally mismatch on run {}", run + 1);
                    }
                    results.push(r);
                }

                // Write stats per phase
                let phases: Vec<(&str, Vec<&PhaseMeasurement>)> = vec![
                    ("encryption", results.iter().map(|r| &r.encryption).collect()),
                    ("addition", results.iter().map(|r| &r.addition).collect()),
                    ("decryption", results.iter().map(|r| &r.decryption).collect()),
                ];

                for (phase, measurements) in &phases {
                    write_csv_row(
                        &mut file,
                        ballots,
                        candidates,
                        zkp_enabled,
                        phase,
                        config.runs,
                        measurements,
                    );
                }

                // ZKP phase only when enabled
                if zkp_enabled {
                    let zkp_measurements: Vec<&PhaseMeasurement> =
                        results.iter().filter_map(|r| r.zkp.as_ref()).collect();
                    write_csv_row(
                        &mut file,
                        ballots,
                        candidates,
                        zkp_enabled,
                        "zkp_verification",
                        config.runs,
                        &zkp_measurements,
                    );
                }
            }
        }
    }

    println!("\nResults written to {}", config.output);
}
