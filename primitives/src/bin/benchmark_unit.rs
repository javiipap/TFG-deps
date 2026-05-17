use alloy_primitives::{Bytes, U256};
use alloy_sol_types::SolValue;
use elastic_elgamal::group::Ristretto;
use elastic_elgamal::PublicKey;
use primitives::ballots::{
    add_votes, encrypt_vote, generate_acc, generate_elgamal_keypair, verify_vote,
};
use rand_legacy::Rng;
use rand_legacy::SeedableRng;
use rand_legacy::rngs::StdRng;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::time::Instant;

// --- Config ---

struct Config {
    candidates: Vec<usize>,
    runs: usize,
    output: String,
    seed: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            candidates: vec![3, 5, 10, 20],
            runs: 100,
            output: "benchmark_unit__results.csv".into(),
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
    raw_encryption: PhaseMeasurement,
    proof_generation: PhaseMeasurement,
    zkp_verification: PhaseMeasurement,
    addition: PhaseMeasurement,
}

fn run_benchmark(candidates: usize, seed: u64) -> RunResult {
    let (pk, _sk) = generate_elgamal_keypair();
    let encoded_count = U256::from(candidates).abi_encode();
    let mut acc = generate_acc(&encoded_count);
    let mut rng = StdRng::seed_from_u64(seed);
    let choice = rng.gen_range(0..candidates);

    // Phase 1: Raw ElGamal encryption (no proof)
    let (_, raw_encryption) = measure(|| {
        let receiver = PublicKey::<Ristretto>::from_bytes(&pk).unwrap();
        let mut enc_rng = StdRng::seed_from_u64(seed);
        for i in 0..candidates {
            let val = if i == choice { 1_u64 } else { 0_u64 };
            receiver.encrypt(val, &mut enc_rng);
        }
    });

    // Phase 2: Full ballot creation (encryption + ZKP proof generation)
    let (encrypted, proof_generation) = measure(|| {
        encrypt_vote(&pk, choice, candidates).expect("encrypt failed")
    });

    // Phase 3: ZKP verification
    let (_, zkp_verification) = measure(|| {
        let input = (
            U256::from(candidates),
            Bytes::from(pk.clone()),
            Bytes::from(encrypted.clone()),
        )
            .abi_encode_sequence();
        verify_vote(&input);
    });

    // Phase 4: Homomorphic addition
    let (_, addition) = measure(|| {
        let input =
            (Bytes::from(acc.clone()), Bytes::from(encrypted.clone())).abi_encode_sequence();
        acc = add_votes(&input);
    });

    RunResult {
        raw_encryption,
        proof_generation,
        zkp_verification,
        addition,
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

// --- Temp dump helpers ---

fn dump_set_to_temp(
    tmp_path: &str,
    candidates: usize,
    runs: usize,
    results: &[RunResult],
) {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(tmp_path)
        .expect("failed to open temp file");

    let phases: Vec<(&str, Vec<&PhaseMeasurement>)> = vec![
        ("raw_encryption", results.iter().map(|r| &r.raw_encryption).collect()),
        ("proof_generation", results.iter().map(|r| &r.proof_generation).collect()),
        ("zkp_verification", results.iter().map(|r| &r.zkp_verification).collect()),
        ("addition", results.iter().map(|r| &r.addition).collect()),
    ];

    for (phase, measurements) in &phases {
        let walls: Vec<f64> = measurements.iter().map(|m| m.wall_secs).collect();
        let cpus: Vec<f64> = measurements.iter().map(|m| m.cpu_user_secs).collect();
        let rsss: Vec<f64> = measurements.iter().map(|m| m.rss_delta_kb as f64).collect();

        let line = format!(
            "{},{},{},{:.6},{:.6},{:.6},{:.6},{:.1},{:.1}",
            candidates,
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
    }
    file.flush().expect("failed to flush");
}

fn aggregate_temp_to_output(tmp_path: &str, output_path: &str) {
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(output_path)
        .expect("failed to open output file");

    writeln!(
        file,
        "candidates,phase,runs,mean_wall_s,stddev_wall_s,mean_cpu_user_s,stddev_cpu_user_s,mean_rss_delta_kb,stddev_rss_delta_kb"
    )
    .expect("failed to write header");

    let data = fs::read_to_string(tmp_path).expect("failed to read temp file");
    write!(file, "{}", data).expect("failed to write data");
    file.flush().expect("failed to flush");

    let _ = fs::remove_file(tmp_path);
}

// --- Main ---

fn main() {
    let config = parse_args();
    let tmp_path = format!("{}.tmp", config.output);

    // Clear any leftover temp file
    let _ = fs::remove_file(&tmp_path);

    for &candidates in &config.candidates {
        println!("\n=== candidates={} ({} runs) ===", candidates, config.runs);

        let mut results: Vec<RunResult> = Vec::with_capacity(config.runs);
        for run in 0..config.runs {
            let seed = config.seed.wrapping_add(run as u64);
            println!("  run {}/{}", run + 1, config.runs);
            results.push(run_benchmark(candidates, seed));
        }

        dump_set_to_temp(&tmp_path, candidates, config.runs, &results);
        drop(results);
    }

    aggregate_temp_to_output(&tmp_path, &config.output);
    println!("\nResults written to {}", config.output);
}
