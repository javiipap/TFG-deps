use elastic_elgamal::group::Ristretto;
use elastic_elgamal::{Ciphertext, DiscreteLogTable, Keypair};
use postcard::to_allocvec;
use primitives::ballots::decrypt_result;
use rand_legacy::SeedableRng;
use rand_legacy::rngs::StdRng;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::mem::size_of;
use std::time::Instant;

// --- Config ---

struct Config {
    ballots: Vec<usize>,
    candidates: Vec<usize>,
    runs: usize,
    output: String,
    seed: u64,
    dlt_only: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            ballots: vec![10_000, 100_000, 1_000_000, 10_000_000, 40_000_000],
            candidates: vec![10],
            runs: 10,
            output: "benchmark_tally__results.csv".into(),
            seed: 42,
            dlt_only: true,
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
            "--dlt-only" => {
                config.dlt_only = true;
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

// --- Cached setup: encryption + homomorphic addition ---

struct CachedSetup {
    sk: Vec<u8>,
    acc: Vec<u8>,
    expected: Vec<u64>,
}

fn build_cached_setup(_ballots: usize, candidates: usize, seed: u64) -> CachedSetup {
    let mut rng = StdRng::seed_from_u64(seed);
    let keypair = Keypair::<Ristretto>::generate(&mut rng);
    let pk = keypair.public();
    let sk = Vec::from(keypair.secret().expose_scalar().as_bytes());

    let expected: Vec<u64> = (0..candidates).map(|i| i as u64).collect();
    let acc_vec: Vec<Ciphertext<Ristretto>> =
        expected.iter().map(|&v| pk.encrypt(v, &mut rng)).collect();
    let acc = to_allocvec(&acc_vec).unwrap();

    CachedSetup { sk, acc, expected }
}

// --- Benchmark (decryption only) ---

struct DltSize {
    estimated_heap_bytes: usize,
    rss_delta_kb: i64,
}

fn estimate_dlt_heap_bytes(entries: usize) -> usize {
    // DiscreteLogTable<Ristretto> uses HashMap<Vec<u8>, u64>
    // Key: Vec<u8> of 32 bytes (Ristretto point) → 24 (Vec header) + 32 (heap data) = 56
    // Value: u64 = 8 bytes
    // HashMap overhead per entry: ~1 byte control + padding ≈ bucket size aligned
    // Each bucket stores (key, value) = (56 + 8) = 64 bytes + 1 byte control
    // HashMap allocates capacity as power of 2 with ~87.5% load factor
    let capacity = (entries as f64 / 0.875).ceil() as usize;
    let capacity = capacity.next_power_of_two();
    // Per bucket: 1 byte control metadata
    // Per occupied entry: Vec heap (32) + Vec stack-in-bucket (24 + 8 = 32 for key+value pair)
    // Actual layout: control bytes (capacity) + entries * size_of::<(Vec<u8>, u64)>()
    let control_bytes = capacity;
    let entry_size = size_of::<(Vec<u8>, u64)>(); // 32 bytes typically
    let bucket_array = control_bytes + capacity * entry_size;
    let vec_heap_allocs = entries * 32; // each Vec<u8> has 32 bytes on heap
    bucket_array + vec_heap_allocs
}

fn measure_dlt_size(ballots: usize) -> DltSize {
    let rss_before = get_rss_kb();
    let table = DiscreteLogTable::<Ristretto>::new(0..=(ballots as u64));
    let rss_after = get_rss_kb();
    let entries = ballots; // 0 is handled specially, so entries = ballots (1..=ballots)
    let estimated = estimate_dlt_heap_bytes(entries);
    drop(table);
    DltSize {
        estimated_heap_bytes: estimated,
        rss_delta_kb: rss_after as i64 - rss_before as i64,
    }
}

struct RunResult {
    decryption: PhaseMeasurement,
    correct: bool,
}

fn run_benchmark(setup: &CachedSetup, ballots: usize) -> RunResult {
    let (tallies, decryption) =
        measure(|| decrypt_result(&setup.sk, &setup.acc, ballots as u64).expect("decrypt failed"));

    let correct = tallies
        .iter()
        .zip(setup.expected.iter())
        .all(|(a, b)| *a == *b);

    RunResult {
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

// --- Temp dump helpers ---

fn dump_set_to_temp(
    tmp_path: &str,
    ballots: usize,
    candidates: usize,
    runs: usize,
    results: &[RunResult],
    dlt_size: &DltSize,
) {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(tmp_path)
        .expect("failed to open temp file");

    let measurements: Vec<&PhaseMeasurement> = results.iter().map(|r| &r.decryption).collect();
    let walls: Vec<f64> = measurements.iter().map(|m| m.wall_secs).collect();
    let cpus: Vec<f64> = measurements.iter().map(|m| m.cpu_user_secs).collect();
    let rsss: Vec<f64> = measurements.iter().map(|m| m.rss_delta_kb as f64).collect();

    let line = format!(
        "{},{},{},{},{:.6},{:.6},{:.6},{:.6},{:.1},{:.1},{},{}",
        ballots,
        candidates,
        "decryption",
        runs,
        mean(&walls),
        stddev(&walls),
        mean(&cpus),
        stddev(&cpus),
        mean(&rsss),
        stddev(&rsss),
        dlt_size.estimated_heap_bytes,
        dlt_size.rss_delta_kb,
    );
    println!("  {}", line);
    writeln!(file, "{}", line).expect("failed to write row");
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
        "ballots,candidates,phase,runs,mean_wall_s,stddev_wall_s,mean_cpu_user_s,stddev_cpu_user_s,mean_rss_delta_kb,stddev_rss_delta_kb,dlt_estimated_heap_bytes,dlt_rss_delta_kb"
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

    for &ballots in &config.ballots {
        for &candidates in &config.candidates {
            println!(
                "\n=== ballots={} candidates={} ({} runs) ===",
                ballots, candidates, config.runs
            );

            // Measure DiscreteLogTable size
            println!(
                "  measuring DiscreteLogTable size (entries: {})...",
                ballots + 1
            );
            let dlt_size = measure_dlt_size(ballots);
            println!(
                "    estimated_heap: {} bytes, rss_delta: {} kB",
                dlt_size.estimated_heap_bytes, dlt_size.rss_delta_kb
            );

            if config.dlt_only {
                continue;
            }

            // Cache encryption + addition once per configuration
            println!("  building cached setup (encrypt + accumulate)...");
            let setup = build_cached_setup(ballots, candidates, config.seed);

            let mut results: Vec<RunResult> = Vec::with_capacity(config.runs);
            for run in 0..config.runs {
                println!("  run {}/{}", run + 1, config.runs);
                let r = run_benchmark(&setup, ballots);
                if !r.correct {
                    eprintln!("  WARNING: tally mismatch on run {}", run + 1);
                }
                results.push(r);
            }

            dump_set_to_temp(
                &tmp_path,
                ballots,
                candidates,
                config.runs,
                &results,
                &dlt_size,
            );
            drop(results);
            drop(setup);
        }
    }

    if !config.dlt_only {
        aggregate_temp_to_output(&tmp_path, &config.output);
        println!("\nResults written to {}", config.output);
    }
}
