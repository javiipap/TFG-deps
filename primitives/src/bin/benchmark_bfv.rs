use cupcake::traits::{AdditiveHomomorphicScheme, KeyGeneration, PKEncryption, SKEncryption, Serializable};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::time::Instant;

// --- Config ---

struct Config {
    runs: usize,
    output: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            runs: 100,
            output: "benchmark_bfv__results.csv".into(),
        }
    }
}

fn parse_args() -> Config {
    let args: Vec<String> = std::env::args().collect();
    let mut config = Config::default();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--runs" => {
                i += 1;
                config.runs = args[i].parse().expect("invalid runs");
            }
            "--output" => {
                i += 1;
                config.output = args[i].clone();
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

// --- Statistics ---

fn mean(values: &[f64]) -> f64 {
    values.iter().sum::<f64>() / values.len() as f64
}

fn stddev(values: &[f64]) -> f64 {
    let m = mean(values);
    (values.iter().map(|v| (v - m).powi(2)).sum::<f64>() / values.len() as f64).sqrt()
}

// --- Benchmark ---

struct RunResult {
    encryption: PhaseMeasurement,
    decryption: PhaseMeasurement,
    addition: PhaseMeasurement,
    ciphertext_bytes: usize,
}

fn run_benchmark(scheme: &cupcake::DefaultShemeType) -> RunResult {
    let (pk, sk) = scheme.generate_keypair();
    let plaintext = vec![1u8; scheme.n];

    let (ct, encryption) = measure(|| scheme.encrypt(&plaintext, &pk));

    let ciphertext_bytes = ct.to_bytes().len();

    let (_, decryption) = measure(|| {
        let _: Vec<u8> = scheme.decrypt(&ct, &sk);
    });

    let ct2 = scheme.encrypt(&plaintext, &pk);
    let (_, addition) = measure(|| {
        let mut acc = ct.clone();
        scheme.add_inplace(&mut acc, &ct2);
    });

    RunResult {
        encryption,
        decryption,
        addition,
        ciphertext_bytes,
    }
}

// --- Main ---

fn main() {
    let config = parse_args();
    let scheme = cupcake::default();

    println!("=== BFV Benchmark (n={}, {} runs) ===", scheme.n, config.runs);

    let mut results: Vec<RunResult> = Vec::with_capacity(config.runs);
    for run in 0..config.runs {
        println!("  run {}/{}", run + 1, config.runs);
        results.push(run_benchmark(&scheme));
    }

    // Write results
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&config.output)
        .expect("failed to open output file");

    writeln!(
        file,
        "phase,runs,mean_wall_s,stddev_wall_s,mean_cpu_user_s,stddev_cpu_user_s,mean_rss_delta_kb,stddev_rss_delta_kb"
    )
    .unwrap();

    let phases: Vec<(&str, Vec<&PhaseMeasurement>)> = vec![
        ("encryption", results.iter().map(|r| &r.encryption).collect()),
        ("decryption", results.iter().map(|r| &r.decryption).collect()),
        ("addition", results.iter().map(|r| &r.addition).collect()),
    ];

    for (phase, measurements) in &phases {
        let walls: Vec<f64> = measurements.iter().map(|m| m.wall_secs).collect();
        let cpus: Vec<f64> = measurements.iter().map(|m| m.cpu_user_secs).collect();
        let rsss: Vec<f64> = measurements.iter().map(|m| m.rss_delta_kb as f64).collect();

        let line = format!(
            "{},{},{:.6},{:.6},{:.6},{:.6},{:.1},{:.1}",
            phase,
            config.runs,
            mean(&walls),
            stddev(&walls),
            mean(&cpus),
            stddev(&cpus),
            mean(&rsss),
            stddev(&rsss),
        );
        println!("  {}", line);
        writeln!(file, "{}", line).unwrap();
    }

    writeln!(file, "\nciphertext_bytes,{}", results[0].ciphertext_bytes).unwrap();

    println!("\nResults written to {}", config.output);
    println!("Ciphertext size: {} bytes", results[0].ciphertext_bytes);
}
