mod common;

use std::ops::Add;

use benchmarks::{
    ballot::Ballot,
    bfv::{self, BfvBallot},
    elgamal::{self, ElGamalBallot},
};

use common::generate_sample;
use criterion::{black_box, measurement::WallTime, BenchmarkGroup, BenchmarkId, Criterion};

fn bench_function<PK, SK, BallotType>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    num_candidates: usize,
    num_ballots: usize,
    alg: &str,
) where
    BallotType: Ballot<PK, SK> + Clone + Add<Output = BallotType>,
{
    group.bench_with_input(
        BenchmarkId::new(alg, format!("{:06} {:02}", num_ballots, num_candidates)),
        &(num_ballots, num_candidates),
        |b, (num_ballots, num_candidates)| {
            let (sample, _, secret_key) =
                generate_sample::<PK, SK, BallotType>(*num_ballots, *num_candidates);
            let sum = sample
                .iter()
                .cloned()
                .reduce(|acc, ballot| (acc + ballot))
                .unwrap();

            b.iter(|| {
                let result = sum.decrypt(&secret_key, Some(*num_ballots)).unwrap();
                black_box(result);
            })
        },
    );
}

generate_benchmark_main!(
    bench_function,
    "decrypt_ballots",
    vec![20],
    vec![100, 500, 1000, 2000, 5000, 10000, 100000]
);
