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
        BenchmarkId::new(alg, format!("{:04} {:02}", num_ballots, num_candidates)),
        &(num_ballots, num_candidates),
        |b, (num_ballots, num_candidates)| {
            let (sample, _, _) =
                generate_sample::<PK, SK, BallotType>(*num_ballots, *num_candidates);

            b.iter(|| {
                let sum = sample
                    .iter()
                    .cloned()
                    .reduce(|acc, ballot| (acc + ballot))
                    .unwrap();
                black_box(sum);
            })
        },
    );
}

// generate_benchmark_main!(bench_function, "sum_ballots", vec![5, 10, 20], vec![1000]);

fn main() {}
