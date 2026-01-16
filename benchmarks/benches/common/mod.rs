use benchmarks::ballot::Ballot;
use rand::Rng;

pub fn generate_sample<PK, SK, BallotVariant>(
    num_ballots: usize,
    num_candidates: usize,
) -> (Vec<BallotVariant>, PK, SK)
where
    BallotVariant: Ballot<PK, SK>,
{
    let (public_key, secret_key) = BallotVariant::generate_kepair();

    let mut rng = rand::thread_rng();

    let ballots: Vec<BallotVariant> = (0..num_ballots)
        .map(|_| {
            BallotVariant::new(
                rng.gen_range(1..=(num_candidates - 1)),
                num_candidates,
                &public_key,
            )
        })
        .collect();

    (ballots, public_key, secret_key)
}

#[macro_export]
macro_rules! generate_benchmark_main {
    ($func:ident, $arg:expr, $num_candidates_values:expr, $num_ballots_values:expr) => {
        fn main() {
            let mut criterion = Criterion::default().configure_from_args().sample_size(10);

            let num_candidates_values: Vec<_> = $num_candidates_values;
            let num_ballots_values: Vec<_> = $num_ballots_values;

            let combinations: Vec<_> = num_candidates_values
                .iter()
                .flat_map(|&num_candidates| {
                    num_ballots_values
                        .iter()
                        .map(move |&num_ballots| (num_candidates, num_ballots))
                })
                .collect();

            let mut sum_ballots_group = criterion.benchmark_group($arg);

            for (num_candidates, num_ballots) in combinations {
                bench_function::<bfv::PublicKey, bfv::SecretKey, BfvBallot>(
                    &mut sum_ballots_group,
                    num_candidates,
                    num_ballots,
                    "BFV",
                );
                bench_function::<elgamal::PublicKey, elgamal::SecretKey, ElGamalBallot>(
                    &mut sum_ballots_group,
                    num_candidates,
                    num_ballots,
                    "ElGamal",
                );
            }

            sum_ballots_group.finish();
            criterion.final_summary();
        }
    };
}
