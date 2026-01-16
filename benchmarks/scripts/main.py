import os
import sys
import json
import csv
import pandas as pd

# {
#   "group_id": "decrypt_ballot_5_100_BFV",
#   "function_id": null,
#   "value_str": null,
#   "throughput": null,
#   "full_id": "decrypt_ballot_5_100_BFV",
#   "directory_name": "decrypt_ballot_5_100_BFV",
#   "title": "decrypt_ballot_5_100_BFV"
# }

# --- sample.json
# {
#   "iters": [],
#   "times": []
# }


def main(base: str, output_file: str):
    data = []

    algorithms = ['BFV', 'ElGamal']

    raw_data = []

    for alg in algorithms:
        path = f'{base}decrypt_ballots/{alg}'
        for file in os.listdir(path):
            if os.path.isfile(f'{path}/{file}/new/sample.json'):
                num_voters, num_candidates = file.split(' ')
                sample = {}
                with open(f'{path}/{file}/new/sample.json') as fp:
                    sample = json.load(fp)

                for i, tm in enumerate(sample['times']):
                    for _ in range(int(sample['iters'][i])):
                        raw_data.append([alg, int(num_candidates), int(
                            num_voters), tm/sample['iters'][i]])

    df = pd.DataFrame(raw_data, columns=[
                      'Algorithm', 'NumCandidates', 'NumVoters', 'Time'])

    df.to_csv(output_file)


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(f'Usage: {sys.argv[0]} <base_dir> <output_file>')
        print('       Se espera la base del directorio con los benchmarks y el archivo de salida.')
        exit(1)
    main(*sys.argv[1:])
