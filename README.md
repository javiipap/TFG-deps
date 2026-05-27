# e3vote — Cryptographic Libraries

Rust workspace containing the cryptographic primitives and compiled bindings used by the e3vote voting system.

## Crates

| Crate | Output | Description |
|-------|--------|-------------|
| `primitives` | Library | Core cryptographic operations: ElGamal encryption, blind RSA signatures, ECC, secret sharing, BFV homomorphic encryption |
| `client_lib` | WASM (wasm-pack) | Client-side bindings for ballot creation and blind signature protocols |
| `server_lib` | Node.js native addon (napi-rs) | Server-side bindings for tally, signature verification, and key management |

## Prerequisites

- Rust (stable, edition 2024)
- `wasm-pack` — for building client WASM
- `yarn` (Node.js + npm) — for server_lib napi build
- For musl builds: `musl-dev`, `gcc`, `make`, `openssl-dev`

## Build

```bash
./build.sh <target> [output_dir]
```

- `target`: `glib` (GNU libc) or `musl` (Alpine/static)
- `output_dir`: defaults to `../web/src/lib/pkg`

Examples:
```bash
# Development (GNU libc)
./build.sh glib

# Docker/Alpine build
./build.sh musl /pkg
```

The script compiles both `client_lib` (WASM) and `server_lib` (native .node addon) and places the output in the specified directory.

## Testing

```bash
# Run all tests
cd primitives && cargo test
cd client_lib && cargo test
cd server_lib && cargo test
```

## Benchmarks

The `primitives` crate includes several benchmark binaries:

```bash
cd primitives
cargo run --release --bin benchmark_unit
cargo run --release --bin benchmark_full-scale
cargo run --release --bin benchmark_tally
cargo run --release --bin benchmark_bfv
cargo run --release --bin benchmark_vote-size
```

Results are written to CSV files (gitignored).

## Architecture

```
primitives/         Core crypto library (ElGamal, blind RSA, ECC, Shamir secret sharing, BFV)
├── src/
│   ├── lib.rs
│   ├── ballots.rs          Ballot encryption/decryption
│   ├── blind_signatures.rs Blind RSA signature scheme
│   ├── ecc.rs              Elliptic curve operations
│   ├── secret_sharing.rs   Shamir secret sharing
│   └── signatures.rs       Standard signatures
├── tests/
└── src/bin/                Benchmark binaries

client_lib/         WASM bindings (browser)
├── src/
└── tests/

server_lib/         Node.js native addon (napi-rs)
├── src/
├── tests/
└── index.d.ts      TypeScript type definitions
```

## Author

Javier Padilla Pío — [jpadillp@ull.edu.es](mailto:jpadillp@ull.edu.es)
