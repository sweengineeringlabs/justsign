# justsign fuzz harness

cargo-fuzz targets that feed arbitrary `&[u8]` data into each
public wire-decode parser in justsign and assert no panic. The
contract under test is "decoders surface a typed error for any
input" — implementations must never `unwrap`, never index out of
bounds, never overflow.

These parsers consume bytes from untrusted sources (Sigstore
bundles pulled from a registry, DSSE envelopes received over a
network, TUF metadata fetched from a mirror, PEM cert chains
returned by Fulcio, Rekor responses). A panic on any of them is a
denial-of-service against verifiers; a logic bug is potentially
worse. This harness is the proving ground.

## Layout

```
fuzz/
├── Cargo.toml                           # sub-project — NOT a member of the
│                                        # parent workspace; lives in its own
│                                        # cargo invocation per cargo-fuzz convention
├── fuzz_targets/
│   ├── envelope_decode_json.rs          # spec::Envelope::decode_json (DSSE)
│   ├── bundle_decode_json.rs            # spec::Bundle::decode_json (Sigstore Bundle v0.3)
│   ├── statement_decode_json.rs         # spec::Statement::decode_json (in-toto)
│   ├── tuf_canonicalize.rs              # tuf::canonicalize (after serde_json::from_slice)
│   ├── tuf_parse_with_signed_span.rs    # tuf::parse_with_signed_span::<Root>
│   ├── fulcio_parse_chain.rs            # fulcio::chain::parse_chain (PEM cert chain)
│   ├── rekor_decode_log_entry_bytes.rs  # rekor::decode_log_entry_bytes
│   └── oci_parse_referrer_manifest.rs   # sign::oci::parse_referrer_manifest
├── corpus/                              # seed inputs (committed) +
│                                        # libFuzzer-grown corpora (NOT committed)
└── README.md                            # this file
```

The `fuzz/` directory is **not** a member of the root workspace —
it has its own `Cargo.toml` and is built independently. This is the
cargo-fuzz convention: it keeps the `libfuzzer-sys` dependency and
the nightly-only build flags off the main crate graph. The root
`Cargo.toml` lists it under `exclude = ["fuzz"]` so that
`cargo build --workspace` skips it.

## Prerequisites

- Nightly Rust toolchain — `rustup toolchain install nightly`
- cargo-fuzz — `cargo install cargo-fuzz`

cargo-fuzz drives libFuzzer, which is shipped with rustc nightly.

## Running

Requires nightly Rust + cargo-fuzz. Run `cargo install cargo-fuzz`
then `cargo +nightly fuzz run <target>` from this directory. Each
target runs until you Ctrl-C or until `-max_total_time=N` (seconds)
elapses.

```bash
cd fuzz
cargo +nightly fuzz run envelope_decode_json
cargo +nightly fuzz run bundle_decode_json
cargo +nightly fuzz run statement_decode_json
cargo +nightly fuzz run tuf_canonicalize
cargo +nightly fuzz run tuf_parse_with_signed_span
cargo +nightly fuzz run fulcio_parse_chain
cargo +nightly fuzz run rekor_decode_log_entry_bytes
cargo +nightly fuzz run oci_parse_referrer_manifest
```

For a bounded run (CI uses 5 minutes / 300 seconds per target):

```bash
cargo +nightly fuzz run envelope_decode_json -- -max_total_time=300
```

## Triage

When libFuzzer finds a crashing input it writes the bytes to
`fuzz/artifacts/<target>/crash-<sha>` and prints the path.
Reproduce with:

```bash
cargo +nightly fuzz run envelope_decode_json fuzz/artifacts/envelope_decode_json/crash-<sha>
```

Minimise the crashing input down to the smallest reproducer:

```bash
cargo +nightly fuzz tmin envelope_decode_json fuzz/artifacts/envelope_decode_json/crash-<sha>
```

## Corpora

`fuzz/corpus/<target>/` holds two kinds of files:

1. **Hand-curated seed inputs** (committed). A few representative
   shapes per target — well-formed inputs, known-bad inputs, edge
   cases. They cover the happy-path shape so libFuzzer doesn't
   have to reinvent it from random bytes; seeded fuzzing finds
   bugs roughly 10x faster than purely random fuzzing.
2. **libFuzzer-grown corpora** (NOT committed). Generated on every
   run and balloon over time. The `.gitignore` ignores the entire
   `corpus/` tree by default; seeds are added with `git add -f`.

To wipe the local grown corpus and start over from seeds only:

```bash
rm -rf fuzz/corpus/<target>/*
git checkout fuzz/corpus/<target>/
```

## CI

A GitHub Actions workflow at `.github/workflows/fuzz.yml` runs the
8 targets in parallel for 5 minutes each on `workflow_dispatch`.
We don't run fuzzing on every push — 8 × 5 min × every-PR is too
much CI cost for the marginal coverage gain — but it is one click
away from the Actions tab.

## Smoke build (no fuzzer)

To verify the harness compiles without running the fuzzer (e.g. to
catch a wiring break in CI on a stable toolchain):

```bash
cargo build --manifest-path fuzz/Cargo.toml
```

Note: stable cannot link the `#[no_main]` binaries because
libfuzzer-sys requires nightly's libfuzzer instrumentation. The
build fails at link time on stable; the *check* step (typecheck)
still runs and surfaces API drift.

```bash
cargo +nightly fuzz build
```

is the canonical way to confirm all 8 binaries link end-to-end.
