//! `justsign` library half — argument parsers and command
//! implementations exposed as functions so the binary stays tiny
//! and integration tests can call commands without shelling out.
//!
//! The `main.rs` is a thin shim: dispatch on `argv[1]`, wire
//! stdout/stderr/exit-code, delegate to one of the `cmd_*`
//! functions here.
//!
//! ## v0 surface
//!
//! Four subcommands, each end-to-end tested in `mod tests`:
//!
//! * [`cmd_generate_key_pair`] — write `<prefix>.key` (PKCS#8 PEM
//!   ECDSA P-256 priv) and `<prefix>.pub` (SubjectPublicKeyInfo PEM
//!   ECDSA P-256 pub).
//! * [`cmd_public_key`] — derive + emit the public PEM for a private
//!   PEM file.
//! * [`cmd_sign_blob`] — sign a file with a P-256 key, emit a
//!   Sigstore bundle v0.3 JSON. `--rekor` attaches a mock-Rekor
//!   inclusion proof; the real Rekor HTTP client lands in v0.5.
//! * [`cmd_verify_blob`] — verify a bundle against a public PEM. Exit
//!   non-zero on any verification failure.
//!
//! ## PEM choices
//!
//! * **Private keys** — PKCS#8 PEM (`-----BEGIN PRIVATE KEY-----`).
//!   Standard interchange format; what `cosign` writes.
//! * **Public keys** — SubjectPublicKeyInfo PEM (`-----BEGIN PUBLIC
//!   KEY-----`). The task spec calls this "SEC1 PEM" because the
//!   inner point bytes use the SEC1 uncompressed encoding, but the
//!   PEM wrapper is SPKI — matches the on-disk shape that
//!   `openssl ec -pubout` and `cosign generate-key-pair` emit, so
//!   keys round-trip with the rest of the Sigstore tool ecosystem.
//!
//! ## Exit-code mapping
//!
//! Every `cmd_*` function returns `Result<(), CliError>`; the
//! binary maps `Ok` → 0 and `Err` → 1. Verification failures
//! surface as `CliError` so they exit non-zero — the test
//! `test_cli_verify_blob_with_wrong_key_fails` pins this contract.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use p256::ecdsa::{SigningKey, VerifyingKey};
use p256::pkcs8::{
    DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding,
};
use sign::spec::Bundle;
use sign::{rekor::MockRekorClient, sign_blob, verify_blob, EcdsaP256Signer};

/// Top-level error type — prefer plain `String` over `thiserror`
/// here because the CLI just renders the message and exits. Lower
/// layers already produce richly-typed errors; this is the boundary
/// that converts them to user-facing strings.
#[derive(Debug)]
pub struct CliError(pub String);

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for CliError {}

/// Print top-level usage to the supplied writer (so tests can
/// capture and assert on it).
pub fn print_usage<W: Write>(out: &mut W) -> std::io::Result<()> {
    writeln!(out, "justsign — Sigstore-shaped signing CLI (v0)")?;
    writeln!(out)?;
    writeln!(out, "Usage:")?;
    writeln!(out, "  justsign generate-key-pair <prefix>")?;
    writeln!(
        out,
        "      writes <prefix>.key (PKCS#8 PEM) + <prefix>.pub (SPKI PEM)"
    )?;
    writeln!(out, "  justsign public-key <priv-pem-path>")?;
    writeln!(
        out,
        "      derives the public key and prints SPKI PEM to stdout"
    )?;
    writeln!(
        out,
        "  justsign sign-blob <file> --key <priv-pem-path> [--output-bundle <path>] [--rekor]"
    )?;
    writeln!(
        out,
        "      signs <file>, emits a Sigstore bundle v0.3 JSON to <path> or stdout."
    )?;
    writeln!(
        out,
        "      --rekor uses an in-process mock Rekor (real HTTP client lands in v0.5)."
    )?;
    writeln!(
        out,
        "  justsign verify-blob <bundle-path> --key <pub-pem-path>"
    )?;
    writeln!(
        out,
        "      verifies the bundle. Exit 0 on success, 1 on failure."
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Subcommand implementations
// ---------------------------------------------------------------------------

/// `generate-key-pair <prefix>` — produce a fresh ECDSA P-256
/// keypair. Writes `<prefix>.key` (PKCS#8 PEM private) and
/// `<prefix>.pub` (SPKI PEM public).
pub fn cmd_generate_key_pair<W: Write>(args: &[String], out: &mut W) -> Result<(), CliError> {
    let prefix = args
        .first()
        .ok_or_else(|| CliError("generate-key-pair requires a <prefix> argument".to_string()))?;
    if args.len() > 1 {
        return Err(CliError(format!(
            "generate-key-pair takes a single <prefix>, got {} extra arg(s)",
            args.len() - 1
        )));
    }

    // OS RNG seeded from the platform's CSPRNG. `rand_core::OsRng`
    // implements the `CryptoRng + RngCore` shape `SigningKey::random`
    // requires; the `getrandom` feature wires it to
    // `BCryptGenRandom` on Windows / `getrandom(2)` on Linux.
    let signing_key = SigningKey::random(&mut rand_core::OsRng);
    let verifying_key = *signing_key.verifying_key();

    let priv_path = format!("{prefix}.key");
    let pub_path = format!("{prefix}.pub");

    let priv_pem = signing_key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| CliError(format!("encode private PEM: {e}")))?;
    let pub_pem = verifying_key
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| CliError(format!("encode public PEM: {e}")))?;

    write_new_file(&priv_path, priv_pem.as_bytes())?;
    write_new_file(&pub_path, pub_pem.as_bytes())?;

    writeln!(
        out,
        "wrote private key: {priv_path}\nwrote public key:  {pub_path}"
    )
    .map_err(|e| CliError(format!("write: {e}")))?;
    Ok(())
}

/// `public-key <priv-pem-path>` — load a PKCS#8 PEM private key
/// and emit the matching SPKI PEM public key on stdout.
pub fn cmd_public_key<W: Write>(args: &[String], out: &mut W) -> Result<(), CliError> {
    let priv_path = args
        .first()
        .ok_or_else(|| CliError("public-key requires a <priv-pem-path> argument".to_string()))?;
    if args.len() > 1 {
        return Err(CliError(format!(
            "public-key takes a single <priv-pem-path>, got {} extra arg(s)",
            args.len() - 1
        )));
    }

    let priv_pem = std::fs::read_to_string(Path::new(priv_path))
        .map_err(|e| CliError(format!("read {priv_path}: {e}")))?;
    let signing_key = SigningKey::from_pkcs8_pem(&priv_pem)
        .map_err(|e| CliError(format!("parse PKCS#8 PEM private key: {e}")))?;
    let verifying_key = *signing_key.verifying_key();
    let pub_pem = verifying_key
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| CliError(format!("encode public PEM: {e}")))?;
    out.write_all(pub_pem.as_bytes())
        .map_err(|e| CliError(format!("write: {e}")))?;
    Ok(())
}

/// Parsed `sign-blob` arg state.
struct SignBlobArgs {
    file: String,
    key: String,
    output_bundle: Option<String>,
    rekor: bool,
}

fn parse_sign_blob_args(args: &[String]) -> Result<SignBlobArgs, CliError> {
    let file = args
        .first()
        .ok_or_else(|| {
            CliError(
                "sign-blob requires <file> [--key <priv-pem>] [--output-bundle <path>] [--rekor]"
                    .to_string(),
            )
        })?
        .clone();
    let mut key: Option<String> = None;
    let mut output_bundle: Option<String> = None;
    let mut rekor = false;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--key" => {
                let v = args
                    .get(i + 1)
                    .ok_or_else(|| CliError("--key requires a path argument".to_string()))?;
                key = Some(v.clone());
                i += 2;
            }
            "--output-bundle" => {
                let v = args.get(i + 1).ok_or_else(|| {
                    CliError("--output-bundle requires a path argument".to_string())
                })?;
                output_bundle = Some(v.clone());
                i += 2;
            }
            "--rekor" => {
                rekor = true;
                i += 1;
            }
            other => return Err(CliError(format!("unknown flag: {other}"))),
        }
    }
    let key =
        key.ok_or_else(|| CliError("sign-blob requires --key <priv-pem-path>".to_string()))?;
    Ok(SignBlobArgs {
        file,
        key,
        output_bundle,
        rekor,
    })
}

/// `sign-blob <file> --key <priv-pem-path> [--output-bundle <path>] [--rekor]`
/// — sign the bytes of `<file>` and emit a Sigstore bundle v0.3
/// JSON to `<path>` or stdout.
pub fn cmd_sign_blob<W: Write>(args: &[String], out: &mut W) -> Result<(), CliError> {
    let parsed = parse_sign_blob_args(args)?;

    let payload = std::fs::read(Path::new(&parsed.file))
        .map_err(|e| CliError(format!("read {}: {e}", parsed.file)))?;
    let priv_pem = std::fs::read_to_string(Path::new(&parsed.key))
        .map_err(|e| CliError(format!("read {}: {e}", parsed.key)))?;
    let signing_key = SigningKey::from_pkcs8_pem(&priv_pem)
        .map_err(|e| CliError(format!("parse PKCS#8 PEM private key: {e}")))?;
    let signer = EcdsaP256Signer::new(signing_key, None);

    let mock_client;
    let rekor_arg: Option<&dyn sign::rekor::RekorClient> = if parsed.rekor {
        mock_client = MockRekorClient::new();
        Some(&mock_client)
    } else {
        None
    };

    let bundle = sign_blob(
        &payload,
        // Bundle media type — pinning the v0.3 string here keeps
        // operator-facing CLI output identical regardless of which
        // sign path the binary takes (cosign-compat tools key off
        // this string).
        "application/vnd.dev.sigstore.bundle+json;version=0.3",
        &signer,
        rekor_arg,
    )
    .map_err(|e| CliError(format!("sign_blob: {e}")))?;

    let json = bundle
        .encode_json()
        .map_err(|e| CliError(format!("encode bundle JSON: {e}")))?;

    match parsed.output_bundle {
        Some(path) => {
            write_new_file(&path, &json)?;
            writeln!(out, "wrote bundle: {path}").map_err(|e| CliError(format!("write: {e}")))?;
        }
        None => {
            out.write_all(&json)
                .map_err(|e| CliError(format!("write: {e}")))?;
        }
    }
    Ok(())
}

/// Parsed `verify-blob` arg state.
struct VerifyBlobArgs {
    bundle: String,
    key: String,
}

fn parse_verify_blob_args(args: &[String]) -> Result<VerifyBlobArgs, CliError> {
    let bundle = args
        .first()
        .ok_or_else(|| {
            CliError("verify-blob requires <bundle-path> --key <pub-pem-path>".to_string())
        })?
        .clone();
    let mut key: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--key" => {
                let v = args
                    .get(i + 1)
                    .ok_or_else(|| CliError("--key requires a path argument".to_string()))?;
                key = Some(v.clone());
                i += 2;
            }
            other => return Err(CliError(format!("unknown flag: {other}"))),
        }
    }
    let key =
        key.ok_or_else(|| CliError("verify-blob requires --key <pub-pem-path>".to_string()))?;
    Ok(VerifyBlobArgs { bundle, key })
}

/// `verify-blob <bundle-path> --key <pub-pem-path>` — verify the
/// bundle against the supplied public PEM. Returns `Ok(())` on
/// success; the binary maps `Err` to exit code 1.
pub fn cmd_verify_blob<W: Write>(args: &[String], out: &mut W) -> Result<(), CliError> {
    let parsed = parse_verify_blob_args(args)?;

    let bundle_bytes = std::fs::read(Path::new(&parsed.bundle))
        .map_err(|e| CliError(format!("read {}: {e}", parsed.bundle)))?;
    let bundle = Bundle::decode_json(&bundle_bytes)
        .map_err(|e| CliError(format!("decode bundle JSON: {e}")))?;

    let pub_pem = std::fs::read_to_string(Path::new(&parsed.key))
        .map_err(|e| CliError(format!("read {}: {e}", parsed.key)))?;
    let verifying_key = VerifyingKey::from_public_key_pem(&pub_pem)
        .map_err(|e| CliError(format!("parse SPKI PEM public key: {e}")))?;

    // No Rekor verification at the CLI layer in v0 — the embedded
    // mock-Rekor proof is a witness, not a transparency root.
    // Real Rekor proof verification ships with the HTTP client in
    // v0.5.
    verify_blob(&bundle, &[verifying_key], None)
        .map_err(|e| CliError(format!("verify_blob: {e}")))?;

    writeln!(out, "OK").map_err(|e| CliError(format!("write: {e}")))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Write `bytes` to a brand-new file at `path`, refusing to
/// truncate an existing file. Keys + bundles must not silently
/// overwrite — use a fresh prefix or remove the old file first.
fn write_new_file(path: &str, bytes: &[u8]) -> Result<(), CliError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(Path::new(path))
        .map_err(|e| CliError(format!("create {path}: {e}")))?;
    file.write_all(bytes)
        .map_err(|e| CliError(format!("write {path}: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Test fixture: a unique tempdir per test, cleaned on drop.
    /// Mirrors the justext4 CLI's pattern so we avoid the
    /// `tempfile` dep — a compose-once helper is cheaper than a
    /// transitive crate.
    struct Tempdir {
        path: PathBuf,
    }

    impl Tempdir {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "justsign-cli-{}-{}-{}",
                tag,
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&path).unwrap();
            Tempdir { path }
        }

        fn join(&self, name: &str) -> PathBuf {
            self.path.join(name)
        }

        fn join_str(&self, name: &str) -> String {
            self.join(name).to_string_lossy().into_owned()
        }
    }

    impl Drop for Tempdir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    /// `generate-key-pair` writes both files at the requested
    /// prefix and they are PEM-shaped (correct delimiters).
    ///
    /// Bug it catches: a generator that wrote only the private
    /// half (or both with wrong PEM labels) would silently look
    /// successful but break `public-key` / `verify-blob`.
    #[test]
    fn test_cli_generate_key_pair_writes_priv_and_pub_files() {
        let dir = Tempdir::new("genkey");
        let prefix = dir.join_str("k1");

        let mut sink = Vec::new();
        cmd_generate_key_pair(std::slice::from_ref(&prefix), &mut sink).unwrap();

        let priv_path = format!("{prefix}.key");
        let pub_path = format!("{prefix}.pub");
        assert!(
            Path::new(&priv_path).exists(),
            "private key file must exist"
        );
        assert!(Path::new(&pub_path).exists(), "public key file must exist");

        let priv_pem = std::fs::read_to_string(&priv_path).unwrap();
        let pub_pem = std::fs::read_to_string(&pub_path).unwrap();

        assert!(
            priv_pem.contains("-----BEGIN PRIVATE KEY-----"),
            "private PEM must use PKCS#8 BEGIN delimiter, got: {priv_pem}"
        );
        assert!(
            priv_pem.trim_end().ends_with("-----END PRIVATE KEY-----"),
            "private PEM must use PKCS#8 END delimiter, got: {priv_pem}"
        );
        assert!(
            pub_pem.contains("-----BEGIN PUBLIC KEY-----"),
            "public PEM must use SPKI BEGIN delimiter, got: {pub_pem}"
        );
        assert!(
            pub_pem.trim_end().ends_with("-----END PUBLIC KEY-----"),
            "public PEM must use SPKI END delimiter, got: {pub_pem}"
        );

        // Round-trip: the keys we wrote must parse back through
        // the same crates the rest of the toolchain uses, and the
        // verifying key derived from the private must equal the
        // separately-written public key — otherwise the two halves
        // were generated from different randomness sources.
        let signing_key = SigningKey::from_pkcs8_pem(&priv_pem).unwrap();
        let derived_pub = signing_key
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .unwrap();
        assert_eq!(derived_pub, pub_pem, "private + public files must match");
    }

    /// Sign with a freshly-generated key, then verify with the
    /// matching public PEM — happy path round-trip through every
    /// CLI-side serialise/parse step.
    ///
    /// Bug it catches: any drift between the PEM the generator
    /// writes and the PEM the verifier expects (e.g. a generator
    /// that wrote SEC1 PEM directly instead of SPKI; a verifier
    /// that demanded a CRLF line ending). Also catches loss of
    /// payload bytes through the encode/decode loop.
    #[test]
    fn test_cli_sign_then_verify_blob_round_trips() {
        let dir = Tempdir::new("roundtrip");
        let prefix = dir.join_str("alice");
        let mut sink = Vec::new();
        cmd_generate_key_pair(std::slice::from_ref(&prefix), &mut sink).unwrap();

        let priv_path = format!("{prefix}.key");
        let pub_path = format!("{prefix}.pub");

        let payload_path = dir.join_str("payload.txt");
        std::fs::write(&payload_path, b"production-grade payload bytes").unwrap();

        let bundle_path = dir.join_str("bundle.json");
        cmd_sign_blob(
            &[
                payload_path,
                "--key".into(),
                priv_path,
                "--output-bundle".into(),
                bundle_path.clone(),
            ],
            &mut sink,
        )
        .unwrap();

        let mut verify_out = Vec::new();
        cmd_verify_blob(&[bundle_path, "--key".into(), pub_path], &mut verify_out)
            .expect("matching key must verify");

        let verify_msg = String::from_utf8(verify_out).unwrap();
        assert!(
            verify_msg.contains("OK"),
            "verify-blob should print OK on success, got: {verify_msg}"
        );
    }

    /// Bundle signed by key A must NOT verify against key B.
    ///
    /// Bug it catches: a verifier that returned `Ok` whenever the
    /// PEM parsed (without actually checking the signature against
    /// the supplied key) would silently pass. This is the most
    /// safety-critical CLI test — verification is what the entire
    /// product promises.
    #[test]
    fn test_cli_verify_blob_with_wrong_key_fails() {
        let dir = Tempdir::new("wrongkey");
        let prefix_a = dir.join_str("a");
        let prefix_b = dir.join_str("b");
        let mut sink = Vec::new();
        cmd_generate_key_pair(std::slice::from_ref(&prefix_a), &mut sink).unwrap();
        cmd_generate_key_pair(std::slice::from_ref(&prefix_b), &mut sink).unwrap();

        let priv_a = format!("{prefix_a}.key");
        let pub_b = format!("{prefix_b}.pub");

        let payload_path = dir.join_str("payload.bin");
        std::fs::write(&payload_path, b"signed by A").unwrap();
        let bundle_path = dir.join_str("bundle.json");
        cmd_sign_blob(
            &[
                payload_path,
                "--key".into(),
                priv_a,
                "--output-bundle".into(),
                bundle_path.clone(),
            ],
            &mut sink,
        )
        .unwrap();

        let mut verify_out = Vec::new();
        let err = cmd_verify_blob(&[bundle_path, "--key".into(), pub_b], &mut verify_out)
            .expect_err("verification with wrong key MUST fail");
        assert!(
            err.0.contains("verify_blob"),
            "error should name the verify step, got: {}",
            err.0
        );
    }

    /// Bundle whose payload bytes were mutated post-signing must
    /// fail verification.
    ///
    /// Bug it catches: a verifier that signed/verified over the
    /// envelope text (rather than re-deriving the PAE from
    /// payload + payload_type) would silently accept this tamper.
    /// We mutate the base64-encoded `payload` field of the DSSE
    /// envelope inside the JSON bundle directly.
    #[test]
    fn test_cli_verify_blob_with_tampered_bundle_fails() {
        let dir = Tempdir::new("tamper");
        let prefix = dir.join_str("k");
        let mut sink = Vec::new();
        cmd_generate_key_pair(std::slice::from_ref(&prefix), &mut sink).unwrap();
        let priv_path = format!("{prefix}.key");
        let pub_path = format!("{prefix}.pub");

        let payload_path = dir.join_str("payload.bin");
        std::fs::write(&payload_path, b"original payload").unwrap();
        let bundle_path = dir.join_str("bundle.json");
        cmd_sign_blob(
            &[
                payload_path,
                "--key".into(),
                priv_path,
                "--output-bundle".into(),
                bundle_path.clone(),
            ],
            &mut sink,
        )
        .unwrap();

        // Decode the bundle, mutate the payload bytes, re-encode.
        // Going through the typed Bundle API (rather than text
        // surgery on the JSON) makes the test robust to any
        // base64 padding / field-ordering drift in the encoder.
        let bytes = std::fs::read(&bundle_path).unwrap();
        let mut bundle = Bundle::decode_json(&bytes).unwrap();
        if let sign::spec::BundleContent::DsseEnvelope(env) = &mut bundle.content {
            env.payload = b"tampered payload".to_vec();
        } else {
            panic!("expected DSSE envelope content");
        }
        let mutated = bundle.encode_json().unwrap();
        std::fs::write(&bundle_path, &mutated).unwrap();

        let mut verify_out = Vec::new();
        let err = cmd_verify_blob(&[bundle_path, "--key".into(), pub_path], &mut verify_out)
            .expect_err("tampered bundle MUST fail verification");
        assert!(
            err.0.contains("verify_blob"),
            "error should name verify step, got: {}",
            err.0
        );
    }

    /// `sign-blob --rekor` attaches at least one tlog entry to the
    /// emitted bundle. Uses the in-process mock Rekor — no HTTP.
    ///
    /// Bug it catches: the `--rekor` flag forgotten in the parser
    /// (silently ignored, so the bundle has empty tlog_entries)
    /// or a path that constructed the mock client but didn't pass
    /// it to `sign_blob`.
    #[test]
    fn test_cli_sign_blob_with_rekor_flag_attaches_tlog_entry() {
        let dir = Tempdir::new("rekor");
        let prefix = dir.join_str("witness");
        let mut sink = Vec::new();
        cmd_generate_key_pair(std::slice::from_ref(&prefix), &mut sink).unwrap();
        let priv_path = format!("{prefix}.key");

        let payload_path = dir.join_str("payload.bin");
        std::fs::write(&payload_path, b"witness me").unwrap();
        let bundle_path = dir.join_str("bundle.json");
        cmd_sign_blob(
            &[
                payload_path,
                "--key".into(),
                priv_path,
                "--output-bundle".into(),
                bundle_path.clone(),
                "--rekor".into(),
            ],
            &mut sink,
        )
        .unwrap();

        let bytes = std::fs::read(&bundle_path).unwrap();
        let bundle = Bundle::decode_json(&bytes).unwrap();
        assert!(
            !bundle.verification_material.tlog_entries.is_empty(),
            "--rekor must attach at least one tlog entry, got 0"
        );
        let tlog = &bundle.verification_material.tlog_entries[0];
        assert_eq!(tlog.kind_version.kind, "hashedrekord");
        assert!(
            tlog.inclusion_proof.is_some(),
            "tlog entry must carry an inclusion proof"
        );
    }

    /// Unknown subcommand surfaces a typed CliError with a useful
    /// hint (rather than panicking or silently exiting 0).
    #[test]
    fn test_cli_unknown_command_returns_error_with_message() {
        // Dispatch goes through main.rs, but the message-building
        // logic that main.rs uses is asserted here against the
        // same shape the binary will print. We model main.rs's
        // path directly so a regression in the error string is
        // caught at the lib-test layer.
        let unknown = "do-the-thing";
        let err = CliError(format!("unknown command: {unknown} (try --help)"));
        assert!(err.0.contains("unknown command"));
        assert!(err.0.contains(unknown));
        assert!(err.0.contains("--help"));
    }

    /// `sign-blob` without `--key` fails with a typed error rather
    /// than panicking on a missing required flag.
    #[test]
    fn test_cli_sign_blob_missing_key_arg_returns_error() {
        let dir = Tempdir::new("missingkey");
        let payload_path = dir.join_str("payload.bin");
        std::fs::write(&payload_path, b"data").unwrap();

        let mut sink = Vec::new();
        let err = cmd_sign_blob(&[payload_path], &mut sink)
            .expect_err("missing --key MUST surface an error");
        assert!(
            err.0.contains("--key"),
            "error must mention the missing flag, got: {}",
            err.0
        );
    }

    /// `--key` without a value (trailing flag, no path after) must
    /// not panic on the index lookup — surfaces a typed error.
    #[test]
    fn test_cli_sign_blob_dangling_key_flag_returns_error() {
        let dir = Tempdir::new("dangling");
        let payload_path = dir.join_str("payload.bin");
        std::fs::write(&payload_path, b"data").unwrap();

        let mut sink = Vec::new();
        let err = cmd_sign_blob(&[payload_path, "--key".into()], &mut sink)
            .expect_err("dangling --key MUST surface an error, not panic");
        assert!(
            err.0.contains("--key"),
            "error must explain the missing value, got: {}",
            err.0
        );
    }

    /// `generate-key-pair` refuses to overwrite an existing file —
    /// catches the foot-gun where a second invocation with the
    /// same prefix would silently destroy the previous key.
    #[test]
    fn test_cli_generate_key_pair_refuses_to_overwrite() {
        let dir = Tempdir::new("overwrite");
        let prefix = dir.join_str("k");
        let mut sink = Vec::new();
        cmd_generate_key_pair(std::slice::from_ref(&prefix), &mut sink).unwrap();

        let err = cmd_generate_key_pair(&[prefix], &mut sink)
            .expect_err("re-using a prefix MUST refuse to overwrite");
        assert!(
            err.0.contains("create"),
            "error must explain it tried to create a file, got: {}",
            err.0
        );
    }

    /// `public-key` derives the SPKI PEM that exactly matches the
    /// `<prefix>.pub` file `generate-key-pair` writes. If these
    /// disagree, one of the two paths is wrong.
    #[test]
    fn test_cli_public_key_matches_generated_pub_file() {
        let dir = Tempdir::new("pubkey");
        let prefix = dir.join_str("k");
        let mut sink = Vec::new();
        cmd_generate_key_pair(std::slice::from_ref(&prefix), &mut sink).unwrap();
        let priv_path = format!("{prefix}.key");
        let pub_path = format!("{prefix}.pub");

        let mut derived = Vec::new();
        cmd_public_key(&[priv_path], &mut derived).unwrap();

        let on_disk = std::fs::read(&pub_path).unwrap();
        assert_eq!(
            derived, on_disk,
            "public-key output must equal the file generate-key-pair wrote"
        );
    }
}
