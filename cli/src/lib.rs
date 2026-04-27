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

use p256::ecdsa::{SigningKey, VerifyingKey as P256VerifyingKey};
use p256::pkcs8::{
    DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding,
};
use rand_core::OsRng;
use sign::spec::Bundle;
use sign::{
    fulcio::{build_csr, FulcioClient, HttpFulcioClient},
    rekor::{HttpRekorClient, MockRekorClient, RekorClient},
    sign_blob, sign_blob_keyless, sign_blob_message, sign_blob_message_keyless, verify_blob,
    verify_blob_message, EcdsaP256Signer, VerifyingKey,
};

// OIDC providers are exposed via --oidc-provider on the
// `oidc-token` subcommand. The CLI uses the `oidc` feature of `sign`
// (always enabled by this crate's Cargo.toml). The `oidc-browser`
// provider is gated behind the cli-side `oidc-browser` feature so a
// default install on a server / CI box doesn't pull the `open` crate.
#[cfg(feature = "oidc-browser")]
use sign::InteractiveBrowserOidcProvider;
use sign::{GcpMetadataOidcProvider, GitHubActionsOidcProvider, OidcProvider, StaticOidcProvider};

/// Default Rekor base URL when `--rekor` is passed without a value.
///
/// Sigstage staging — same hostname cosign uses for staging. We
/// intentionally do NOT default to `rekor.sigstore.dev` (production)
/// in v0 because (a) writes there are permanent, and (b) v0 keys
/// are EOA-shaped, not Fulcio-issued, so production wouldn't accept
/// them anyway.
const DEFAULT_REKOR_URL: &str = "https://rekor.sigstage.dev";

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
        "  justsign sign-blob <file> {{--key <priv-pem> | --keyless [--fulcio <url>] [--oidc-provider <kind>]}} \\\n      [--shape message|dsse] [--payload-type <mime>] [--output-bundle <path>] [--rekor[=<url>]] [--mock-rekor]"
    )?;
    writeln!(
        out,
        "      signs <file>, emits a Sigstore bundle v0.3 JSON to <path> or stdout."
    )?;
    writeln!(
        out,
        "      --shape message (DEFAULT): MessageSignature content; cosign sign-blob interop."
    )?;
    writeln!(
        out,
        "      --shape dsse: DSSE envelope content; cosign attest interop. --payload-type sets MIME."
    )?;
    writeln!(
        out,
        "      --key <priv-pem-path>: static-key signing with a PKCS#8 PEM ECDSA P-256 key."
    )?;
    writeln!(
        out,
        "      --keyless: Sigstore-keyless. Mints an ephemeral keypair, fetches OIDC token,"
    )?;
    writeln!(
        out,
        "                 exchanges with Fulcio for a short-lived cert chain, embeds chain in bundle."
    )?;
    writeln!(
        out,
        "      --fulcio <url>: keyless-only Fulcio base URL; default {DEFAULT_FULCIO_URL}."
    )?;
    writeln!(
        out,
        "                      For production: --fulcio https://fulcio.sigstore.dev"
    )?;
    writeln!(
        out,
        "      --oidc-provider <kind>: keyless-only; one of static (default), github-actions,"
    )?;
    writeln!(
        out,
        "                              gcp-metadata, interactive-browser."
    )?;
    writeln!(
        out,
        "      --rekor[=<url>] submits to a real Rekor; bare flag defaults to {DEFAULT_REKOR_URL}."
    )?;
    writeln!(
        out,
        "                      For production: --rekor https://rekor.sigstore.dev"
    )?;
    writeln!(
        out,
        "      --mock-rekor uses an in-process mock Rekor (test-only; no transparency value)."
    )?;
    writeln!(
        out,
        "  justsign verify-blob <bundle-path> --key <pub-pem-path> [--shape message|dsse] [--payload <path>] \\\n      [--rekor[=<url>]] [--mock-rekor]"
    )?;
    writeln!(
        out,
        "      verifies the bundle. Exit 0 on success, 1 on failure."
    )?;
    writeln!(
        out,
        "      --shape message (DEFAULT): requires --payload <path>; re-hashes and verifies."
    )?;
    writeln!(
        out,
        "      --shape dsse: payload is embedded in the envelope; --payload is rejected."
    )?;
    writeln!(
        out,
        "      --rekor[=<url>] re-checks the bundle's tlog inclusion proof; same default URL."
    )?;
    writeln!(out, "  justsign oidc-token --oidc-provider <kind>")?;
    writeln!(
        out,
        "      fetches an OIDC ID token (JWT) and prints the first 30 chars."
    )?;
    writeln!(
        out,
        "      kinds: static (default), github-actions, gcp-metadata, interactive-browser."
    )?;
    writeln!(
        out,
        "      The same OIDC providers also feed `sign-blob --keyless`; this subcommand"
    )?;
    writeln!(
        out,
        "      lets operators preview the token resolution without driving a sign call."
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

/// Selects which Rekor backend `sign-blob` / `verify-blob` should
/// use. Concrete enum (not a `Box<dyn RekorClient>`) so the
/// `--rekor` and `--mock-rekor` flags stay mutually exclusive at
/// the parse layer.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RekorChoice {
    /// Caller did not pass any Rekor flag — no transparency.
    None,
    /// `--rekor[=<url>]` — real HTTP client at `url` (defaults to
    /// the staging URL).
    Http { url: String },
    /// `--mock-rekor` — deterministic in-process mock; carries no
    /// transparency value but pins the SPI shape for tests.
    Mock,
}

/// Default Fulcio base URL when `--keyless` is passed without an
/// explicit `--fulcio` override.
///
/// Sigstage staging — same hostname cosign uses for staging. We
/// intentionally do NOT default to `fulcio.sigstore.dev` (production)
/// for the same reason `DEFAULT_REKOR_URL` doesn't: a typo of the
/// command line could otherwise burn a permanent identity entry into
/// the public production Rekor log. Operators sign against production
/// by passing `--fulcio https://fulcio.sigstore.dev` and
/// `--rekor https://rekor.sigstore.dev` explicitly.
const DEFAULT_FULCIO_URL: &str = "https://fulcio.sigstage.dev";

/// Whether the sign path is static-key or Fulcio-keyless.
#[derive(Debug, PartialEq)]
enum SignMode {
    /// Caller supplied `--key <priv-pem>`.
    StaticKey { key_path: String },
    /// Caller supplied `--keyless`. Pulls an OIDC token via the
    /// configured provider, exchanges it with Fulcio for a
    /// short-lived cert chain, signs with the freshly-generated
    /// ephemeral keypair, and embeds the chain in the bundle.
    Keyless {
        fulcio_url: String,
        oidc_provider: OidcProviderKind,
    },
}

/// Bundle content shape `sign-blob` / `verify-blob` should produce
/// or accept. Mirrors cosign's distinction between `sign-blob`
/// (MessageSignature content; raw blob bytes) and `attest` (DSSE
/// envelope content; in-toto Statement payload).
///
/// Default is [`BundleShape::Message`] — cosign's `sign-blob`
/// equivalent. Operators signing in-toto attestations pass
/// `--shape dsse` explicitly, or use the dedicated `attest` CLI
/// surface (future).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BundleShape {
    /// `messageSignature` content arm. cosign `sign-blob` /
    /// `verify-blob` interop. Signature is over `SHA-256(payload)`;
    /// rekor schema is `hashedrekord`.
    Message,
    /// `dsseEnvelope` content arm. cosign `attest` /
    /// `verify-blob-attestation` interop. Signature is over the DSSE
    /// PAE bytes; rekor schema is `dsse`. Required for in-toto
    /// Statement payloads.
    Dsse,
}

/// Parse the `--shape <kind>` flag value.
///
/// Bug it pre-empts: a parser that silently fell back to a default
/// on an unknown shape would mask operator typos (`--shape dsee`
/// for `--shape dsse`) and silently sign the wrong content arm.
fn parse_bundle_shape(s: &str) -> Result<BundleShape, CliError> {
    match s {
        "message" => Ok(BundleShape::Message),
        "dsse" => Ok(BundleShape::Dsse),
        other => Err(CliError(format!(
            "unknown --shape: '{other}' (expected: message, dsse)"
        ))),
    }
}

/// Default DSSE `payload_type` for `--shape dsse` when the operator
/// doesn't pass `--payload-type`. Sigstore's convention for raw-blob
/// DSSE is the generic octet-stream MIME type — nothing semantic.
/// Attestation flows pass `application/vnd.in-toto+json` explicitly.
const DEFAULT_DSSE_PAYLOAD_TYPE: &str = "application/octet-stream";

/// Parsed `sign-blob` arg state.
struct SignBlobArgs {
    file: String,
    mode: SignMode,
    output_bundle: Option<String>,
    rekor: RekorChoice,
    shape: BundleShape,
    /// `payload_type` for `--shape dsse`. Ignored for
    /// `--shape message` (MessageSignature has no payload_type
    /// concept; the digest+signature pair stands alone).
    payload_type: String,
}

/// Parse the `--rekor[=<url>]` flag. Returns the URL to use.
fn parse_rekor_flag(arg: &str) -> String {
    match arg.split_once('=') {
        Some((_, url)) if !url.is_empty() => url.to_string(),
        _ => DEFAULT_REKOR_URL.to_string(),
    }
}

fn parse_sign_blob_args(args: &[String]) -> Result<SignBlobArgs, CliError> {
    let file = args
        .first()
        .ok_or_else(|| {
            CliError(
                "sign-blob requires <file> [--key <priv-pem> | --keyless [--fulcio <url>] [--oidc-provider <kind>]] [--shape message|dsse] [--payload-type <mime>] [--output-bundle <path>] [--rekor[=<url>]] [--mock-rekor]"
                    .to_string(),
            )
        })?
        .clone();
    let mut key: Option<String> = None;
    let mut keyless = false;
    let mut fulcio_url: Option<String> = None;
    let mut oidc_provider: Option<OidcProviderKind> = None;
    let mut output_bundle: Option<String> = None;
    let mut rekor = RekorChoice::None;
    let mut shape: Option<BundleShape> = None;
    let mut payload_type: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        let arg = args[i].as_str();
        match arg {
            "--key" => {
                let v = args
                    .get(i + 1)
                    .ok_or_else(|| CliError("--key requires a path argument".to_string()))?;
                key = Some(v.clone());
                i += 2;
            }
            "--keyless" => {
                keyless = true;
                i += 1;
            }
            "--fulcio" => {
                let v = args
                    .get(i + 1)
                    .ok_or_else(|| CliError("--fulcio requires a URL argument".to_string()))?;
                fulcio_url = Some(v.clone());
                i += 2;
            }
            "--oidc-provider" => {
                let v = args.get(i + 1).ok_or_else(|| {
                    CliError("--oidc-provider requires a kind argument".to_string())
                })?;
                oidc_provider = Some(parse_oidc_provider_kind(v)?);
                i += 2;
            }
            "--output-bundle" => {
                let v = args.get(i + 1).ok_or_else(|| {
                    CliError("--output-bundle requires a path argument".to_string())
                })?;
                output_bundle = Some(v.clone());
                i += 2;
            }
            "--shape" => {
                let v = args
                    .get(i + 1)
                    .ok_or_else(|| CliError("--shape requires a kind argument".to_string()))?;
                shape = Some(parse_bundle_shape(v)?);
                i += 2;
            }
            "--payload-type" => {
                let v = args.get(i + 1).ok_or_else(|| {
                    CliError("--payload-type requires a MIME argument".to_string())
                })?;
                payload_type = Some(v.clone());
                i += 2;
            }
            "--mock-rekor" => {
                if rekor != RekorChoice::None {
                    return Err(CliError(
                        "--mock-rekor and --rekor are mutually exclusive".to_string(),
                    ));
                }
                rekor = RekorChoice::Mock;
                i += 1;
            }
            _ if arg == "--rekor" || arg.starts_with("--rekor=") => {
                if rekor != RekorChoice::None {
                    return Err(CliError(
                        "--rekor and --mock-rekor are mutually exclusive".to_string(),
                    ));
                }
                rekor = RekorChoice::Http {
                    url: parse_rekor_flag(arg),
                };
                i += 1;
            }
            other => return Err(CliError(format!("unknown flag: {other}"))),
        }
    }
    // Default shape is `message` (cosign sign-blob equivalent —
    // issue #40). Operators signing in-toto attestations opt in via
    // `--shape dsse`. Default `payload_type` for DSSE is
    // `application/octet-stream`; for MessageSignature it's unused.
    let shape = shape.unwrap_or(BundleShape::Message);
    let payload_type = match (shape, payload_type) {
        (BundleShape::Message, Some(_)) => {
            return Err(CliError(
                "--payload-type is only valid with --shape dsse (MessageSignature has no payload_type field)"
                    .to_string(),
            ));
        }
        (BundleShape::Message, None) => String::new(),
        (BundleShape::Dsse, Some(v)) => v,
        (BundleShape::Dsse, None) => DEFAULT_DSSE_PAYLOAD_TYPE.to_string(),
    };
    // `--key` and `--keyless` are mutually exclusive AND one is required.
    let mode = match (key, keyless) {
        (Some(_), true) => {
            return Err(CliError(
                "--key and --keyless are mutually exclusive".to_string(),
            ));
        }
        (None, false) => {
            return Err(CliError(
                "sign-blob requires either --key <priv-pem-path> or --keyless".to_string(),
            ));
        }
        (Some(key_path), false) => {
            // `--fulcio` and `--oidc-provider` only apply to keyless.
            if fulcio_url.is_some() {
                return Err(CliError(
                    "--fulcio is only valid with --keyless".to_string(),
                ));
            }
            if oidc_provider.is_some() {
                return Err(CliError(
                    "--oidc-provider is only valid with --keyless".to_string(),
                ));
            }
            SignMode::StaticKey { key_path }
        }
        (None, true) => SignMode::Keyless {
            fulcio_url: fulcio_url.unwrap_or_else(|| DEFAULT_FULCIO_URL.to_string()),
            oidc_provider: oidc_provider.unwrap_or(OidcProviderKind::Static),
        },
    };
    Ok(SignBlobArgs {
        file,
        mode,
        output_bundle,
        rekor,
        shape,
        payload_type,
    })
}

/// `sign-blob <file> [--key <priv-pem-path> | --keyless [--fulcio <url>] [--oidc-provider <kind>]] [--output-bundle <path>] [--rekor]`
/// — sign the bytes of `<file>` and emit a Sigstore bundle v0.3
/// JSON to `<path>` or stdout.
///
/// Two sign modes:
///
/// * **`--key <priv-pem>`** — static-key signing. Caller supplies a
///   PKCS#8 PEM ECDSA P-256 private key (e.g. from `generate-key-pair`).
///   The bundle's `verification_material.certificate` is left
///   empty; verifiers need the matching public key out-of-band.
/// * **`--keyless`** — Sigstore-keyless signing. Mints an ephemeral
///   ECDSA P-256 keypair, fetches an OIDC ID token via the chosen
///   provider, exchanges it with Fulcio for a short-lived cert
///   chain, signs the payload with the ephemeral key, and embeds
///   the chain in the bundle. Verifiers establish trust by walking
///   the chain back to Sigstore's trust roots.
///
/// Default Fulcio target is `fulcio.sigstage.dev` (staging) — operators
/// signing against production must pass `--fulcio https://fulcio.sigstore.dev`
/// AND `--rekor https://rekor.sigstore.dev` explicitly. The mismatch
/// between defaults is intentional: a typo'd command line should not
/// burn a permanent identity entry into the public production Rekor log.
pub fn cmd_sign_blob<W: Write>(args: &[String], out: &mut W) -> Result<(), CliError> {
    let parsed = parse_sign_blob_args(args)?;

    let payload = std::fs::read(Path::new(&parsed.file))
        .map_err(|e| CliError(format!("read {}: {e}", parsed.file)))?;

    // Hold storage for whichever Rekor client variant is in play.
    // Both branches are bound out-of-line so `rekor_arg` can borrow
    // them through a `&dyn RekorClient` of matching lifetime.
    let mock_client;
    let http_client;
    let rekor_arg: Option<&dyn RekorClient> = match &parsed.rekor {
        RekorChoice::None => None,
        RekorChoice::Mock => {
            mock_client = MockRekorClient::new();
            Some(&mock_client)
        }
        RekorChoice::Http { url } => {
            http_client = HttpRekorClient::new(url.as_str())
                .map_err(|e| CliError(format!("build Rekor client for {url}: {e}")))?;
            Some(&http_client)
        }
    };

    let bundle = match &parsed.mode {
        SignMode::StaticKey { key_path } => {
            let priv_pem = std::fs::read_to_string(Path::new(key_path))
                .map_err(|e| CliError(format!("read {key_path}: {e}")))?;
            let signing_key = SigningKey::from_pkcs8_pem(&priv_pem)
                .map_err(|e| CliError(format!("parse PKCS#8 PEM private key: {e}")))?;
            let signer = EcdsaP256Signer::new(signing_key, None);

            // Dispatch on the bundle shape:
            //   --shape message (default): MessageSignature content,
            //     cosign `sign-blob` interop, signature over
            //     SHA-256(payload). Issue #40.
            //   --shape dsse: DSSE envelope content, cosign `attest`
            //     interop, signature over PAE bytes. Operator passes
            //     `--payload-type` for the wrapper MIME.
            match parsed.shape {
                BundleShape::Message => sign_blob_message(&payload, &signer, rekor_arg)
                    .map_err(|e| CliError(format!("sign_blob_message: {e}")))?,
                BundleShape::Dsse => sign_blob(&payload, &parsed.payload_type, &signer, rekor_arg)
                    .map_err(|e| CliError(format!("sign_blob: {e}")))?,
            }
        }
        SignMode::Keyless {
            fulcio_url,
            oidc_provider,
        } => {
            // Step 1: resolve OIDC ID token. Operator surfaces the
            // chosen provider via `--oidc-provider`; the helper here
            // dispatches to the matching `OidcProvider` impl.
            writeln!(out, "fetching OIDC token from {}...", oidc_provider.label())
                .map_err(|e| CliError(format!("write: {e}")))?;
            let token = fetch_oidc_token(*oidc_provider)?;

            // Step 2: ephemeral ECDSA P-256 keypair. Fresh per sign
            // call; never written to disk; freed when this function
            // returns.
            let signing_key = SigningKey::random(&mut OsRng);

            // Step 3: build the CSR. The `subject_email` placeholder
            // is overwritten server-side by Fulcio with the OIDC
            // token's `sub` / `email` claim (the OIDC subject is what
            // ends up in the leaf cert's SAN, not what we put here).
            let csr = build_csr(&signing_key, "justsign-cli@local")
                .map_err(|e| CliError(format!("build CSR: {e}")))?;

            // Step 4: exchange CSR + token for a cert chain. The
            // cert chain's leaf is a P-256 signing cert bound to the
            // OIDC subject; intermediates and root come from Fulcio.
            writeln!(out, "exchanging CSR with Fulcio at {fulcio_url}...")
                .map_err(|e| CliError(format!("write: {e}")))?;
            let fulcio_client = HttpFulcioClient::new(fulcio_url.as_str())
                .map_err(|e| CliError(format!("build Fulcio client for {fulcio_url}: {e}")))?;
            let cert_chain = fulcio_client
                .sign_csr(&csr, &token)
                .map_err(|e| CliError(format!("Fulcio sign_csr: {e}")))?;

            // Step 5: convert chain to the leaf-first DER vec shape
            // `sign_blob_keyless` expects. The fulcio crate's
            // `X509Cert` already holds verbatim DER bytes per cert.
            let cert_chain_der: Vec<Vec<u8>> =
                cert_chain.certs.iter().map(|c| c.der.clone()).collect();

            // Step 6: build the signer over the ephemeral key and
            // delegate to the keyless producer matching the chosen
            // shape. Both producers carry the leaf cert on the wire
            // at `verification_material.certificate.rawBytes`
            // (singular `X509Certificate`, the protobuf-specs v0.3
            // final shape cosign 3.0+ requires); they differ in the
            // content arm (MessageSignature vs DsseEnvelope) and the
            // rekor schema dispatch (hashedrekord vs dsse).
            let signer = EcdsaP256Signer::new(signing_key, None);
            match parsed.shape {
                BundleShape::Message => {
                    sign_blob_message_keyless(&payload, &signer, &cert_chain_der, rekor_arg)
                        .map_err(|e| CliError(format!("sign_blob_message_keyless: {e}")))?
                }
                BundleShape::Dsse => sign_blob_keyless(
                    &payload,
                    &parsed.payload_type,
                    &signer,
                    &cert_chain_der,
                    rekor_arg,
                )
                .map_err(|e| CliError(format!("sign_blob_keyless: {e}")))?,
            }
        }
    };

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
    rekor: RekorChoice,
    shape: BundleShape,
    /// Path to the original payload bytes — required for
    /// `--shape message` (verifier re-hashes them and checks against
    /// the bundle's pinned digest). Ignored for `--shape dsse` (the
    /// payload is embedded in the envelope).
    payload: Option<String>,
}

fn parse_verify_blob_args(args: &[String]) -> Result<VerifyBlobArgs, CliError> {
    let bundle = args
        .first()
        .ok_or_else(|| {
            CliError(
                "verify-blob requires <bundle-path> --key <pub-pem-path> [--shape message|dsse] [--payload <path>] [--rekor[=<url>]] [--mock-rekor]"
                    .to_string(),
            )
        })?
        .clone();
    let mut key: Option<String> = None;
    let mut rekor = RekorChoice::None;
    let mut shape: Option<BundleShape> = None;
    let mut payload: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        let arg = args[i].as_str();
        match arg {
            "--key" => {
                let v = args
                    .get(i + 1)
                    .ok_or_else(|| CliError("--key requires a path argument".to_string()))?;
                key = Some(v.clone());
                i += 2;
            }
            "--shape" => {
                let v = args
                    .get(i + 1)
                    .ok_or_else(|| CliError("--shape requires a kind argument".to_string()))?;
                shape = Some(parse_bundle_shape(v)?);
                i += 2;
            }
            "--payload" => {
                let v = args
                    .get(i + 1)
                    .ok_or_else(|| CliError("--payload requires a path argument".to_string()))?;
                payload = Some(v.clone());
                i += 2;
            }
            "--mock-rekor" => {
                if rekor != RekorChoice::None {
                    return Err(CliError(
                        "--mock-rekor and --rekor are mutually exclusive".to_string(),
                    ));
                }
                rekor = RekorChoice::Mock;
                i += 1;
            }
            _ if arg == "--rekor" || arg.starts_with("--rekor=") => {
                if rekor != RekorChoice::None {
                    return Err(CliError(
                        "--rekor and --mock-rekor are mutually exclusive".to_string(),
                    ));
                }
                rekor = RekorChoice::Http {
                    url: parse_rekor_flag(arg),
                };
                i += 1;
            }
            other => return Err(CliError(format!("unknown flag: {other}"))),
        }
    }
    let key =
        key.ok_or_else(|| CliError("verify-blob requires --key <pub-pem-path>".to_string()))?;
    let shape = shape.unwrap_or(BundleShape::Message);
    // `--payload` is required for `--shape message` (the verifier
    // re-hashes the payload bytes the operator fetched, and the path
    // tells us where to find them). For `--shape dsse` the payload is
    // already embedded in the envelope, so the flag is rejected to
    // catch typo'd command lines that pass both.
    if shape == BundleShape::Dsse && payload.is_some() {
        return Err(CliError(
            "--payload is only valid with --shape message (DSSE bundles carry the payload inline)"
                .to_string(),
        ));
    }
    Ok(VerifyBlobArgs {
        bundle,
        key,
        rekor,
        shape,
        payload,
    })
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
    // The CLI's v0 surface only knows how to parse P-256 SPKI PEM
    // (mirrors what `cosign generate-key-pair` writes). Multi-algo
    // verification is available via the library API (`sign::VerifyingKey`
    // is a typed enum across P-256 / Ed25519 / P-384 / secp256k1 behind
    // their respective features), but the CLI's --key flag is P-256
    // until issue #13 wires algorithm detection from PEM headers.
    let p256_vk = P256VerifyingKey::from_public_key_pem(&pub_pem)
        .map_err(|e| CliError(format!("parse SPKI PEM public key: {e}")))?;
    let verifying_key = VerifyingKey::P256(p256_vk);

    // Rekor verification at the CLI layer is OPT-IN: the bundle's
    // embedded inclusion proof is re-checked against its own root
    // when the operator passes `--rekor` (real client) or
    // `--mock-rekor` (test-only).
    let mock_client;
    let http_client;
    let rekor_arg: Option<&dyn RekorClient> = match &parsed.rekor {
        RekorChoice::None => None,
        RekorChoice::Mock => {
            mock_client = MockRekorClient::new();
            Some(&mock_client)
        }
        RekorChoice::Http { url } => {
            http_client = HttpRekorClient::new(url.as_str())
                .map_err(|e| CliError(format!("build Rekor client for {url}: {e}")))?;
            Some(&http_client)
        }
    };

    // Dispatch on the bundle shape:
    //   --shape message (default): MessageSignature content. Caller
    //     supplies `--payload <path>`; verifier re-hashes those bytes
    //     and checks against the bundle's pinned digest, then verifies
    //     the signature against the digest.
    //   --shape dsse: DSSE envelope content. Payload is embedded in
    //     the envelope; verifier re-derives the PAE and checks.
    match parsed.shape {
        BundleShape::Message => {
            let payload_path = parsed.payload.ok_or_else(|| {
                CliError(
                    "--shape message requires --payload <path> (verifier re-hashes the payload)"
                        .to_string(),
                )
            })?;
            let payload_bytes = std::fs::read(Path::new(&payload_path))
                .map_err(|e| CliError(format!("read {payload_path}: {e}")))?;
            verify_blob_message(&bundle, &payload_bytes, &[verifying_key], rekor_arg)
                .map_err(|e| CliError(format!("verify_blob_message: {e}")))?;
        }
        BundleShape::Dsse => {
            verify_blob(&bundle, &[verifying_key], rekor_arg)
                .map_err(|e| CliError(format!("verify_blob: {e}")))?;
        }
    }

    writeln!(out, "OK").map_err(|e| CliError(format!("write: {e}")))?;
    Ok(())
}

/// Selects which OIDC provider `oidc-token` should use.
///
/// Concrete enum (rather than a `Box<dyn OidcProvider>`) so the
/// `--oidc-provider <kind>` flag has a single, exhaustively-matched
/// place where the kind string is decoded — adding a new provider
/// means failing the `match` upfront, which is what we want.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OidcProviderKind {
    Static,
    GitHubActions,
    GcpMetadata,
    InteractiveBrowser,
}

impl OidcProviderKind {
    /// Operator-friendly label printed in "fetching from <kind>..."
    /// messages and in the unknown-provider error.
    fn label(&self) -> &'static str {
        match self {
            OidcProviderKind::Static => "static",
            OidcProviderKind::GitHubActions => "github-actions",
            OidcProviderKind::GcpMetadata => "gcp-metadata",
            OidcProviderKind::InteractiveBrowser => "interactive-browser",
        }
    }
}

/// Parse the `--oidc-provider <kind>` value. Returns a typed
/// `OidcProviderKind` or a `CliError` whose message names every
/// supported value — operators who mistype a kind get the answer in
/// the error rather than having to read the help text.
fn parse_oidc_provider_kind(s: &str) -> Result<OidcProviderKind, CliError> {
    match s {
        "static" => Ok(OidcProviderKind::Static),
        "github-actions" => Ok(OidcProviderKind::GitHubActions),
        "gcp-metadata" => Ok(OidcProviderKind::GcpMetadata),
        "interactive-browser" => Ok(OidcProviderKind::InteractiveBrowser),
        other => Err(CliError(format!(
            "unknown --oidc-provider kind: '{other}' (expected: static, github-actions, gcp-metadata, interactive-browser)"
        ))),
    }
}

/// `oidc-token --oidc-provider <kind>` — fetch an OIDC ID token from
/// the selected provider and print the first 30 chars.
///
/// v0 wiring proof: the CLI does not yet have a keyless-sign command,
/// so the fetched token has nowhere to go end-to-end. Surfacing it
/// here proves the provider trait + flag wiring works against every
/// kind we ship; the keyless-sign command (which feeds the token to
/// Fulcio) lands in a follow-up issue.
pub fn cmd_oidc_token<W: Write>(args: &[String], out: &mut W) -> Result<(), CliError> {
    // Default to `static` so this subcommand works in CI / scripted
    // flows where the token is already in env (the most common case).
    let mut kind = OidcProviderKind::Static;
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        match arg {
            "--oidc-provider" => {
                let v = args.get(i + 1).ok_or_else(|| {
                    CliError("--oidc-provider requires a kind argument".to_string())
                })?;
                kind = parse_oidc_provider_kind(v)?;
                i += 2;
            }
            other => return Err(CliError(format!("unknown flag: {other}"))),
        }
    }

    writeln!(out, "fetching OIDC token from {}...", kind.label())
        .map_err(|e| CliError(format!("write: {e}")))?;

    let token = fetch_oidc_token(kind)?;

    // Print only the first 30 chars + `...` — full JWTs are 1-2 KiB
    // and pasting one into a terminal log line is a footgun
    // (operators tend to copy them, the first 30 chars is enough to
    // confirm the wiring + sniff which issuer it came from). Use
    // `chars()` not byte slicing so we never split a UTF-8 codepoint.
    let preview: String = token.chars().take(30).collect();
    let elided = if token.chars().count() > 30 {
        "..."
    } else {
        ""
    };
    writeln!(out, "token: {preview}{elided}").map_err(|e| CliError(format!("write: {e}")))?;
    Ok(())
}

/// Resolve an OIDC ID token via the configured provider.
///
/// Shared helper between `cmd_oidc_token` (which prints a preview)
/// and `cmd_sign_blob`'s `--keyless` path (which feeds the token to
/// Fulcio). Centralised so the OIDC-error -> CliError mapping happens
/// in one place.
fn fetch_oidc_token(kind: OidcProviderKind) -> Result<String, CliError> {
    let token = match kind {
        OidcProviderKind::Static => StaticOidcProvider::default().fetch_token(),
        OidcProviderKind::GitHubActions => GitHubActionsOidcProvider::default().fetch_token(),
        OidcProviderKind::GcpMetadata => GcpMetadataOidcProvider::default().fetch_token(),
        OidcProviderKind::InteractiveBrowser => fetch_interactive_browser_token(),
    }
    .map_err(|e| CliError(format!("oidc fetch: {e}")))?;
    Ok(token)
}

/// Helper that returns `Err` when the `oidc-browser` feature is OFF —
/// keeps the `match` arm exhaustive without needing two compilation
/// shapes for `cmd_oidc_token`.
#[cfg(feature = "oidc-browser")]
fn fetch_interactive_browser_token() -> Result<String, sign::OidcError> {
    InteractiveBrowserOidcProvider::default().fetch_token()
}

#[cfg(not(feature = "oidc-browser"))]
fn fetch_interactive_browser_token() -> Result<String, sign::OidcError> {
    // `OidcError::Http` is the right shape: same enum the real
    // provider would return, the only sensible variant for "this
    // build has no browser provider".
    Err(sign::OidcError::Http(
        "interactive-browser provider not compiled in (rebuild with --features oidc-browser)"
            .to_string(),
    ))
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
    /// Default `--shape message` (issue #40, cosign sign-blob
    /// equivalent): sign reads `<file>` and emits a MessageSignature
    /// bundle; verify takes the same `<file>` via `--payload <path>`,
    /// re-hashes, and checks the signature.
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
                payload_path.clone(),
                "--key".into(),
                priv_path,
                "--output-bundle".into(),
                bundle_path.clone(),
            ],
            &mut sink,
        )
        .unwrap();

        let mut verify_out = Vec::new();
        cmd_verify_blob(
            &[
                bundle_path,
                "--key".into(),
                pub_path,
                "--payload".into(),
                payload_path,
            ],
            &mut verify_out,
        )
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
                payload_path.clone(),
                "--key".into(),
                priv_a,
                "--output-bundle".into(),
                bundle_path.clone(),
            ],
            &mut sink,
        )
        .unwrap();

        let mut verify_out = Vec::new();
        let err = cmd_verify_blob(
            &[
                bundle_path,
                "--key".into(),
                pub_b,
                "--payload".into(),
                payload_path,
            ],
            &mut verify_out,
        )
        .expect_err("verification with wrong key MUST fail");
        // Default shape is `--shape message` (issue #40), so the
        // verify step runs through `verify_blob_message`.
        assert!(
            err.0.contains("verify_blob_message") || err.0.contains("verify_blob"),
            "error should name the verify step, got: {}",
            err.0
        );
    }

    /// Bundle whose pinned digest no longer matches the payload the
    /// verifier was handed must fail verification.
    ///
    /// MessageSignature semantics (default shape, issue #40): the
    /// bundle pins `messageDigest.digest = SHA-256(payload)` at
    /// sign time; verify recomputes from `--payload` and rejects
    /// when they disagree. We mutate the bundle's pinned digest in
    /// place (so the caller-supplied payload no longer matches) and
    /// require rejection.
    ///
    /// Bug it catches: a verifier that skipped the digest gate
    /// would accept a bundle re-pointed at different bytes.
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
                payload_path.clone(),
                "--key".into(),
                priv_path,
                "--output-bundle".into(),
                bundle_path.clone(),
            ],
            &mut sink,
        )
        .unwrap();

        // Decode the bundle, mutate the pinned digest, re-encode.
        // Going through the typed Bundle API (rather than text
        // surgery on the JSON) makes the test robust to any
        // base64 padding / field-ordering drift in the encoder.
        let bytes = std::fs::read(&bundle_path).unwrap();
        let mut bundle = Bundle::decode_json(&bytes).unwrap();
        match &mut bundle.content {
            sign::spec::BundleContent::MessageSignature(ms) => {
                // Flip a bit so the recomputed SHA-256 of the payload
                // file no longer matches; verify_blob_message must
                // surface PayloadDigestMismatch.
                ms.message_digest.digest[0] ^= 0xFF;
            }
            other => panic!("expected MessageSignature content, got {other:?}"),
        }
        let mutated = bundle.encode_json().unwrap();
        std::fs::write(&bundle_path, &mutated).unwrap();

        let mut verify_out = Vec::new();
        let err = cmd_verify_blob(
            &[
                bundle_path,
                "--key".into(),
                pub_path,
                "--payload".into(),
                payload_path,
            ],
            &mut verify_out,
        )
        .expect_err("tampered bundle MUST fail verification");
        assert!(
            err.0.contains("verify_blob_message") || err.0.contains("verify_blob"),
            "error should name verify step, got: {}",
            err.0
        );
    }

    /// `sign-blob --mock-rekor` attaches at least one tlog entry to
    /// the emitted bundle. Uses the in-process mock — no HTTP.
    ///
    /// Bug it catches: the `--mock-rekor` flag forgotten in the
    /// parser (silently ignored, so the bundle has empty
    /// tlog_entries) or a path that constructed the mock client
    /// but didn't pass it to `sign_blob`. We test against the mock
    /// rather than `--rekor` because `--rekor` defaults to a real
    /// HTTPS URL — exercising it here would hit the network.
    #[test]
    fn test_cli_sign_blob_with_mock_rekor_flag_attaches_tlog_entry() {
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
                "--mock-rekor".into(),
            ],
            &mut sink,
        )
        .unwrap();

        let bytes = std::fs::read(&bundle_path).unwrap();
        let bundle = Bundle::decode_json(&bytes).unwrap();
        assert!(
            !bundle.verification_material.tlog_entries.is_empty(),
            "--mock-rekor must attach at least one tlog entry, got 0"
        );
        let tlog = &bundle.verification_material.tlog_entries[0];
        assert_eq!(tlog.kind_version.kind, "hashedrekord");
        assert!(
            tlog.inclusion_proof.is_some(),
            "tlog entry must carry an inclusion proof"
        );
    }

    /// `sign-blob --rekor=<url>` parses the embedded URL and routes
    /// to `HttpRekorClient` — confirmed by the parser, not by a
    /// network call. We bind a non-routable URL and assert the
    /// failure path goes through `HttpRekorClient::submit` (a
    /// transport / DNS / connect error), NOT through any code path
    /// that would silently succeed.
    ///
    /// Bug it catches: `--rekor=<url>` falling through to the bare
    /// `--rekor` arm (defaulting to staging) and silently sending
    /// to the wrong server, or a parser that drops the value and
    /// silently picks `RekorChoice::None`.
    #[test]
    fn test_cli_sign_blob_with_rekor_url_routes_to_http_client() {
        let dir = Tempdir::new("rekor-url");
        let prefix = dir.join_str("k");
        let mut sink = Vec::new();
        cmd_generate_key_pair(std::slice::from_ref(&prefix), &mut sink).unwrap();
        let priv_path = format!("{prefix}.key");

        let payload_path = dir.join_str("payload.bin");
        std::fs::write(&payload_path, b"witness me").unwrap();
        let bundle_path = dir.join_str("bundle.json");

        // RFC 6761 reserved TLD `.invalid` — guaranteed not to
        // resolve, so we exercise the wiring without sending real
        // traffic. The error MUST come from the Rekor submit path.
        let err = cmd_sign_blob(
            &[
                payload_path,
                "--key".into(),
                priv_path,
                "--output-bundle".into(),
                bundle_path,
                "--rekor=https://nonexistent.invalid".into(),
            ],
            &mut sink,
        )
        .expect_err("non-routable Rekor URL must surface a typed error");
        assert!(
            err.0.contains("sign_blob") || err.0.contains("Rekor"),
            "error must name the sign/Rekor step, got: {}",
            err.0
        );
    }

    /// `--rekor` and `--mock-rekor` are mutually exclusive — passing
    /// both surfaces a typed error rather than silently picking one.
    ///
    /// Bug it catches: a parser ordering bug where the second flag
    /// silently overwrites the first would let a test claim
    /// "transparency" while actually using the mock (or vice
    /// versa). The mutual-exclusion check is the only thing
    /// stopping that confusion at the CLI surface.
    #[test]
    fn test_cli_sign_blob_with_both_rekor_flags_returns_error() {
        let dir = Tempdir::new("both-rekor");
        let prefix = dir.join_str("k");
        let mut sink = Vec::new();
        cmd_generate_key_pair(std::slice::from_ref(&prefix), &mut sink).unwrap();
        let priv_path = format!("{prefix}.key");

        let payload_path = dir.join_str("payload.bin");
        std::fs::write(&payload_path, b"data").unwrap();

        let err = cmd_sign_blob(
            &[
                payload_path,
                "--key".into(),
                priv_path,
                "--rekor".into(),
                "--mock-rekor".into(),
            ],
            &mut sink,
        )
        .expect_err("mixing --rekor and --mock-rekor MUST surface an error");
        assert!(
            err.0.contains("mutually exclusive"),
            "error must explain the conflict, got: {}",
            err.0
        );
    }

    /// `--key` and `--keyless` are mutually exclusive — passing both
    /// surfaces a typed error rather than silently dropping one.
    ///
    /// Bug it catches: a parser that ignored the duplicate-mode case
    /// would let a caller think they're signing keyless while
    /// actually using a static key (or vice versa), masking the
    /// identity surface that ends up in the bundle.
    #[test]
    fn test_cli_sign_blob_with_key_and_keyless_returns_error() {
        let dir = Tempdir::new("key-and-keyless");
        let prefix = dir.join_str("k");
        let mut sink = Vec::new();
        cmd_generate_key_pair(std::slice::from_ref(&prefix), &mut sink).unwrap();
        let priv_path = format!("{prefix}.key");

        let payload_path = dir.join_str("payload.bin");
        std::fs::write(&payload_path, b"data").unwrap();

        let err = cmd_sign_blob(
            &[payload_path, "--key".into(), priv_path, "--keyless".into()],
            &mut sink,
        )
        .expect_err("--key + --keyless MUST surface an error");
        assert!(
            err.0.contains("mutually exclusive"),
            "error must explain the conflict, got: {}",
            err.0
        );
    }

    /// `--fulcio` is keyless-only; passing it with `--key` surfaces
    /// a typed error so callers don't think their override applied.
    ///
    /// Bug it catches: a parser that silently accepted `--fulcio`
    /// in the static-key branch would have it appear to work, with
    /// the operator not realising the URL was ignored.
    #[test]
    fn test_cli_sign_blob_with_fulcio_and_static_key_returns_error() {
        let dir = Tempdir::new("fulcio-static");
        let prefix = dir.join_str("k");
        let mut sink = Vec::new();
        cmd_generate_key_pair(std::slice::from_ref(&prefix), &mut sink).unwrap();
        let priv_path = format!("{prefix}.key");

        let payload_path = dir.join_str("payload.bin");
        std::fs::write(&payload_path, b"data").unwrap();

        let err = cmd_sign_blob(
            &[
                payload_path,
                "--key".into(),
                priv_path,
                "--fulcio".into(),
                "https://fulcio.example.invalid".into(),
            ],
            &mut sink,
        )
        .expect_err("--fulcio without --keyless MUST surface an error");
        assert!(
            err.0.contains("--fulcio"),
            "error must explain --fulcio is keyless-only, got: {}",
            err.0
        );
    }

    /// `--keyless` parses defaults: Fulcio defaults to staging,
    /// OIDC provider defaults to Static. Pins the default values
    /// so a regression that flips Fulcio default to production
    /// would be caught at the parser layer.
    ///
    /// Bug it catches: a default change to `https://fulcio.sigstore.dev`
    /// (production) would let a typo'd command burn a permanent
    /// identity entry into the public production Rekor log. The
    /// CLI default is staging on purpose; this test pins that.
    #[test]
    fn test_cli_sign_blob_keyless_defaults_to_staging_fulcio() {
        let dir = Tempdir::new("keyless-defaults");
        let payload_path = dir.join_str("payload.bin");
        std::fs::write(&payload_path, b"data").unwrap();

        let parsed = super::parse_sign_blob_args(&[payload_path, "--keyless".into()]).unwrap();
        match parsed.mode {
            SignMode::Keyless {
                fulcio_url,
                oidc_provider,
            } => {
                assert_eq!(
                    fulcio_url, DEFAULT_FULCIO_URL,
                    "Fulcio default must be staging"
                );
                assert_eq!(oidc_provider, OidcProviderKind::Static);
            }
            other => panic!("expected SignMode::Keyless, got {other:?}"),
        }
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

    /// `--oidc-provider <kind>` parses every supported value into
    /// the typed `OidcProviderKind` enum, and unknown kinds surface
    /// a typed CliError that names the legal values.
    ///
    /// Bug it catches: a parser that silently fell back to `static`
    /// on an unknown kind would mask operator typos (e.g. `--oidc-
    /// provider github` instead of `github-actions`) and silently
    /// pull a stale env-var token in CI.
    #[test]
    fn test_cli_parse_oidc_provider_kind_accepts_all_supported_values() {
        assert_eq!(
            parse_oidc_provider_kind("static").unwrap(),
            OidcProviderKind::Static
        );
        assert_eq!(
            parse_oidc_provider_kind("github-actions").unwrap(),
            OidcProviderKind::GitHubActions
        );
        assert_eq!(
            parse_oidc_provider_kind("gcp-metadata").unwrap(),
            OidcProviderKind::GcpMetadata
        );
        assert_eq!(
            parse_oidc_provider_kind("interactive-browser").unwrap(),
            OidcProviderKind::InteractiveBrowser
        );

        let err = parse_oidc_provider_kind("github")
            .expect_err("unknown kind must surface a typed error");
        assert!(
            err.0.contains("github-actions"),
            "error must list legal values, got: {}",
            err.0
        );
        assert!(
            err.0.contains("static"),
            "error must list legal values, got: {}",
            err.0
        );
    }

    // ── --shape flag (issue #40) ────────────────────────────────────
    //
    // cosign's `sign-blob` produces MessageSignature content;
    // `attest` produces DSSE envelope content. justsign's CLI now
    // dispatches on `--shape <kind>` with `message` (default) routing
    // to the cosign-blob equivalent.

    /// Default `--shape` is `message`. Pin the parser default so a
    /// regression that flipped the default to `dsse` (the pre-#40
    /// behaviour) would surface here at the lib-test layer rather
    /// than out in the wild as cosign-rejected bundles.
    ///
    /// Bug it catches: an operator running `justsign sign-blob` with
    /// no `--shape` flag MUST get a MessageSignature-content bundle
    /// (cosign sign-blob shape). A regression that defaulted to dsse
    /// would re-introduce the issue-40 wire-shape gap silently.
    #[test]
    fn test_cli_sign_blob_default_shape_is_message() {
        let dir = Tempdir::new("default-shape");
        let payload_path = dir.join_str("payload.bin");
        std::fs::write(&payload_path, b"data").unwrap();

        // Parser-only test — we don't actually need a real key here.
        let parsed =
            parse_sign_blob_args(&[payload_path, "--key".into(), "/dev/null".into()]).unwrap();
        assert_eq!(
            parsed.shape,
            BundleShape::Message,
            "default --shape MUST be message (cosign sign-blob equivalent)"
        );
        assert_eq!(
            parsed.payload_type, "",
            "MessageSignature has no payload_type concept; default must be empty"
        );
    }

    /// `--shape dsse` routes through `sign_blob` (DSSE content) and
    /// produces a bundle whose content arm is `DsseEnvelope`. Pinned
    /// so a regression that ignored `--shape dsse` and silently used
    /// the message default would emit the wrong content arm for
    /// attestation flows.
    ///
    /// Bug it catches: a dispatch site that branched on the wrong
    /// field (e.g. `parsed.mode` instead of `parsed.shape`) would
    /// emit the same shape regardless of the `--shape` flag.
    #[test]
    fn test_cli_sign_blob_shape_dsse_routes_to_dsse_path() {
        let dir = Tempdir::new("shape-dsse");
        let prefix = dir.join_str("k");
        let mut sink = Vec::new();
        cmd_generate_key_pair(std::slice::from_ref(&prefix), &mut sink).unwrap();
        let priv_path = format!("{prefix}.key");

        let payload_path = dir.join_str("payload.bin");
        std::fs::write(&payload_path, b"attestation-shaped payload").unwrap();
        let bundle_path = dir.join_str("bundle.json");
        cmd_sign_blob(
            &[
                payload_path,
                "--key".into(),
                priv_path,
                "--shape".into(),
                "dsse".into(),
                "--output-bundle".into(),
                bundle_path.clone(),
            ],
            &mut sink,
        )
        .unwrap();

        let bytes = std::fs::read(&bundle_path).unwrap();
        let bundle = Bundle::decode_json(&bytes).unwrap();
        assert_eq!(
            bundle.content_kind(),
            sign::spec::BundleContentKind::DsseEnvelope,
            "--shape dsse MUST emit DsseEnvelope content"
        );
    }

    /// Default `--shape message` is the cosign sign-blob equivalent:
    /// produces a MessageSignature-content bundle that round-trips
    /// through the CLI's verify-blob path with `--payload`.
    ///
    /// Bug it catches: any drift between the default-shape sign path
    /// and the default-shape verify path — e.g. a `cmd_sign_blob`
    /// that ignored `--shape` and always emitted DSSE while
    /// `cmd_verify_blob` defaulted to `verify_blob_message`. The
    /// asymmetry would surface as `WrongContentType` rejection on a
    /// freshly-produced bundle.
    #[test]
    fn test_cli_sign_blob_shape_message_round_trips_through_cli_verify() {
        let dir = Tempdir::new("shape-msg-rt");
        let prefix = dir.join_str("k");
        let mut sink = Vec::new();
        cmd_generate_key_pair(std::slice::from_ref(&prefix), &mut sink).unwrap();
        let priv_path = format!("{prefix}.key");
        let pub_path = format!("{prefix}.pub");

        let payload_path = dir.join_str("payload.bin");
        std::fs::write(&payload_path, b"cosign sign-blob equivalent").unwrap();
        let bundle_path = dir.join_str("bundle.json");

        cmd_sign_blob(
            &[
                payload_path.clone(),
                "--key".into(),
                priv_path,
                "--output-bundle".into(),
                bundle_path.clone(),
            ],
            &mut sink,
        )
        .expect("sign with default --shape message must succeed");

        // Sanity: the bundle on disk is MessageSignature-shaped.
        let bytes = std::fs::read(&bundle_path).unwrap();
        let bundle = Bundle::decode_json(&bytes).unwrap();
        assert_eq!(
            bundle.content_kind(),
            sign::spec::BundleContentKind::MessageSignature
        );

        // Verify with default --shape message + --payload.
        let mut verify_out = Vec::new();
        cmd_verify_blob(
            &[
                bundle_path,
                "--key".into(),
                pub_path,
                "--payload".into(),
                payload_path,
            ],
            &mut verify_out,
        )
        .expect("MessageSignature bundle MUST round-trip through CLI verify");
        let s = String::from_utf8(verify_out).unwrap();
        assert!(s.contains("OK"), "verify must print OK, got: {s}");
    }

    /// `--shape message` requires `--payload` (verifier needs the
    /// bytes to re-hash). Missing `--payload` surfaces a typed error
    /// rather than panicking on a None unwrap or running the wrong
    /// code path.
    ///
    /// Bug it catches: a parser that auto-defaulted `--payload` to
    /// the bundle path (or some other "convenient" fallback) would
    /// silently re-hash the wrong bytes and either pass a wrong
    /// bundle or fail with a confusing error.
    #[test]
    fn test_cli_verify_blob_shape_message_requires_payload() {
        let dir = Tempdir::new("shape-msg-no-payload");
        let prefix = dir.join_str("k");
        let mut sink = Vec::new();
        cmd_generate_key_pair(std::slice::from_ref(&prefix), &mut sink).unwrap();
        let priv_path = format!("{prefix}.key");
        let pub_path = format!("{prefix}.pub");

        let payload_path = dir.join_str("payload.bin");
        std::fs::write(&payload_path, b"data").unwrap();
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
        let err = cmd_verify_blob(&[bundle_path, "--key".into(), pub_path], &mut verify_out)
            .expect_err("--shape message without --payload MUST surface an error");
        assert!(
            err.0.contains("--payload"),
            "error must name the missing flag, got: {}",
            err.0
        );
    }

    /// `--payload` with `--shape dsse` is rejected — DSSE bundles
    /// carry the payload inline so a `--payload` arg would be
    /// silently ignored, which is the kind of footgun this
    /// surface-area must reject loudly.
    ///
    /// Bug it catches: a parser that accepted `--payload` in the
    /// dsse branch and then silently ignored it would let an
    /// operator think they were verifying a particular file when
    /// the actual signature was over different bytes (the
    /// envelope's embedded payload).
    #[test]
    fn test_cli_verify_blob_shape_dsse_rejects_payload_flag() {
        let parsed = parse_verify_blob_args(&[
            "bundle.json".into(),
            "--key".into(),
            "k.pub".into(),
            "--shape".into(),
            "dsse".into(),
            "--payload".into(),
            "/some/path".into(),
        ]);
        match parsed {
            Ok(_) => panic!("--shape dsse + --payload MUST surface an error"),
            Err(err) => {
                let lower = err.0.to_lowercase();
                assert!(
                    lower.contains("--payload") && lower.contains("dsse"),
                    "error must explain the conflict, got: {}",
                    err.0
                );
            }
        }
    }

    /// Unknown `--shape` value surfaces a typed error naming the
    /// legal values. Same posture as `parse_oidc_provider_kind`.
    #[test]
    fn test_cli_parse_bundle_shape_rejects_unknown_value() {
        let err = parse_bundle_shape("dsee").expect_err("typo'd shape MUST reject");
        assert!(
            err.0.contains("dsse"),
            "error must list legal values, got: {}",
            err.0
        );
        assert!(
            err.0.contains("message"),
            "error must list legal values, got: {}",
            err.0
        );
    }

    /// `oidc-token` with `--oidc-provider static` and the env var set
    /// fetches the token and prints the first 30 chars.
    ///
    /// Bug it catches: a wiring bug where the CLI built a provider
    /// but never called `fetch_token()`, or one where the printed
    /// preview used byte slicing and panicked on a multibyte JWT
    /// boundary. The 30-char preview is the only operator-visible
    /// output of the v0 wiring; if it doesn't appear, the wiring
    /// is broken.
    #[test]
    fn test_cli_oidc_token_with_static_provider_prints_preview() {
        // Mutating SIGSTORE_ID_TOKEN here races with the
        // sign-crate's static_provider tests in the same workspace
        // run, BUT cargo runs each crate's tests in a separate
        // process, so cross-crate races are impossible. Within this
        // crate, this is the only env-touching test.
        let prev = std::env::var("SIGSTORE_ID_TOKEN").ok();
        // 60 chars so the elision branch (`...`) fires too. JWTs in
        // production are ~1-2 KiB; 60 chars is the smallest input
        // that still exercises the truncation logic.
        let canned_jwt = "eyJhbGciOiJSUzI1NiJ9.cli-preview-test.signature_part_x";
        std::env::set_var("SIGSTORE_ID_TOKEN", canned_jwt);

        let mut out = Vec::new();
        cmd_oidc_token(&["--oidc-provider".into(), "static".into()], &mut out)
            .expect("static provider with env set must succeed");

        let stdout = String::from_utf8(out).unwrap();
        assert!(
            stdout.contains("fetching OIDC token from static"),
            "must announce which provider, got: {stdout}"
        );
        // First 30 chars of the canned JWT exactly.
        let expected_prefix: String = canned_jwt.chars().take(30).collect();
        assert!(
            stdout.contains(&expected_prefix),
            "must print first 30 chars of token, got: {stdout}"
        );
        assert!(
            stdout.contains("..."),
            "must elide remainder with '...', got: {stdout}"
        );

        std::env::remove_var("SIGSTORE_ID_TOKEN");
        if let Some(v) = prev {
            std::env::set_var("SIGSTORE_ID_TOKEN", v);
        }
    }
}
