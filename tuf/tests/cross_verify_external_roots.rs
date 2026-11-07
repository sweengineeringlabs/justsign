//! Cross-verification of the bundled Sigstore root against roots shipped by
//! OTHER projects' release pipelines (issue #34).
//!
//! # Why
//!
//! `tuf/assets/sigstore_prod.root.json` is corroborated by three sources
//! (Sigstore CDN, and two paths in the `sigstore/root-signing` repo), all
//! owned by Sigstore. A compromise of Sigstore's release pipeline would
//! tamper with all three alike. cosign and sigstore-go embed their own
//! copies of an (older) Sigstore root through separate Go release
//! pipelines, so agreement with them is independent evidence.
//!
//! # What is compared, and why not literal byte-identity at our version
//!
//! Neither project carries OUR version. As of this writing sigstore-go
//! v1.4.0 embeds root v14 and `sigstore/sigstore` v1.11.1 (the module
//! cosign v3.1.4 pins) embeds v12; ours is newer. Both are *ancestors* of
//! it. So for each external root this test:
//!
//! 1. pins the external file by SHA-256 (a moved tag or a tampered file
//!    fails loudly);
//! 2. requires it to equal Sigstore's published root of the same version
//!    byte-for-byte, apart from a single trailing newline (the only
//!    difference found: Go's encoder appends one);
//! 3. uses it as the bootstrap for the real `TufClient`, walking Sigstore's
//!    SIGNED root chain forward (each step verified by the previous root's
//!    keys), and requires the root the walk reaches at our embedded version
//!    to be byte-identical to `SIGSTORE_PRODUCTION_ROOT_BYTES`.
//!
//! Step 3 is the strong one: our baked bytes are tied to an independently
//! shipped trust anchor by signatures, not by trusting a mirror.
//!
//! # Running
//!
//! Needs network (GitHub raw + the Sigstore CDN, public static files; no
//! secrets, no staging quota). Opt-in so a plain `cargo test` stays offline:
//! `JUSTSIGN_TUF_CROSSCHECK=1 cargo test -p swe_justsign_tuf --test
//! cross_verify_external_roots -- --nocapture`. Without it the network test
//! prints `SKIP`; CI fails the job if it sees that line.
//!
//! # Refreshing the pins
//!
//! When cosign or sigstore-go ships a newer embedded root, update `SOURCES`
//! (tag, expected root version, SHA-256). Older pins keep working because an
//! ancestor still walks forward; refresh them to track what operators run.

use std::path::PathBuf;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tuf::{TufClient, SIGSTORE_PRODUCTION_ROOT_BYTES, SIGSTORE_PRODUCTION_ROOT_VERSION};

const CDN: &str = "https://tuf-repo-cdn.sigstore.dev";
const HTTP_TIMEOUT_SECS: u64 = 30;
const HTTP_ATTEMPTS: u32 = 3;

/// An independently-shipped copy of a Sigstore root.
struct ExternalRoot {
    /// Who ships it, for failure messages.
    name: &'static str,
    /// Raw URL at an immutable release tag.
    url: &'static str,
    /// The root version the file contains.
    version: u32,
    /// SHA-256 of the file at that tag.
    sha256: &'static str,
}

const SOURCES: [ExternalRoot; 2] = [
    ExternalRoot {
        name: "sigstore-go v1.4.0",
        url: "https://raw.githubusercontent.com/sigstore/sigstore-go/v1.4.0/pkg/tuf/repository/root.json",
        version: 14,
        sha256: "a0dfcc5d51c1ce4a66b541a3fff0afa97225ccc40456b21140bb2e2f113122e2",
    },
    ExternalRoot {
        // The module cosign v3.1.4 pins (its go.mod).
        name: "sigstore/sigstore v1.11.1 (cosign v3.1.4)",
        url: "https://raw.githubusercontent.com/sigstore/sigstore/v1.11.1/pkg/tuf/repository/root.json",
        version: 12,
        sha256: "874bcce852d0eb8346bcc7fc1816fddd9cb4a8664ba6a43c1101834cea6ba2a4",
    },
];

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn strip_one_trailing_newline(b: &[u8]) -> &[u8] {
    b.strip_suffix(b"\n").unwrap_or(b)
}

/// `a` and `b` are the same file, ignoring ONE trailing newline each.
fn same_modulo_trailing_newline(label: &str, a: &[u8], b: &[u8]) -> Result<(), String> {
    let (a, b) = (strip_one_trailing_newline(a), strip_one_trailing_newline(b));
    if a == b {
        Ok(())
    } else {
        Err(format!(
            "{label}: bytes differ (sha256 {} vs {}, len {} vs {})",
            sha256_hex(a),
            sha256_hex(b),
            a.len(),
            b.len()
        ))
    }
}

fn http_get(client: &reqwest::blocking::Client, url: &str) -> Vec<u8> {
    let mut last = String::new();
    for attempt in 1..=HTTP_ATTEMPTS {
        match client.get(url).send().and_then(|r| r.error_for_status()) {
            Ok(resp) => return resp.bytes().expect("read body").to_vec(),
            Err(e) => {
                last = e.to_string();
                std::thread::sleep(Duration::from_secs(u64::from(attempt) * 2));
            }
        }
    }
    panic!("GET {url} failed after {HTTP_ATTEMPTS} attempts: {last}");
}

fn unique_cache_dir(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!("tuf-crosscheck-{}-{tag}", std::process::id()))
}

// ---- offline tests (always run) -------------------------------------

/// Bug it catches: a comparison that ignores differences. Two files that
/// differ by one byte must NOT be reported as the same.
#[test]
fn test_same_modulo_trailing_newline_one_flipped_byte_is_rejected() {
    let a = b"{\"signed\": 16}\n";
    let mut b = a.to_vec();
    b[10] ^= 0x01;
    assert!(same_modulo_trailing_newline("x", a, &b).is_err());
}

/// The one tolerated difference: Go appends a trailing newline.
#[test]
fn test_same_modulo_trailing_newline_accepts_only_a_single_newline() {
    assert!(same_modulo_trailing_newline("x", b"abc", b"abc\n").is_ok());
    assert!(same_modulo_trailing_newline("x", b"abc\n", b"abc").is_ok());
    assert!(
        same_modulo_trailing_newline("x", b"abc", b"abc\n\n").is_err(),
        "two trailing newlines is a real difference, not Go's one"
    );
    assert!(same_modulo_trailing_newline("x", b"abc", b"abc ").is_err());
}

/// Bug it catches: a malformed pin table (typo'd hash) that would only
/// surface as a confusing network-test failure.
#[test]
fn test_external_source_pins_are_well_formed() {
    for s in &SOURCES {
        assert_eq!(s.sha256.len(), 64, "{}: sha256 length", s.name);
        assert!(
            s.sha256
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
            "{}: sha256 must be lowercase hex",
            s.name
        );
        assert!(
            s.url.contains("/v"),
            "{}: pin to an immutable tag, not a branch",
            s.name
        );
        assert!(
            s.version < SIGSTORE_PRODUCTION_ROOT_VERSION,
            "{}: an external root at or above our version would not exercise the chain walk",
            s.name
        );
    }
}

// ---- network test (opt-in) -------------------------------------------

#[test]
fn test_embedded_root_matches_what_sigstore_go_and_cosign_chain_to() {
    if std::env::var("JUSTSIGN_TUF_CROSSCHECK").as_deref() != Ok("1") {
        eprintln!("SKIP: JUSTSIGN_TUF_CROSSCHECK != 1 - external-root cross-verification skipped");
        return;
    }

    let http = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
        .build()
        .expect("http client");

    for src in &SOURCES {
        // 1. The external file is exactly what we pinned.
        let ext_bytes = http_get(&http, src.url);
        assert_eq!(
            sha256_hex(&ext_bytes),
            src.sha256,
            "{}: file at {} no longer matches the pinned SHA-256 (moved tag, or tampered)",
            src.name,
            src.url
        );
        let ext_root = tuf::parse_with_signed_span::<tuf::Root>(&ext_bytes)
            .unwrap_or_else(|e| panic!("{}: not a TUF root: {e}", src.name))
            .signed;
        assert_eq!(
            ext_root.version, src.version,
            "{}: unexpected root version",
            src.name
        );

        // 2. It equals Sigstore's own published copy of that version.
        let cdn_same_version = http_get(&http, &format!("{CDN}/{}.root.json", src.version));
        same_modulo_trailing_newline(
            &format!("{} vs Sigstore CDN v{}", src.name, src.version),
            &ext_bytes,
            &cdn_same_version,
        )
        .unwrap_or_else(|e| panic!("{e}"));

        // 3. Bootstrap the real client from it and walk the SIGNED chain.
        let cache = unique_cache_dir(&format!("v{}", src.version));
        let _ = std::fs::remove_dir_all(&cache);
        let client = TufClient::new(CDN, &cache).expect("client");
        let latest = client.fetch_root(&ext_root).unwrap_or_else(|e| {
            panic!("{}: chain walk from v{} failed: {e}", src.name, src.version)
        });
        assert!(
            latest.version >= SIGSTORE_PRODUCTION_ROOT_VERSION,
            "{}: chain ended at v{}, below our embedded v{}",
            src.name,
            latest.version,
            SIGSTORE_PRODUCTION_ROOT_VERSION
        );

        // The client caches every root it verified as `<N>.root.json`.
        let reached =
            std::fs::read(cache.join(format!("{SIGSTORE_PRODUCTION_ROOT_VERSION}.root.json")))
                .unwrap_or_else(|e| {
                    panic!(
                        "{}: walk did not pass through v{SIGSTORE_PRODUCTION_ROOT_VERSION}: {e}",
                        src.name
                    )
                });
        same_modulo_trailing_newline(
            &format!(
                "{}: root reached at v{SIGSTORE_PRODUCTION_ROOT_VERSION} vs bundled asset",
                src.name
            ),
            &reached,
            SIGSTORE_PRODUCTION_ROOT_BYTES,
        )
        .unwrap_or_else(|e| panic!("{e}"));

        // Control: the same comparison MUST fail on altered bytes, or the
        // assertion above proves nothing.
        let mut altered = SIGSTORE_PRODUCTION_ROOT_BYTES.to_vec();
        let mid = altered.len() / 2;
        altered[mid] ^= 0x01;
        assert!(
            same_modulo_trailing_newline("control", &reached, &altered).is_err(),
            "control failed: the comparison cannot detect a one-byte change"
        );

        let _ = std::fs::remove_dir_all(&cache);
        eprintln!(
            "OK: {} (root v{}) chains to bundled v{SIGSTORE_PRODUCTION_ROOT_VERSION}",
            src.name, src.version
        );
    }
}
