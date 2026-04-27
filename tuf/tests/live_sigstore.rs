//! Skip-pass live integration test against the Sigstore TUF mirror.
//!
//! Always-on, no `#[ignore]`. The test compiles, links, and runs in
//! every `cargo test` invocation but no-ops cleanly with a `SKIP:
//! ...` log when the environment to drive it is not present.
//!
//! # Trigger
//!
//! Both env vars must be set:
//!
//! - `JUSTSIGN_TUF_LIVE=1` — opt-in flag (mirrors the
//!   `JUSTSIGN_FULCIO_STAGING` / `JUSTSIGN_REKOR_STAGING` pattern in
//!   sibling crates).
//! - `JUSTSIGN_TUF_BOOTSTRAP=<path>` — path to a trusted
//!   `1.root.json` that the test will use as its bootstrap. Caller
//!   is responsible for verifying this file out-of-band (a single
//!   audited copy supplied to the CI runner). We refuse to bake a
//!   Sigstore root into the test binary — bootstrap is a separate
//!   attack-surface decision.
//!
//! When set, the test:
//!
//! 1. Reads the bootstrap root from disk.
//! 2. Builds a `TufClient::sigstore(<temp_cache>)`.
//! 3. Walks the chained-root chain (`fetch_root`).
//! 4. Fetches + verifies timestamp, snapshot, and targets in order.
//! 5. Asserts the final root version is >= bootstrap version.
//! 6. Asserts the targets map is non-empty (Sigstore's repo always
//!    distributes at least the Fulcio / Rekor trust roots).
//!
//! # Bug class caught
//!
//! Drift between the spec we implement and what Sigstore's actual
//! repo serves: a key-type the unit suite doesn't model, a hash
//! algorithm name the cross-check doesn't recognise, a signature
//! over a `signed` shape that disagrees with our canonicaliser by
//! one byte. Unit tests prove our encoder is internally consistent;
//! only a live call surfaces upstream changes. Driving this on
//! every CI run would burn quota, so it lives in the `staging`
//! workflow (manual dispatch) — see `.github/workflows/staging.yml`.

use std::fs;

use tuf::TufClient;

#[test]
fn test_tuf_client_walks_real_sigstore_chain_when_configured() {
    if std::env::var("JUSTSIGN_TUF_LIVE").as_deref() != Ok("1") {
        eprintln!("SKIP: JUSTSIGN_TUF_LIVE != 1 — live Sigstore TUF integration test skipped");
        return;
    }

    let bootstrap_path = match std::env::var("JUSTSIGN_TUF_BOOTSTRAP") {
        Ok(p) if !p.is_empty() => p,
        _ => {
            eprintln!(
                "SKIP: JUSTSIGN_TUF_BOOTSTRAP unset or empty — cannot bootstrap chain without a \
                 trusted initial root.json"
            );
            return;
        }
    };

    let bootstrap_bytes = fs::read(&bootstrap_path)
        .unwrap_or_else(|e| panic!("read bootstrap {bootstrap_path}: {e}"));

    // The bootstrap on disk is the full envelope (`{signed,
    // signatures}`); we want just the signed body for the typed
    // Root the client expects as its starting point.
    let v: serde_json::Value = serde_json::from_slice(&bootstrap_bytes).expect("bootstrap is JSON");
    let signed = v
        .get("signed")
        .cloned()
        .expect("bootstrap has `signed` field");
    let initial_root: tuf::Root = serde_json::from_value(signed).expect("parse initial root");

    let cache_dir = std::env::temp_dir().join(format!(
        "swe_justsign_tuf-live-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));

    let client = TufClient::sigstore(&cache_dir).expect("sigstore client builds");

    let final_root = client
        .fetch_root(&initial_root)
        .expect("chained-root walk against live Sigstore must succeed");
    assert!(
        final_root.version >= initial_root.version,
        "final root version {} regressed below bootstrap {}",
        final_root.version,
        initial_root.version
    );

    let timestamp = client
        .fetch_timestamp(&final_root)
        .expect("fetch_timestamp must succeed against live mirror");

    let snapshot = client
        .fetch_snapshot(&final_root, &timestamp)
        .expect("fetch_snapshot must succeed (incl. timestamp -> snapshot hash check)");

    let targets = client
        .fetch_targets(&final_root, &snapshot)
        .expect("fetch_targets must succeed (incl. snapshot -> targets hash check)");

    assert!(
        !targets.targets.is_empty(),
        "Sigstore targets.json must list at least one artefact"
    );

    let _ = fs::remove_dir_all(&cache_dir);
}
