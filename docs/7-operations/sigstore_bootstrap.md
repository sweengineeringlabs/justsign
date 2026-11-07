# Sigstore TUF root: operator runbook

**Audience**: Operators and release engineers who run justsign and need to confirm, refresh, override, or recover the Sigstore trust root it ships with.

> **TLDR**: justsign embeds one Sigstore production TUF root and walks forward from it. That root **expires** (v14 did, on 2026-06-22, and broke every build). A monthly workflow opens a refresh PR; if you are ever stuck on an expired root, fetch the current root, verify it against two independent sources, and pass it to `TufClient::with_initial_root_bytes`.

## 1. What justsign trusts

The bootstrap trust anchor is `tuf/assets/sigstore_prod.root.json`, compiled in as `tuf::SIGSTORE_PRODUCTION_ROOT_BYTES`. Alongside it, `tuf/src/embedded.rs` records `SIGSTORE_PRODUCTION_ROOT_VERSION`, `_SHA256`, `_SOURCE` and `_FETCHED_AT`. `TufClient::sigstore()` starts from it and follows Sigstore's signed root chain to the current root. The decision and its trade-offs are in [ADR-001](../3-design/adr/001_sigstore_tuf_bootstrap.md).

The embedded root only needs to be a valid *ancestor* of the current root, not the newest. It does need to be **unexpired**: `build.rs` fails the build on an expired asset (and warns within 30 days), and `sigstore()` returns `TufError::EmbeddedRootExpired` at runtime.

## 2. Confirm what you have

From a source checkout (read-only; changes nothing):

```sh
python3 scripts/sigstore_root_refresh.py
```

It prints the embedded version, its expiry and days left, and the newest version on the Sigstore mirror, after cross-checking the mirror against GitHub. `"update_available": true` means a refresh is due.

To check by hand, compare three SHA-256 values; they must be identical (substitute your version for `16`):

```sh
sha256sum tuf/assets/sigstore_prod.root.json
curl -fsS https://tuf-repo-cdn.sigstore.dev/16.root.json | sha256sum
curl -fsS https://raw.githubusercontent.com/sigstore/root-signing/main/metadata/root_history/16.root.json | sha256sum
```

From a compiled consumer, read `tuf::SIGSTORE_PRODUCTION_ROOT_VERSION` and `tuf::SIGSTORE_PRODUCTION_ROOT_SHA256`. Do not rely on the number alone; compare the hash. If the CDN and GitHub hashes differ, **stop** and treat it as an incident: report it to Sigstore and do not refresh.

## 3. Normal refresh (automated)

`.github/workflows/sigstore_root_watch.yml` runs at 06:00 UTC on the 1st of each month, and on demand. When Sigstore has published a newer root it:

1. requires the CDN and GitHub copies to be byte-identical (otherwise it fails and opens nothing);
2. replaces the asset and the `embedded.rs` constants;
3. runs `cargo build`, the tuf tests, and the real client walking the signature chain from the **old** root to the new one against the live mirror;
4. opens a PR whose body lists both hashes.

Review the hashes in the PR body, then merge. A PR opened by `GITHUB_TOKEN` does not start CI by itself: push an empty commit or re-run checks before merging.

If Sigstore has **not** rotated and the embedded root has under 60 days left, the run fails on purpose. That failure is the warning; there is nothing to merge until Sigstore publishes a new root.

## 4. Override the bundled root

Use `TufClient::with_initial_root_bytes` when you must not trust the bundled root: air-gapped hosts, a private mirror, or a pipeline that audits the root out-of-band.

```rust
use tuf::TufClient;

let root_bytes = std::fs::read("audited.root.json")?;
let client = TufClient::with_initial_root_bytes(
    &root_bytes,
    "https://tuf-repo-cdn.sigstore.dev", // or your mirror
    cache_dir,
)?;
let latest = client.fetch_root_from_bootstrap()?; // walks the signed chain
```

The constructor parses the root and rejects an expired one. It does **not** verify signatures, because the bootstrap root *is* the trust anchor. Whoever supplies the bytes is vouching for them.

## 5. Recovery: the bundled root has expired

Symptoms: `cargo build` panics with "embedded TUF asset … has expired", or a deployed binary returns `TufError::EmbeddedRootExpired`.

**Waiting for a patch release is the default.** To recover sooner:

1. Fetch the current root: `curl -fsS https://tuf-repo-cdn.sigstore.dev/<N>.root.json`, walking `<N>` upward until a 404 (the script in §2 does this).
2. Verify it with the three-way hash comparison in §2.
3. Pass it to `with_initial_root_bytes` as in §4.

The new root must itself be unexpired, and an old ancestor will not work: it is rejected as expired. For a source build, run `python3 scripts/sigstore_root_refresh.py --apply`, review the diff, then build.

## 6. Not yet available

There is no `justsign tuf-root verify` command (issue #35) and no cross-check against cosign's bundled root (issue #34). Until they exist, §2 and §5 are manual.
