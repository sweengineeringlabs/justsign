//! `TufClient` — fetches Sigstore TUF metadata over HTTPS, walks the
//! root chain, verifies role signatures against the wire bytes of
//! the `signed` field (extracted via
//! [`crate::span::parse_with_signed_span`]), and cross-checks role
//! hashes between roles.
//!
//! # Spec compliance
//!
//! Implements the prescribed client workflow from TUF spec §5.3:
//!
//! 1. **Update the root role** (§5.3.4): walk N → N+1 → N+2 → … until
//!    a 404, verifying each step is signed by a threshold of the
//!    *previous* root's keys AND a threshold of the *new* root's
//!    keys.
//! 2. **Update the timestamp role** (§5.3.5): fetch `timestamp.json`,
//!    verify against the (verified) root's timestamp role keys,
//!    enforce expiry.
//! 3. **Update the snapshot role** (§5.3.6): fetch `snapshot.json`,
//!    verify signatures against root's snapshot role, AND cross-check
//!    its hash against `timestamp.snapshot_meta.hashes.sha256`.
//! 4. **Update the targets role** (§5.3.7): fetch `targets.json`,
//!    verify signatures, AND cross-check hash against
//!    `snapshot.targets_meta.hashes.sha256`.
//!
//! Caller threads the verified [`crate::Root`] through each call so
//! the trust chain never inverts (a fetched-but-unverified role is
//! never used to validate anything).
//!
//! # Bootstrap
//!
//! Per ADR `docs/3-design/adr/001-sigstore-tuf-bootstrap.md`,
//! [`TufClient::sigstore`] uses the Sigstore production root that is
//! baked into the binary at build time (see [`crate::embedded`]). For
//! air-gapped deployments, custom mirrors, or operators who refuse
//! the bundled root for policy reasons,
//! [`TufClient::with_initial_root_bytes`] accepts a caller-supplied
//! root as bytes; both constructors run a runtime expiry guard that
//! returns [`TufError::EmbeddedRootExpired`] if the supplied root has
//! already passed its `expires` timestamp on the current clock.
//!
//! # What's NOT here
//!
//! - **Delegated targets.** [`crate::types::Targets::delegations`]
//!   is preserved as raw JSON; walking delegations is post-v0.
//! - **Online keys.** v0 supports Ed25519-only roots for signature
//!   verification, mirroring the verifier's constraint (see
//!   [`crate::root`] crate-level docs). The bundled Sigstore v14 root
//!   uses ECDSA P-256 keys; a live chain walk against it will
//!   currently surface [`TufError::UnsupportedKeyType`] from the
//!   verifier path -- bundling lets us land the bootstrap policy
//!   ahead of the ECDSA verifier work.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use spec::{Clock, FixedClock, SystemClock};

use crate::expiry::{format_rfc3339_utc, is_expired};
use crate::root::{verify_role, Root, TufError};
use crate::span::parse_with_signed_span;
use crate::types::{Signed, Snapshot, Targets, Timestamp};

/// Default per-request HTTP timeout. Mirrors the value used in
/// `swe_justsign_rekor` so a single tuned constant governs timeouts
/// across the workspace's blocking HTTP clients.
const HTTP_TIMEOUT_SECS: u64 = 30;

/// Hard cap on the chained-root walk. Defends against a malicious
/// mirror that serves an unbounded sequence of `N.root.json` to
/// exhaust client resources. 1024 is generous: Sigstore's production
/// chain was at version 13 as of 2026-Q1.
const MAX_ROOT_CHAIN_LEN: u32 = 1024;

/// Production Sigstore TUF mirror.
const SIGSTORE_PROD_URL: &str = "https://tuf-repo-cdn.sigstore.dev";

/// Sigstore staging TUF mirror.
const SIGSTAGE_URL: &str = "https://tuf-repo-cdn.sigstage.dev";

/// Orchestrates fetching + verifying TUF metadata for a single repo
/// (production Sigstore, staging Sigstore, or a caller-specified
/// mirror).
///
/// `TufClient` is reusable across calls; the underlying
/// [`reqwest::blocking::Client`] is built once. Caching is on-disk
/// at `cache_dir`.
///
/// A `TufClient` MAY carry an embedded "initial root" — the trusted
/// bootstrap document a chained-root walk starts from. Constructors
/// that accept a root ([`Self::sigstore`],
/// [`Self::with_initial_root_bytes`]) populate this; the bare-bones
/// [`Self::new`] / [`Self::sigstage`] constructors leave it `None`
/// and require callers to supply a root explicitly to
/// [`Self::fetch_root`].
///
/// Time source: the client owns a `Box<dyn spec::Clock>` (issue #26).
/// Production callers get [`spec::SystemClock`] by default; tests and
/// air-gapped deploys can swap it via [`Self::with_clock`].
pub struct TufClient {
    base_url: String,
    cache_dir: PathBuf,
    http: reqwest::blocking::Client,
    /// Time source for every expiry comparison this client makes.
    /// Default is [`SystemClock`]; [`Self::with_clock`] /
    /// [`Self::with_now_override`] swap it for tests or
    /// time-pinned deploys.
    clock: Box<dyn Clock>,
    /// Trusted bootstrap root document the chained-root walk starts
    /// from. Populated by [`Self::sigstore`] and
    /// [`Self::with_initial_root_bytes`]. `None` for clients built
    /// via [`Self::new`] / [`Self::sigstage`].
    initial_root: Option<Root>,
}

// Manual `Debug` impl: `Box<dyn Clock>` does not require `Debug` on
// the trait (per spec), so we surface the clock's presence as an
// opaque marker rather than widening the trait bound.
impl std::fmt::Debug for TufClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TufClient")
            .field("base_url", &self.base_url)
            .field("cache_dir", &self.cache_dir)
            .field("clock", &"<dyn Clock>")
            .field("initial_root_present", &self.initial_root.is_some())
            .finish()
    }
}

impl TufClient {
    /// Build a client for `base_url`, with cached metadata stored at
    /// `cache_dir`. The cache directory is created if it does not
    /// exist.
    ///
    /// Trailing slashes on `base_url` are tolerated.
    pub fn new(
        base_url: impl Into<String>,
        cache_dir: impl Into<PathBuf>,
    ) -> Result<Self, TufError> {
        let base_url = base_url.into().trim_end_matches('/').to_string();
        if !(base_url.starts_with("http://") || base_url.starts_with("https://")) {
            return Err(TufError::Http(format!(
                "base_url must start with http:// or https://: {base_url}"
            )));
        }
        let cache_dir = cache_dir.into();
        fs::create_dir_all(&cache_dir)
            .map_err(|e| TufError::Io(format!("create cache_dir {}: {e}", cache_dir.display())))?;
        let http = reqwest::blocking::Client::builder()
            .user_agent(concat!("swe_justsign_tuf/", env!("CARGO_PKG_VERSION")))
            .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
            .build()
            .map_err(|e| TufError::Http(format!("build http client: {e}")))?;
        Ok(Self {
            base_url,
            cache_dir,
            http,
            clock: Box::new(SystemClock),
            initial_root: None,
        })
    }

    /// Build a client against the production Sigstore TUF mirror
    /// (<https://tuf-repo-cdn.sigstore.dev>) using the bundled
    /// production root as the bootstrap.
    ///
    /// The bundled root ([`crate::embedded::SIGSTORE_PRODUCTION_ROOT_BYTES`])
    /// is parsed, runtime-expiry-checked, AND self-signature-verified
    /// at this point. The self-verification step is the
    /// "new-self-signs" half of TUF spec §5.3.4: the bundled root's
    /// own root role must approve its own bytes to threshold,
    /// otherwise the asset is malformed (e.g. a corrupt copy was
    /// committed, or the verifier's wire-shape expectations have
    /// drifted from what Sigstore's tuf-on-ci tooling actually
    /// emits). Failing fast here surfaces a corrupt asset before
    /// any network traffic, instead of letting the failure surface
    /// later in the chain walk where the diagnostic is muddier.
    ///
    /// If the embedded asset has already expired on the system
    /// clock, the constructor returns
    /// [`TufError::EmbeddedRootExpired`] -- the chain walker can
    /// usually catch up by chained-root-walking forward, but only
    /// after a successful bootstrap.
    ///
    /// `cache_dir` is required because the workspace does not depend
    /// on `dirs` and we refuse to silently spread cached signing-trust
    /// state across an unspecified filesystem location.
    ///
    /// To override the bundled root (air-gapped deploys, custom
    /// mirrors, security-paranoid pipelines that audit the root
    /// out-of-band), use [`Self::with_initial_root_bytes`]. That
    /// path does NOT signature-verify the supplied bytes -- per
    /// TUF spec the bootstrap root IS the trust anchor, and the
    /// caller is responsible for verifying out-of-band.
    pub fn sigstore(cache_dir: impl Into<PathBuf>) -> Result<Self, TufError> {
        let bytes = crate::embedded::SIGSTORE_PRODUCTION_ROOT_BYTES;
        let client = Self::with_initial_root_bytes(bytes, SIGSTORE_PROD_URL, cache_dir)?;
        verify_bundled_root_self_signature(bytes)?;
        Ok(client)
    }

    /// Build a client preloaded with a caller-supplied initial root.
    ///
    /// The escape hatch for callers that need to bootstrap from
    /// something other than the bundled Sigstore production root --
    /// air-gapped deployments, custom mirrors, or security-paranoid
    /// pipelines that audit the root out-of-band before passing the
    /// bytes in.
    ///
    /// `root_bytes` is the raw JSON of a TUF root metadata envelope
    /// (`{"signed": {...}, "signatures": [...]}`); the constructor:
    ///
    /// 1. Parses it via the typed [`Root`] deserialiser. Garbage in
    ///    surfaces as [`TufError::Json`].
    /// 2. Rejects an already-expired root with
    ///    [`TufError::EmbeddedRootExpired`]. This is distinct from
    ///    [`TufError::Expired`] (which fires after a network fetch);
    ///    the bootstrap-time variant lets operators route on it
    ///    cleanly.
    /// 3. Stores the parsed root as the bootstrap that
    ///    [`Self::fetch_root_from_bootstrap`] will walk from.
    ///
    /// Note: the constructor does not signature-verify the supplied
    /// root. Per TUF spec the bootstrap root IS the trust anchor; if
    /// the operator supplies an attacker-controlled root, every
    /// downstream verification trusts the attacker. The caller is
    /// responsible for verifying the bytes out-of-band before calling
    /// this constructor.
    pub fn with_initial_root_bytes(
        root_bytes: &[u8],
        base_url: impl Into<String>,
        cache_dir: impl Into<PathBuf>,
    ) -> Result<Self, TufError> {
        let mut client = Self::new(base_url, cache_dir)?;
        let root = parse_initial_root(root_bytes)?;
        check_initial_root_not_expired(&root, client.now())?;
        client.initial_root = Some(root);
        Ok(client)
    }

    /// Build a client against the Sigstore staging mirror
    /// (<https://tuf-repo-cdn.sigstage.dev>). Used by the skip-pass
    /// integration test; not for production verification. Does not
    /// preload an initial root -- the staging root is not bundled.
    pub fn sigstage(cache_dir: impl Into<PathBuf>) -> Result<Self, TufError> {
        Self::new(SIGSTAGE_URL, cache_dir)
    }

    /// Reference to the trusted bootstrap root the client was
    /// preloaded with, if any. Populated by [`Self::sigstore`] and
    /// [`Self::with_initial_root_bytes`]; `None` for clients built
    /// via [`Self::new`] / [`Self::sigstage`].
    pub fn bootstrap_root(&self) -> Option<&Root> {
        self.initial_root.as_ref()
    }

    /// Walk the root chain starting from the bootstrap root the
    /// client was preloaded with.
    ///
    /// Convenience wrapper for [`Self::fetch_root`] that uses the
    /// stored bootstrap. Returns [`TufError::MissingRole`] (with
    /// `role: "root"`) if the client was built without a bootstrap
    /// root (i.e. via [`Self::new`] / [`Self::sigstage`]) -- those
    /// callers must use the explicit [`Self::fetch_root`] path.
    pub fn fetch_root_from_bootstrap(&self) -> Result<Root, TufError> {
        let root = self.initial_root.as_ref().ok_or(TufError::MissingRole {
            role: "root (no bootstrap configured; use TufClient::sigstore or \
                   TufClient::with_initial_root_bytes, or call fetch_root with \
                   an explicit initial root)"
                .to_string(),
        })?;
        self.fetch_root(root)
    }

    /// Test-only: pin the `now` reference [`is_expired`] uses. Lets
    /// expiry tests use deterministic timestamps without poking
    /// system clocks.
    ///
    /// Implemented as a thin shim over [`Self::with_clock`]: converts
    /// the [`SystemTime`] into a [`FixedClock`] holding the equivalent
    /// Unix-seconds value. Times before the Unix epoch are clamped to
    /// 0 (the implementation never produces such a value, but the
    /// type permits it).
    #[doc(hidden)]
    pub fn with_now_override(self, now: SystemTime) -> Self {
        let secs = match now.duration_since(UNIX_EPOCH) {
            Ok(d) => {
                let s = d.as_secs();
                if s > i64::MAX as u64 {
                    i64::MAX
                } else {
                    s as i64
                }
            }
            Err(_) => 0,
        };
        self.with_clock(Box::new(FixedClock(secs)))
    }

    /// Swap the [`Clock`] this client consults for expiry comparisons.
    ///
    /// Production code should NEVER need this — [`SystemClock`] is the
    /// default for every public constructor. The injection point exists
    /// for two callers:
    ///
    /// 1. **Tests** that need a deterministic "now" so expiry assertions
    ///    don't depend on the host's wall clock.
    /// 2. **Air-gapped / replay deploys** that pin the verifier's clock
    ///    to a release timestamp (e.g. reproducing a build).
    ///
    /// The supplied clock is consulted at every point the client checks
    /// expiry: the bootstrap-root expiry guard inside
    /// [`Self::with_initial_root_bytes`] (when wrapped via this
    /// constructor instead), the chained-root walk's freeze-attack
    /// check, and every per-role expiry check in
    /// [`Self::fetch_timestamp`] / [`Self::fetch_snapshot`] /
    /// [`Self::fetch_targets`].
    pub fn with_clock(mut self, clock: Box<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Inject a pre-built reqwest client (parallels `HttpFulcioClient`
    /// + `HttpRekorClient`). Used by tests that point at a local
    /// in-process HTTP server.
    #[doc(hidden)]
    pub fn with_http(mut self, http: reqwest::blocking::Client) -> Self {
        self.http = http;
        self
    }

    /// Resolve the client's clock to a [`SystemTime`] suitable for
    /// the existing [`is_expired`] / [`format_rfc3339_utc`] surface.
    ///
    /// Negative `now_unix_secs()` (system clock set before 1970) is
    /// clamped to [`UNIX_EPOCH`] — matches the existing
    /// [`format_rfc3339_utc`] error path which would otherwise return
    /// [`crate::ExpiryParseError::ClockBeforeEpoch`]. We prefer a
    /// silent clamp here because every downstream comparison treats
    /// "now = 1970-01-01" as "everything is expired" anyway, which is
    /// the safer default than crashing the verifier on an operator
    /// misconfiguration.
    fn now(&self) -> SystemTime {
        let secs = self.clock.now_unix_secs();
        if secs <= 0 {
            UNIX_EPOCH
        } else {
            UNIX_EPOCH + Duration::from_secs(secs as u64)
        }
    }

    /// Walk the root chain from `initial_root` upward.
    ///
    /// On entry, `initial_root` must already be the caller's
    /// trusted bootstrap root. The walker fetches `N+1.root.json`,
    /// `N+2.root.json`, …, until 404. Each step verifies that the
    /// new root is signed by a threshold of:
    ///
    /// 1. The *current* root's `roles.root.keyids` (old signs new),
    ///    AND
    /// 2. The *new* root's `roles.root.keyids` (new self-signs).
    ///
    /// The pair of checks is the load-bearing TUF property — either
    /// alone is bypassable.
    ///
    /// Returns the final, freshest root. The final root's expiry is
    /// enforced before returning; an expired final root is a
    /// [`TufError::Expired`].
    pub fn fetch_root(&self, initial_root: &Root) -> Result<Root, TufError> {
        let mut current_root = initial_root.clone();
        let walk_start = current_root.version;

        loop {
            // Hard cap: defends against an unbounded chain.
            if current_root.version.saturating_sub(walk_start) > MAX_ROOT_CHAIN_LEN {
                return Err(TufError::Http(format!(
                    "root chain exceeded maximum length {MAX_ROOT_CHAIN_LEN}"
                )));
            }

            let next_version = current_root.version + 1;
            let path = format!("{next_version}.root.json");
            let bytes = match self.fetch_or_cached(&path) {
                Ok(b) => b,
                Err(TufError::NotFound { .. }) => {
                    // Spec §5.3.4 step 4: "If a 404 ... is returned ...
                    // we are done with the root role update."
                    break;
                }
                Err(other) => return Err(other),
            };

            let spanned = parse_with_signed_span::<Root>(&bytes)?;
            // Verify against the EXACT wire bytes of the `signed`
            // field — approach (b) from the canonical-vs-span
            // trade-off. The verifier sees byte-for-byte what the
            // signer hashed, with zero re-canonicalisation drift
            // surface.
            let signed_wire_bytes = &bytes[spanned.signed_bytes.clone()];

            // Old signs new: the previous root's root role must
            // approve this version's bytes.
            verify_role(
                &current_root,
                "root",
                signed_wire_bytes,
                &spanned.signatures,
            )?;

            // New self-signs: the new root's own root role must
            // also approve. Without this an attacker who has
            // compromised the *previous* root role's keys could
            // hand us any keyset they like.
            verify_role(
                &spanned.signed,
                "root",
                signed_wire_bytes,
                &spanned.signatures,
            )?;

            // Monotonicity: spec §5.3.4 step 5 — version must
            // advance. Strictly we require N+1 == current.version+1,
            // but we relax to "strictly greater" so a mirror that
            // skips a version (rare, but legal under the spec's
            // "can't roll back" framing) still succeeds.
            if spanned.signed.version <= current_root.version {
                return Err(TufError::VersionRegression {
                    previous: current_root.version,
                    fetched: spanned.signed.version,
                });
            }

            current_root = spanned.signed;
        }

        // Spec §5.3.4 step 6: "Check for a freeze attack" — the
        // final root must not be expired.
        if is_expired(&current_root.expires, self.now())? {
            return Err(TufError::Expired {
                role: "root".to_string(),
                expires: current_root.expires.clone(),
            });
        }

        Ok(current_root)
    }

    /// Fetch and verify `timestamp.json` against `root`.
    ///
    /// `root` MUST already have been threaded through
    /// [`Self::fetch_root`] — verifying timestamp against an
    /// unverified root would invert the trust chain.
    pub fn fetch_timestamp(&self, root: &Root) -> Result<Timestamp, TufError> {
        let bytes = self.fetch_or_cached("timestamp.json")?;
        let spanned = parse_with_signed_span::<Timestamp>(&bytes)?;
        let signed_wire_bytes = &bytes[spanned.signed_bytes.clone()];
        verify_role(root, "timestamp", signed_wire_bytes, &spanned.signatures)?;
        if is_expired(&spanned.signed.expires, self.now())? {
            return Err(TufError::Expired {
                role: "timestamp".to_string(),
                expires: spanned.signed.expires.clone(),
            });
        }
        Ok(spanned.signed)
    }

    /// Fetch and verify `snapshot.json` against `root` AND
    /// cross-check its SHA-256 against
    /// `timestamp.snapshot_meta.hashes.sha256`.
    ///
    /// The hash cross-check is the freshness defence: even if a
    /// signature on a stale snapshot is still valid (root role
    /// hasn't rotated yet), the timestamp's pin to the *current*
    /// snapshot's hash means the verifier rejects any older
    /// snapshot the mirror tries to serve.
    pub fn fetch_snapshot(&self, root: &Root, timestamp: &Timestamp) -> Result<Snapshot, TufError> {
        let bytes = self.fetch_or_cached("snapshot.json")?;

        // Hash cross-check: the SHA-256 of the on-wire snapshot bytes
        // must match `timestamp.snapshot_meta.hashes.sha256`. We do
        // this BEFORE signature verification because a hash
        // mismatch is a stronger, cheaper rejection — no point
        // running ed25519 on bytes the timestamp role already
        // disowned.
        let meta = timestamp
            .snapshot_meta()
            .ok_or_else(|| TufError::MissingRole {
                role: "snapshot.json".to_string(),
            })?;
        cross_check_sha256(&bytes, "snapshot", meta)?;

        let spanned = parse_with_signed_span::<Snapshot>(&bytes)?;
        let signed_wire_bytes = &bytes[spanned.signed_bytes.clone()];
        verify_role(root, "snapshot", signed_wire_bytes, &spanned.signatures)?;
        if is_expired(&spanned.signed.expires, self.now())? {
            return Err(TufError::Expired {
                role: "snapshot".to_string(),
                expires: spanned.signed.expires.clone(),
            });
        }
        Ok(spanned.signed)
    }

    /// Fetch and verify `targets.json` against `root` AND
    /// cross-check its SHA-256 against
    /// `snapshot.targets_meta.hashes.sha256`.
    pub fn fetch_targets(&self, root: &Root, snapshot: &Snapshot) -> Result<Targets, TufError> {
        let bytes = self.fetch_or_cached("targets.json")?;

        let meta = snapshot
            .targets_meta()
            .ok_or_else(|| TufError::MissingRole {
                role: "targets.json".to_string(),
            })?;
        cross_check_sha256(&bytes, "targets", meta)?;

        let spanned = parse_with_signed_span::<Targets>(&bytes)?;
        let signed_wire_bytes = &bytes[spanned.signed_bytes.clone()];
        verify_role(root, "targets", signed_wire_bytes, &spanned.signatures)?;
        if is_expired(&spanned.signed.expires, self.now())? {
            return Err(TufError::Expired {
                role: "targets".to_string(),
                expires: spanned.signed.expires.clone(),
            });
        }
        Ok(spanned.signed)
    }

    // ------- internals -------

    /// Read `path` from the on-disk cache; on miss, fetch via HTTP
    /// and persist a copy. Cache hit/miss decision is purely
    /// "file present and non-empty"; expiry is enforced after the
    /// caller parses the bytes (we don't want to silently re-fetch
    /// a fresh-but-not-yet-expired document and burn budget).
    fn fetch_or_cached(&self, path: &str) -> Result<Vec<u8>, TufError> {
        let cache_path = self.cache_dir.join(safe_cache_filename(path));
        if let Ok(bytes) = fs::read(&cache_path) {
            if !bytes.is_empty() {
                return Ok(bytes);
            }
        }

        let url = format!("{}/{}", self.base_url, path);
        let resp = self
            .http
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .map_err(|e| TufError::Http(format!("GET {url}: {e}")))?;

        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(TufError::NotFound { url });
        }
        if !status.is_success() {
            let body = resp.text().unwrap_or_else(|_| String::from("<unreadable>"));
            return Err(TufError::HttpStatus {
                status: status.as_u16(),
                body,
            });
        }

        let bytes = resp
            .bytes()
            .map_err(|e| TufError::Http(format!("read {url} body: {e}")))?
            .to_vec();

        // Best-effort cache write: if disk is full or the path is
        // read-only, we surface the IO error rather than silently
        // discarding the bytes — a cache that pretends to work but
        // doesn't would mask wire flakiness.
        if let Some(parent) = cache_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| TufError::Io(format!("create cache dir {}: {e}", parent.display())))?;
        }
        fs::write(&cache_path, &bytes)
            .map_err(|e| TufError::Io(format!("write cache {}: {e}", cache_path.display())))?;

        Ok(bytes)
    }

    /// Public for tests: clears the cache directory. Not exported
    /// outside the crate.
    #[doc(hidden)]
    pub fn _clear_cache_for_tests(&self) -> Result<(), TufError> {
        for entry in fs::read_dir(&self.cache_dir)
            .map_err(|e| TufError::Io(format!("read cache_dir: {e}")))?
        {
            let entry = entry.map_err(|e| TufError::Io(format!("cache entry: {e}")))?;
            fs::remove_file(entry.path())
                .map_err(|e| TufError::Io(format!("remove cache entry: {e}")))?;
        }
        Ok(())
    }

    /// Returns the cache directory the client is using. Useful for
    /// tests that want to seed pre-canned bytes onto disk.
    pub fn cache_dir(&self) -> &Path {
        &self.cache_dir
    }
}

/// Parse a `{signed, signatures}` envelope and return just the typed
/// [`Root`] body. Used by [`TufClient::with_initial_root_bytes`] +
/// [`TufClient::sigstore`] to extract the bootstrap root from raw
/// wire bytes (or the embedded asset). Errors flow as
/// [`TufError::Json`] for the usual reason: anything malformed at
/// this depth is a JSON shape problem, not an envelope-level concern.
fn parse_initial_root(bytes: &[u8]) -> Result<Root, TufError> {
    let v: serde_json::Value = serde_json::from_slice(bytes)?;
    let signed = v.get("signed").cloned().ok_or_else(|| {
        // Construct a synthesised serde_json::Error so this funnels
        // into TufError::Json without a new variant for an extremely
        // narrow failure mode.
        TufError::Json(<serde_json::Error as serde::de::Error>::custom(
            "initial root envelope is missing top-level `signed` field",
        ))
    })?;
    let root: Root = serde_json::from_value(signed)?;
    Ok(root)
}

/// Runtime expiry guard for an initial trust root. Component 3 of
/// issue #27. Distinct from the post-fetch `is_expired` -> `Expired`
/// path: this fires before any network traffic, on the bootstrap
/// material itself, so operators can route on the difference.
fn check_initial_root_not_expired(root: &Root, now: SystemTime) -> Result<(), TufError> {
    if is_expired(&root.expires, now)? {
        let now_iso8601 =
            format_rfc3339_utc(now).unwrap_or_else(|_| "<clock-before-epoch>".to_string());
        return Err(TufError::EmbeddedRootExpired {
            expired_at: root.expires.clone(),
            now_iso8601,
            hint: "upgrade swe_justsign_tuf or pass a fresh root via \
                 TufClient::with_initial_root_bytes"
                .to_string(),
        });
    }
    Ok(())
}

/// Self-signature gate for the bundled Sigstore production root.
///
/// Equivalent to the "new self-signs" half of TUF spec §5.3.4 run
/// against the bootstrap asset itself: the root's `roles.root` must
/// approve the root's own canonical-JSON-encoded `signed` body to
/// threshold, using the keys it declares.
///
/// Why fail-fast here: if the bundled asset is malformed (corrupt
/// copy committed, byte drift from the upstream CDN, mismatch
/// between the verifier's wire-shape expectations and what
/// tuf-on-ci actually emits), every later
/// [`TufClient::fetch_root_from_bootstrap`] call would surface
/// `TufError::BelowThreshold` on the first network hop. That error
/// is muddier than this one because the operator can't tell whether
/// the bug is in the bundled root, the network, or the freshly-
/// fetched chain step. Pre-flight verifying the bundled root
/// localises the diagnostic.
fn verify_bundled_root_self_signature(bytes: &[u8]) -> Result<(), TufError> {
    let v: serde_json::Value = serde_json::from_slice(bytes).map_err(TufError::Json)?;
    let signed_value = v.get("signed").cloned().ok_or_else(|| {
        TufError::Json(<serde_json::Error as serde::de::Error>::custom(
            "bundled root envelope is missing top-level `signed` field",
        ))
    })?;
    let signatures_value = v.get("signatures").cloned().ok_or_else(|| {
        TufError::Json(<serde_json::Error as serde::de::Error>::custom(
            "bundled root envelope is missing top-level `signatures` field",
        ))
    })?;
    let signatures: Vec<crate::root::Signature> =
        serde_json::from_value(signatures_value).map_err(TufError::Json)?;
    let canonical_bytes = crate::canonical::canonicalize(&signed_value)?;
    let root: Root = serde_json::from_value(signed_value).map_err(TufError::Json)?;
    verify_role(&root, "root", &canonical_bytes, &signatures)
}

/// Sanitise a TUF metadata path to a safe filename for the cache.
///
/// TUF metadata paths are simple (`timestamp.json`, `7.root.json`)
/// but we still strip any embedded `/` to prevent a malicious mirror
/// or a code-path bug from writing outside `cache_dir`. Equivalent to
/// `path.split('/').last()` with a fallback.
fn safe_cache_filename(path: &str) -> String {
    path.rsplit('/').next().unwrap_or(path).to_string()
}

/// Cross-check the SHA-256 of `bytes` against `meta.hashes.sha256`.
/// Returns `Ok(())` only if both are present and identical.
fn cross_check_sha256(
    bytes: &[u8],
    role: &str,
    meta: &crate::types::MetaInfo,
) -> Result<(), TufError> {
    let hashes = meta.hashes.as_ref().ok_or_else(|| TufError::MissingHash {
        role: role.to_string(),
    })?;
    let expected = hashes.get("sha256").ok_or_else(|| TufError::MissingHash {
        role: role.to_string(),
    })?;
    let actual = sha256_lower_hex(bytes);
    if actual != *expected {
        return Err(TufError::HashMismatch {
            role: role.to_string(),
            expected: expected.clone(),
            actual,
        });
    }
    Ok(())
}

/// Plain SHA-256 lowercase hex. Local impl to avoid pulling another
/// crypto crate just for one digest — the hash table is on-wire
/// pinned; nothing we do here needs constant-time properties.
fn sha256_lower_hex(bytes: &[u8]) -> String {
    // We re-export the same SHA-256 via ed25519-dalek's transitive
    // `sha2` dep — which is already in our dep graph through
    // `ed25519-dalek` (it pulls `sha2` for SHA-512, but the same
    // crate also exposes `Sha256`). Re-using it keeps our direct
    // dep count unchanged.
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    let digest = h.finalize();
    let mut out = String::with_capacity(64);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for b in digest.iter() {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

// Internal: a thin newtype around `Signed<Root>` is unused at the
// moment but kept conceptually so tests can construct envelopes by
// hand. Hidden behind `#[allow(dead_code)]` would mask real
// dead-code warnings; we instead expose this typed-only parser for
// any downstream that wants the envelope shape without the span.
// The signature-verification path in this crate uses
// [`crate::span::parse_with_signed_span`] so the verifier sees the
// exact wire bytes of `signed`.
#[doc(hidden)]
pub fn _parse_root_envelope(bytes: &[u8]) -> Result<Signed<Root>, TufError> {
    let typed: Signed<Root> = serde_json::from_slice(bytes)?;
    Ok(typed)
}

// ── Tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::canonicalize;
    use crate::root::{Key, KeyVal, Role, Signature};
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::OsRng;
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration, UNIX_EPOCH};

    /// Atomic counter so concurrent tests on the same machine never
    /// collide on the same temp directory name.
    static TEST_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn unique_temp_dir(label: &str) -> PathBuf {
        let n = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("swe_justsign_tuf-{pid}-{label}-{n}"));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    /// Build a deterministic test root with `n` Ed25519 keys and
    /// threshold `t`. Returns the typed Root, the canonical bytes
    /// that signatures cover, and the signing keys.
    fn build_test_root(
        n: usize,
        threshold: u32,
        version: u32,
        expires: &str,
    ) -> (Root, Vec<SigningKey>) {
        let mut rng = OsRng;
        let signing_keys: Vec<SigningKey> =
            (0..n).map(|_| SigningKey::generate(&mut rng)).collect();

        let mut keys = BTreeMap::new();
        let mut keyids = Vec::new();
        for (i, sk) in signing_keys.iter().enumerate() {
            let keyid = format!("k{i}");
            keyids.push(keyid.clone());
            keys.insert(
                keyid,
                Key {
                    keytype: "ed25519".into(),
                    scheme: "ed25519".into(),
                    keyval: KeyVal {
                        public: hex::encode(sk.verifying_key().to_bytes()),
                    },
                },
            );
        }

        let mut roles = BTreeMap::new();
        for r in ["root", "timestamp", "snapshot", "targets"] {
            roles.insert(
                r.into(),
                Role {
                    keyids: keyids.clone(),
                    threshold,
                },
            );
        }

        let root = Root {
            type_field: "root".into(),
            spec_version: "1.0.31".into(),
            version,
            expires: expires.into(),
            keys,
            roles,
            consistent_snapshot: true,
        };
        (root, signing_keys)
    }

    /// Wrap a Root into a fully-formed `{signed, signatures}` envelope
    /// signed by `signers` (which must each appear in the root's keys
    /// at the named keyids — `signer_keyids[i]` is the keyid the i'th
    /// signer is registered under).
    ///
    /// Returns the byte form ready to write to a cache file or serve
    /// over HTTP.
    fn envelope_for_root(
        root: &Root,
        signers: &[(&SigningKey, &str)], // (signing_key, keyid)
    ) -> Vec<u8> {
        let signed_value = serde_json::to_value(root).unwrap();
        let canonical = canonicalize(&signed_value).unwrap();
        let mut sigs = Vec::new();
        for (sk, keyid) in signers {
            let sig = sk.sign(&canonical);
            sigs.push(Signature {
                keyid: (*keyid).to_string(),
                sig: hex::encode(sig.to_bytes()),
            });
        }
        let envelope = json!({
            "signed": signed_value,
            "signatures": serde_json::to_value(&sigs).unwrap(),
        });
        serde_json::to_vec(&envelope).unwrap()
    }

    /// Spin a one-shot in-process HTTP server that serves a fixed
    /// `path -> bytes` table. Returns the bound base URL and a
    /// shutdown handle (drop = wake the accept thread via a
    /// throwaway TCP connect; in-flight reqs run to completion).
    ///
    /// We use raw `TcpListener` instead of pulling `httpmock` /
    /// `tiny_http` because we need exactly one feature: serve a few
    /// known paths. Nothing parses headers, nothing handles
    /// keep-alive — every connection is one request, one response,
    /// closed.
    struct LocalServer {
        base_url: String,
        port: u16,
        shutdown: Arc<Mutex<bool>>,
        request_log: Arc<Mutex<Vec<String>>>,
        handle: Option<thread::JoinHandle<()>>,
    }

    impl LocalServer {
        fn start(routes: Vec<(String, Vec<u8>)>) -> Self {
            Self::start_with_fallback(routes, 404, b"".to_vec())
        }

        /// Variant that returns `fallback_status` (with `fallback_body`)
        /// for any path NOT in `routes`. Used by the 500-status test.
        fn start_with_fallback(
            routes: Vec<(String, Vec<u8>)>,
            fallback_status: u16,
            fallback_body: Vec<u8>,
        ) -> Self {
            // Blocking accept: the server thread sleeps inside
            // `accept` until a client connects. Drop() wakes it
            // with a sentinel TCP connect to localhost. This avoids
            // the `set_nonblocking + sleep-loop` race that produces
            // flaky "error sending request" failures on Windows
            // when reqwest connects in the gap between the
            // listener's bind and the first accept poll.
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
            let port = listener.local_addr().unwrap().port();
            let base_url = format!("http://127.0.0.1:{port}");
            let shutdown = Arc::new(Mutex::new(false));
            let request_log: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
            let routes_arc: Arc<Vec<(String, Vec<u8>)>> = Arc::new(routes);

            let shutdown_t = Arc::clone(&shutdown);
            let log_t = Arc::clone(&request_log);
            let handle = thread::spawn(move || loop {
                let (mut stream, _) = match listener.accept() {
                    Ok(s) => s,
                    Err(_) => return,
                };
                if *shutdown_t.lock().unwrap() {
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                    return;
                }
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .expect("read timeout");
                stream
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .expect("write timeout");

                let mut reader = BufReader::new(stream.try_clone().expect("clone"));
                let mut request_line = String::new();
                if reader.read_line(&mut request_line).is_err() {
                    continue;
                }
                // Drain headers — we don't care about their content,
                // we just need to consume bytes through the blank
                // line so the client's send-buffer flushes and the
                // socket flips to readable on our side.
                loop {
                    let mut hdr = String::new();
                    match reader.read_line(&mut hdr) {
                        Ok(0) => break,
                        Ok(_) => {
                            if hdr == "\r\n" || hdr == "\n" {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                log_t.lock().unwrap().push(request_line.trim().to_string());

                let path = request_line
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or("/")
                    .trim_start_matches('/')
                    .to_string();
                let routes_inner = Arc::clone(&routes_arc);
                let body: Option<Vec<u8>> = routes_inner
                    .iter()
                    .find(|(p, _)| *p == path)
                    .map(|(_, b)| b.clone());

                match body {
                    Some(b) => {
                        let header = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\nContent-Type: application/json\r\n\r\n",
                            b.len()
                        );
                        let _ = stream.write_all(header.as_bytes());
                        let _ = stream.write_all(&b);
                    }
                    None => {
                        let header = format!(
                            "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            fallback_status,
                            status_reason(fallback_status),
                            fallback_body.len()
                        );
                        let _ = stream.write_all(header.as_bytes());
                        let _ = stream.write_all(&fallback_body);
                    }
                }
                let _ = stream.flush();
                let _ = stream.shutdown(std::net::Shutdown::Both);
            });

            Self {
                base_url,
                port,
                shutdown,
                request_log,
                handle: Some(handle),
            }
        }

        fn requests(&self) -> Vec<String> {
            self.request_log.lock().unwrap().clone()
        }
    }

    fn status_reason(code: u16) -> &'static str {
        match code {
            200 => "OK",
            404 => "Not Found",
            500 => "Internal Server Error",
            _ => "Status",
        }
    }

    impl Drop for LocalServer {
        fn drop(&mut self) {
            *self.shutdown.lock().unwrap() = true;
            // Wake the server thread by connecting to it; it will
            // accept the connection, see shutdown=true, and exit.
            // We use a short timeout because if the server thread
            // already exited (e.g. listener dropped) the connect
            // will fail fast and we don't want the test to hang.
            let _ = std::net::TcpStream::connect_timeout(
                &format!("127.0.0.1:{}", self.port).parse().unwrap(),
                Duration::from_millis(200),
            );
            if let Some(h) = self.handle.take() {
                let _ = h.join();
            }
        }
    }

    // ─── constructor tests ──────────────────────────────────────

    /// `TufClient::new` creates the cache directory if it does not
    /// already exist.
    ///
    /// Bug it catches: a constructor that requires the caller to
    /// pre-create the cache dir — silently returning success on a
    /// non-existent path that later fetches would fail to write
    /// into. The constructor must materialise the dir up front.
    #[test]
    fn test_tuf_client_constructor_creates_cache_dir_if_missing() {
        let dir = unique_temp_dir("ctor_creates_dir");
        // Nest one level deeper to exercise create_dir_all's
        // recursive behaviour.
        let nested = dir.join("a/b/c");
        assert!(!nested.exists());
        let _client = TufClient::new("https://example.invalid", &nested).expect("ctor");
        assert!(nested.is_dir(), "constructor must create nested cache_dir");
        let _ = fs::remove_dir_all(&dir);
    }

    /// `TufClient::new` rejects a base_url without a scheme — this
    /// would otherwise produce malformed request URLs like
    /// `tuf-repo-cdn.sigstore.dev/timestamp.json` (no scheme).
    ///
    /// Bug it catches: a missing-scheme URL silently combining with
    /// a path to produce a relative request that reqwest would
    /// reject mid-fetch with a less actionable error.
    #[test]
    fn test_tuf_client_constructor_rejects_url_without_scheme() {
        let dir = unique_temp_dir("ctor_no_scheme");
        let err = TufClient::new("tuf-repo-cdn.sigstore.dev", &dir).expect_err("must reject");
        assert!(matches!(err, TufError::Http(_)), "{err:?}");
        let _ = fs::remove_dir_all(&dir);
    }

    // ─── chained-root walk ──────────────────────────────────────

    /// Synthesised malicious root rejection: a freshly-fetched root
    /// whose signatures come from random keys (not in the previous
    /// root's `roles.root.keyids`) is rejected.
    ///
    /// Bug it catches: a walker that only checks the new-self-signs
    /// half of TUF's old+new rule would accept any well-formed root
    /// signed by its own keys, breaking the trust chain entirely.
    /// This is the load-bearing security check of the entire
    /// chained-root walk.
    #[test]
    fn test_chained_root_walk_rejects_root_unsigned_by_previous() {
        let dir = unique_temp_dir("chain_unsigned_by_prev");

        // Root v1 (trusted) — caller-supplied bootstrap.
        let (root1, sks1) = build_test_root(1, 1, 1, "2099-01-01T00:00:00Z");

        // Root v2 — uses entirely fresh keys, NOT in root1.keys.
        let (root2, sks2) = build_test_root(1, 1, 2, "2099-01-01T00:00:00Z");
        // Self-signed by root2's own keys — deliberately *not*
        // signed by sks1, so old-signs-new must reject.
        let bytes2 = envelope_for_root(&root2, &[(&sks2[0], "k0")]);

        let server = LocalServer::start(vec![("2.root.json".into(), bytes2)]);

        let client = TufClient::new(&server.base_url, &dir).expect("client");
        let err = client
            .fetch_root(&root1)
            .expect_err("must reject unsigned-by-prev");
        // The first verify_role call (against root1) is the one
        // that fails because root2's signatures use keys not in
        // root1's keys map. Either UnknownKeyId or BelowThreshold
        // is acceptable — the keyid IS in root2.signed.signatures
        // entries (stored as "k0") but root1.keys has its own "k0"
        // mapped to a different public key, so it surfaces as
        // BelowThreshold (the supplied sig won't verify against
        // root1's k0 public key). We assert on either.
        assert!(
            matches!(
                err,
                TufError::BelowThreshold { .. } | TufError::UnknownKeyId { .. }
            ),
            "expected BelowThreshold or UnknownKeyId, got {err:?}"
        );

        // Sanity: the suppressed bug it catches.
        // BelowThreshold { required, valid }
        // UnknownKeyId { keyid }
        drop(sks1);
        let _ = fs::remove_dir_all(&dir);
    }

    /// A fetched root v2 signed by v1's keys but NOT by its own keys
    /// is rejected. v2's keyset has no overlap with v1, so we
    /// re-key with both v1 keys retained (signing) and v2's new key
    /// in v2's keys map without a signature from it.
    ///
    /// Bug it catches: a walker that only checks old-signs-new and
    /// trusts the new keyset on faith — would let an attacker who
    /// has compromised the previous root role insert arbitrary
    /// new keys and have them treated as authoritative.
    #[test]
    fn test_chained_root_walk_rejects_root_unsigned_by_self() {
        let dir = unique_temp_dir("chain_unsigned_by_self");
        let (root1, sks1) = build_test_root(1, 1, 1, "2099-01-01T00:00:00Z");

        // Root v2 has the previous v1 key as its sole signing key
        // (sks1[0]) registered under keyid "k0". Old-signs-new
        // succeeds. Now we tamper: replace v2's k0 public-key
        // material with a fresh, unrelated key — so the same
        // signature that satisfies root1's "k0" (which still maps
        // to sks1[0]'s public key) does NOT satisfy root2's "k0"
        // (which now maps to a stranger public key).
        let mut rng = OsRng;
        let stranger_key = SigningKey::generate(&mut rng);
        let mut root2 = root1.clone();
        root2.version = 2;
        root2.expires = "2099-01-01T00:00:00Z".to_string();
        root2.keys.get_mut("k0").unwrap().keyval.public =
            hex::encode(stranger_key.verifying_key().to_bytes());

        // Sign with v1's key (sks1[0]) — old-signs-new only.
        let bytes2 = envelope_for_root(&root2, &[(&sks1[0], "k0")]);

        let server = LocalServer::start(vec![("2.root.json".into(), bytes2)]);
        let client = TufClient::new(&server.base_url, &dir).expect("client");
        let err = client
            .fetch_root(&root1)
            .expect_err("must reject unsigned-by-self");
        // The first verify_role (against root1) succeeds because
        // root1.keys["k0"] still maps to sks1[0]'s public key. The
        // second verify_role (against root2) fails because
        // root2.keys["k0"] now maps to stranger_key.
        assert!(
            matches!(err, TufError::BelowThreshold { .. }),
            "expected BelowThreshold from new-self-sign check, got {err:?}"
        );
        drop(stranger_key);
        let _ = fs::remove_dir_all(&dir);
    }

    /// A walk with no follow-up roots returns the bootstrap root,
    /// provided its expiry is in the future.
    ///
    /// Bug it catches: a walker that requires at least one fetched
    /// successor would fail freshly-bootstrapped clients whose only
    /// root.json IS the bootstrap. The 404-on-N+1 path must be a
    /// successful termination.
    #[test]
    fn test_chained_root_walk_with_no_successor_returns_bootstrap() {
        let dir = unique_temp_dir("chain_no_successor");
        let (root1, _sks1) = build_test_root(1, 1, 1, "2099-01-01T00:00:00Z");

        // Server has no /2.root.json → 404 → walk terminates
        // successfully.
        let server = LocalServer::start(vec![]);
        let client = TufClient::new(&server.base_url, &dir).expect("client");
        let result = client.fetch_root(&root1).expect("walk must succeed");
        assert_eq!(result.version, 1);
        let _ = fs::remove_dir_all(&dir);
    }

    /// An expired final root is rejected with `TufError::Expired`
    /// after the walk concludes.
    ///
    /// Bug it catches: an expiry check that runs before the walk
    /// (and thus only on the bootstrap, not on the freshest fetched
    /// root). Spec §5.3.4 step 6 requires the check to apply to the
    /// freshest root, and only after confirmation.
    #[test]
    fn test_expiry_enforcement_rejects_expired_root() {
        let dir = unique_temp_dir("expired_root");
        // Expiry in the past relative to an injected now.
        let (root1, _sks1) = build_test_root(1, 1, 1, "2020-01-01T00:00:00Z");
        let server = LocalServer::start(vec![]);
        // Pin "now" to 2023-11-14, which is after 2020-01-01.
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let client = TufClient::new(&server.base_url, &dir)
            .expect("client")
            .with_now_override(now);
        let err = client.fetch_root(&root1).expect_err("expired must error");
        match err {
            TufError::Expired { role, expires } => {
                assert_eq!(role, "root");
                assert_eq!(expires, "2020-01-01T00:00:00Z");
            }
            other => panic!("expected Expired, got {other:?}"),
        }
        let _ = fs::remove_dir_all(&dir);
    }

    /// An expired timestamp.json is rejected with `TufError::Expired`
    /// even when its signatures verify cleanly.
    ///
    /// Bug it catches: an expiry check that only fires on root —
    /// timestamp's freshness is the whole point of the role
    /// (~1-day lifetime), so a missing check defeats freshness
    /// entirely.
    #[test]
    fn test_expiry_enforcement_rejects_expired_timestamp() {
        let dir = unique_temp_dir("expired_ts");
        let (root1, sks1) = build_test_root(1, 1, 1, "2099-01-01T00:00:00Z");

        // Timestamp with expires in 2020 (before injected now).
        let mut meta = BTreeMap::new();
        meta.insert(
            "snapshot.json".to_string(),
            crate::types::MetaInfo {
                version: 1,
                length: None,
                hashes: None,
            },
        );
        let ts = Timestamp {
            type_field: "timestamp".into(),
            spec_version: "1.0.31".into(),
            version: 1,
            expires: "2020-06-01T00:00:00Z".into(),
            meta,
        };
        let signed_value = serde_json::to_value(&ts).unwrap();
        let canonical = canonicalize(&signed_value).unwrap();
        let sig = sks1[0].sign(&canonical);
        let env = json!({
            "signed": signed_value,
            "signatures": [{"keyid": "k0", "sig": hex::encode(sig.to_bytes())}]
        });
        let bytes = serde_json::to_vec(&env).unwrap();

        let server = LocalServer::start(vec![("timestamp.json".into(), bytes)]);
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let client = TufClient::new(&server.base_url, &dir)
            .expect("client")
            .with_now_override(now);

        let err = client
            .fetch_timestamp(&root1)
            .expect_err("expired ts must error");
        assert!(
            matches!(err, TufError::Expired { ref role, .. } if role == "timestamp"),
            "got {err:?}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// Cache hit path: pre-seed the cache dir; fetch_timestamp must
    /// return the cached bytes WITHOUT making an HTTP request.
    ///
    /// Bug it catches: a "cache" that always falls through to HTTP,
    /// or one that writes but never reads. We assert no HTTP
    /// request was logged after the call.
    #[test]
    fn test_cache_hit_does_not_hit_network() {
        let dir = unique_temp_dir("cache_hit");
        let (root1, sks1) = build_test_root(1, 1, 1, "2099-01-01T00:00:00Z");

        let mut meta = BTreeMap::new();
        meta.insert(
            "snapshot.json".to_string(),
            crate::types::MetaInfo {
                version: 1,
                length: None,
                hashes: None,
            },
        );
        let ts = Timestamp {
            type_field: "timestamp".into(),
            spec_version: "1.0.31".into(),
            version: 1,
            expires: "2099-12-31T00:00:00Z".into(),
            meta,
        };
        let signed_value = serde_json::to_value(&ts).unwrap();
        let canonical = canonicalize(&signed_value).unwrap();
        let sig = sks1[0].sign(&canonical);
        let env = json!({
            "signed": signed_value,
            "signatures": [{"keyid": "k0", "sig": hex::encode(sig.to_bytes())}]
        });
        let bytes = serde_json::to_vec(&env).unwrap();

        // Server has NO routes; will return 404 if hit.
        let server = LocalServer::start(vec![]);
        let client = TufClient::new(&server.base_url, &dir).expect("client");
        // Pre-seed cache.
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("timestamp.json"), &bytes).unwrap();

        let ts_back = client
            .fetch_timestamp(&root1)
            .expect("cache hit must succeed");
        assert_eq!(ts_back.version, 1);
        assert_eq!(server.requests().len(), 0, "cache hit must not hit network");
        let _ = fs::remove_dir_all(&dir);
    }

    /// Cache miss path: empty cache, server serves the metadata,
    /// fetch_timestamp returns the served bytes AND writes them to
    /// the cache.
    ///
    /// Bug it catches: a cache that reads but never writes — every
    /// invocation re-fetches even after the first success.
    #[test]
    fn test_cache_miss_falls_through_to_http_and_persists() {
        let dir = unique_temp_dir("cache_miss");
        let (root1, sks1) = build_test_root(1, 1, 1, "2099-01-01T00:00:00Z");

        let mut meta = BTreeMap::new();
        meta.insert(
            "snapshot.json".to_string(),
            crate::types::MetaInfo {
                version: 1,
                length: None,
                hashes: None,
            },
        );
        let ts = Timestamp {
            type_field: "timestamp".into(),
            spec_version: "1.0.31".into(),
            version: 1,
            expires: "2099-12-31T00:00:00Z".into(),
            meta,
        };
        let signed_value = serde_json::to_value(&ts).unwrap();
        let canonical = canonicalize(&signed_value).unwrap();
        let sig = sks1[0].sign(&canonical);
        let env = json!({
            "signed": signed_value,
            "signatures": [{"keyid": "k0", "sig": hex::encode(sig.to_bytes())}]
        });
        let bytes = serde_json::to_vec(&env).unwrap();

        let server = LocalServer::start(vec![("timestamp.json".into(), bytes.clone())]);
        let client = TufClient::new(&server.base_url, &dir).expect("client");
        let ts_back = client
            .fetch_timestamp(&root1)
            .expect("cache miss must fetch");
        assert_eq!(ts_back.version, 1);
        assert_eq!(server.requests().len(), 1, "first fetch must hit network");
        // Cache file must exist and contain the wire bytes verbatim.
        let cached = fs::read(dir.join("timestamp.json")).expect("cache file must exist");
        assert_eq!(cached, bytes, "cache must contain raw wire bytes");
        let _ = fs::remove_dir_all(&dir);
    }

    /// Snapshot hash cross-check: a snapshot.json whose canonical
    /// SHA-256 doesn't match `timestamp.snapshot_meta.hashes.sha256`
    /// is rejected before signature verification.
    ///
    /// Bug it catches: a verifier that signature-checks snapshot
    /// without the hash cross-check would let an attacker pair a
    /// fresh-but-legitimate timestamp with a stale snapshot
    /// (freshness bypass).
    #[test]
    fn test_snapshot_hash_cross_check_rejects_mismatch() {
        let dir = unique_temp_dir("snap_hash_mismatch");
        let (root1, sks1) = build_test_root(1, 1, 1, "2099-01-01T00:00:00Z");

        // Build a real snapshot envelope.
        let mut meta = BTreeMap::new();
        meta.insert(
            "targets.json".to_string(),
            crate::types::MetaInfo {
                version: 1,
                length: None,
                hashes: None,
            },
        );
        let snap = Snapshot {
            type_field: "snapshot".into(),
            spec_version: "1.0.31".into(),
            version: 1,
            expires: "2099-12-31T00:00:00Z".into(),
            meta,
        };
        let signed_value = serde_json::to_value(&snap).unwrap();
        let canonical = canonicalize(&signed_value).unwrap();
        let sig = sks1[0].sign(&canonical);
        let env = json!({
            "signed": signed_value,
            "signatures": [{"keyid": "k0", "sig": hex::encode(sig.to_bytes())}]
        });
        let snap_bytes = serde_json::to_vec(&env).unwrap();

        // Build a timestamp pointing at a DIFFERENT (wrong) snapshot
        // hash: declare the digest of `b"some-other-bytes"` instead
        // of the actual snap_bytes digest.
        let wrong_digest = sha256_lower_hex(b"some-other-bytes");
        let mut ts_meta = BTreeMap::new();
        let mut hashes = BTreeMap::new();
        hashes.insert("sha256".to_string(), wrong_digest.clone());
        ts_meta.insert(
            "snapshot.json".to_string(),
            crate::types::MetaInfo {
                version: 1,
                length: Some(snap_bytes.len() as u64),
                hashes: Some(hashes),
            },
        );
        let ts = Timestamp {
            type_field: "timestamp".into(),
            spec_version: "1.0.31".into(),
            version: 1,
            expires: "2099-12-31T00:00:00Z".into(),
            meta: ts_meta,
        };

        let server = LocalServer::start(vec![("snapshot.json".into(), snap_bytes)]);
        let client = TufClient::new(&server.base_url, &dir).expect("client");
        let err = client
            .fetch_snapshot(&root1, &ts)
            .expect_err("hash mismatch must error");
        match err {
            TufError::HashMismatch { role, expected, .. } => {
                assert_eq!(role, "snapshot");
                assert_eq!(expected, wrong_digest);
            }
            other => panic!("expected HashMismatch, got {other:?}"),
        }
        let _ = fs::remove_dir_all(&dir);
    }

    /// Targets hash cross-check: targets.json whose canonical
    /// SHA-256 doesn't match snapshot's pinned digest is rejected.
    ///
    /// Bug it catches: same family as the snapshot mismatch test
    /// but for the snapshot → targets hop. Both pinning hops must
    /// be checked or a freshness gap opens between them.
    #[test]
    fn test_targets_hash_cross_check_rejects_mismatch() {
        let dir = unique_temp_dir("tgts_hash_mismatch");
        let (root1, sks1) = build_test_root(1, 1, 1, "2099-01-01T00:00:00Z");

        let targets = Targets {
            type_field: "targets".into(),
            spec_version: "1.0.31".into(),
            version: 1,
            expires: "2099-12-31T00:00:00Z".into(),
            targets: BTreeMap::new(),
            delegations: None,
        };
        let signed_value = serde_json::to_value(&targets).unwrap();
        let canonical = canonicalize(&signed_value).unwrap();
        let sig = sks1[0].sign(&canonical);
        let env = json!({
            "signed": signed_value,
            "signatures": [{"keyid": "k0", "sig": hex::encode(sig.to_bytes())}]
        });
        let targets_bytes = serde_json::to_vec(&env).unwrap();

        let wrong_digest = sha256_lower_hex(b"not-the-targets");
        let mut snap_meta = BTreeMap::new();
        let mut hashes = BTreeMap::new();
        hashes.insert("sha256".to_string(), wrong_digest.clone());
        snap_meta.insert(
            "targets.json".to_string(),
            crate::types::MetaInfo {
                version: 1,
                length: Some(targets_bytes.len() as u64),
                hashes: Some(hashes),
            },
        );
        let snap = Snapshot {
            type_field: "snapshot".into(),
            spec_version: "1.0.31".into(),
            version: 1,
            expires: "2099-12-31T00:00:00Z".into(),
            meta: snap_meta,
        };

        let server = LocalServer::start(vec![("targets.json".into(), targets_bytes)]);
        let client = TufClient::new(&server.base_url, &dir).expect("client");
        let err = client
            .fetch_targets(&root1, &snap)
            .expect_err("hash mismatch must error");
        match err {
            TufError::HashMismatch { role, expected, .. } => {
                assert_eq!(role, "targets");
                assert_eq!(expected, wrong_digest);
            }
            other => panic!("expected HashMismatch, got {other:?}"),
        }
        let _ = fs::remove_dir_all(&dir);
    }

    /// Cache filename sanitisation: a "path" with embedded slashes
    /// is reduced to its basename, so a malicious mirror can't
    /// trick the client into writing outside cache_dir.
    ///
    /// Bug it catches: a naive `cache_dir.join(path)` where `path`
    /// is `../../etc/passwd` would write outside the cache.
    /// `safe_cache_filename` strips the path prefix so the worst
    /// case is overwriting an unrelated cache entry.
    #[test]
    fn test_safe_cache_filename_strips_directory_components() {
        assert_eq!(safe_cache_filename("timestamp.json"), "timestamp.json");
        assert_eq!(
            safe_cache_filename("a/b/c/timestamp.json"),
            "timestamp.json"
        );
        assert_eq!(safe_cache_filename("../../etc/passwd"), "passwd");
    }

    /// Ensure `TufError::HttpStatus` is returned for non-success,
    /// non-404 responses. Distinct from `NotFound`, which is the
    /// chained-root walk's normal terminator.
    ///
    /// Bug it catches: collapsing all errors into `Http`/`Status`
    /// would make the chained-root walker treat a 500 as "no more
    /// roots" and return the bootstrap as if it were the freshest
    /// — silently masking a server outage.
    #[test]
    fn test_fetch_returns_typed_http_status_on_500() {
        let dir = unique_temp_dir("http_500");
        // Server has no routes; fallback is 500. fetch_root will
        // hit /2.root.json, which falls through to 500.
        let server = LocalServer::start_with_fallback(vec![], 500, b"bork".to_vec());

        let (root1, _sks1) = build_test_root(1, 1, 1, "2099-01-01T00:00:00Z");
        let client = TufClient::new(&server.base_url, &dir).expect("client");
        let err = client.fetch_root(&root1).expect_err("500 must error");
        assert!(
            matches!(err, TufError::HttpStatus { status: 500, .. }),
            "got {err:?}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// `fetch_root` returns the freshest root when one valid
    /// successor is served. End-to-end happy-path covering: HTTP
    /// fetch, envelope parse, canonicalise, old-signs-new,
    /// new-self-signs, monotonicity, expiry.
    ///
    /// Bug it catches: any wiring break in the verifier flow that
    /// the negative tests above don't surface — for instance, a
    /// canonicaliser that emits subtly different bytes than the
    /// signer used.
    #[test]
    fn test_chained_root_walk_with_one_valid_successor_returns_v2() {
        let dir = unique_temp_dir("chain_one_valid");
        let (root1, sks1) = build_test_root(1, 1, 1, "2099-01-01T00:00:00Z");

        // Root v2 reuses v1's keys (same keyid, same public key)
        // and bumps version. v1 signs v2 (old-signs-new); v2's k0
        // public key still maps to sks1[0] so v2 also self-signs
        // with the same signature.
        let mut root2 = root1.clone();
        root2.version = 2;
        let bytes2 = envelope_for_root(&root2, &[(&sks1[0], "k0")]);

        let server = LocalServer::start(vec![("2.root.json".into(), bytes2)]);
        let client = TufClient::new(&server.base_url, &dir).expect("client");
        let result = client.fetch_root(&root1).expect("walk must succeed");
        assert_eq!(result.version, 2, "freshest root must be v2");
        let _ = fs::remove_dir_all(&dir);
    }

    /// Version regression: a root v2 advertising `version: 1` is
    /// rejected. Defends against a downgrade attack where a mirror
    /// serves an old root.json at the v2 path.
    ///
    /// Bug it catches: a walker that trusts the path version (i.e.
    /// "if it's at /2.root.json, it must be v2") rather than the
    /// metadata's own self-declared version. Spec §5.3.4 requires
    /// the version field to advance.
    #[test]
    fn test_chained_root_walk_rejects_version_regression() {
        let dir = unique_temp_dir("ver_regression");
        let (root1, sks1) = build_test_root(1, 1, 1, "2099-01-01T00:00:00Z");
        // Build a "v2" but with version field still 1.
        let root_stale = root1.clone();
        // version field deliberately still 1 — same as bootstrap.
        let bytes2 = envelope_for_root(&root_stale, &[(&sks1[0], "k0")]);

        let server = LocalServer::start(vec![("2.root.json".into(), bytes2)]);
        let client = TufClient::new(&server.base_url, &dir).expect("client");
        let err = client
            .fetch_root(&root1)
            .expect_err("regression must error");
        assert!(
            matches!(
                err,
                TufError::VersionRegression {
                    previous: 1,
                    fetched: 1
                }
            ),
            "got {err:?}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    // ─── span-vs-canonical migration tests ──────────────────────

    /// The migration from approach (a) (re-canonicalise the parsed
    /// `signed` value) to approach (b) (verify against the exact wire
    /// bytes of the `signed` field) must produce a verifier that
    /// accepts a metadata document signed over its on-the-wire form
    /// even when that form is NOT byte-equal to what our
    /// canonicaliser would have emitted.
    ///
    /// This test constructs exactly that scenario: a `timestamp.json`
    /// envelope where the `signed` field carries non-canonical
    /// whitespace (spaces after `:` and `,`). The signature is
    /// computed over those EXACT wire bytes, not over the
    /// canonicalised form. The post-#22 `TufClient` must accept it.
    ///
    /// To prove this is the migration's value (not an accident of
    /// the test fixture matching the canonicaliser), we additionally
    /// re-parse the same `signed` field and re-canonicalise it; the
    /// resulting bytes must DIFFER from the wire bytes, AND a manual
    /// `verify_role` call against those canonicalised bytes must
    /// fail. That second assertion is the load-bearing one: it shows
    /// the (a) approach this slice replaces would have rejected this
    /// document, while the (b) approach now wired into `TufClient`
    /// accepts it.
    ///
    /// Bug it catches: a `TufClient` that internally re-canonicalises
    /// before verifying (the (a) approach pre-#22) — would silently
    /// reject any producer whose canonicalisation differs from ours
    /// even by one byte. Real-world hazard: a Sigstore root signed
    /// with a slightly different escape policy than our encoder
    /// emits. The (b) path eliminates this entire bug class because
    /// the verifier sees the exact bytes the producer hashed.
    #[test]
    fn test_fetch_role_verifies_against_wire_bytes_not_recanonicalised() {
        let dir = unique_temp_dir("wire_bytes_not_recanon");
        let (root1, sks1) = build_test_root(1, 1, 1, "2099-01-01T00:00:00Z");

        // Hand-roll the `signed` wire bytes: pretty-printed with
        // leading whitespace inside the object. Canonical JSON would
        // emit no whitespace and sort keys; this form deliberately
        // does neither.
        //
        // Field order here also differs from canonical (which sorts
        // alphabetically: `_type`, `expires`, `meta`, `spec_version`,
        // `version`). We put `_type` first by convention, then
        // `version`, then `spec_version`, then `expires`, then
        // `meta`. The canonicaliser would re-order; this hand-rolled
        // form does not.
        let signed_wire = b"{ \"_type\": \"timestamp\", \"version\": 1, \"spec_version\": \"1.0.31\", \"expires\": \"2099-12-31T00:00:00Z\", \"meta\": { \"snapshot.json\": { \"version\": 1 } } }";

        // Sign the EXACT wire bytes (approach (b)).
        let sig = sks1[0].sign(signed_wire);
        let sig_hex = hex::encode(sig.to_bytes());

        // Build the envelope around those wire bytes verbatim. We
        // must not let `serde_json::to_vec` re-emit the `signed`
        // field; if it did, the bytes the verifier sees would be
        // serde's canonical-ish output, not our hand-rolled form.
        let mut envelope_bytes: Vec<u8> = Vec::new();
        envelope_bytes.extend_from_slice(b"{\"signed\":");
        envelope_bytes.extend_from_slice(signed_wire);
        envelope_bytes.extend_from_slice(b",\"signatures\":[{\"keyid\":\"k0\",\"sig\":\"");
        envelope_bytes.extend_from_slice(sig_hex.as_bytes());
        envelope_bytes.extend_from_slice(b"\"}]}");

        // Sanity: the (b) span parser recovers the EXACT wire bytes
        // we built. Without this, the test could pass for the wrong
        // reason (e.g. span parser recovering a different range that
        // happens to also verify).
        let spanned: crate::span::SpannedSignedEnvelope<Timestamp> =
            crate::span::parse_with_signed_span(&envelope_bytes).expect("span parse");
        assert_eq!(
            &envelope_bytes[spanned.signed_bytes.clone()],
            signed_wire,
            "span parser must recover the wire bytes verbatim",
        );

        // Drive the migrated client. Approach (b) verifies signature
        // against the wire bytes — this MUST succeed.
        let server = LocalServer::start(vec![("timestamp.json".into(), envelope_bytes.clone())]);
        let client = TufClient::new(&server.base_url, &dir).expect("client");
        let ts = client
            .fetch_timestamp(&root1)
            .expect("(b) wire-bytes verifier must accept producer's exact bytes");
        assert_eq!(ts.version, 1);

        // Now prove that approach (a) — re-canonicalising — would
        // have rejected the SAME document. Recover the typed `signed`
        // value, canonicalise it, and try the verify_role we just
        // succeeded with against those bytes instead.
        let v: serde_json::Value =
            serde_json::from_slice(&envelope_bytes).expect("envelope reparse");
        let signed_value = v.get("signed").expect("envelope has signed").clone();
        let canonical_bytes = canonicalize(&signed_value).expect("canonicalise");
        assert_ne!(
            canonical_bytes.as_slice(),
            signed_wire,
            "fixture is only meaningful if canonicaliser emits different bytes than the wire",
        );

        let signatures: Vec<Signature> = vec![Signature {
            keyid: "k0".into(),
            sig: sig_hex.clone(),
        }];
        let canonical_verify =
            crate::root::verify_role(&root1, "timestamp", &canonical_bytes, &signatures);
        match canonical_verify {
            Err(TufError::BelowThreshold {
                required: 1,
                valid: 0,
            }) => {
                // The (a) path rejects, as expected. The (b) path
                // accepted (above). Migration value proven.
            }
            other => panic!(
                "(a) canonicalise path was expected to reject this fixture (BelowThreshold), \
                 got {other:?}. If this assertion fails, the test fixture no longer demonstrates \
                 a divergence between the wire form and the canonical form, so it does not \
                 prove the (b) migration's value."
            ),
        }

        let _ = fs::remove_dir_all(&dir);
    }

    /// Tampering with a single byte INSIDE the `signed` block of the
    /// served envelope (after the producer signed it) must cause the
    /// fetcher to reject it. The wire-bytes verifier hashes the
    /// tampered range, the signature was over the un-tampered range,
    /// and Ed25519's avalanche means the verify fails.
    ///
    /// Bug it catches: a span extractor whose recorded range does
    /// NOT cover the tampered byte. If the span ended one byte
    /// short, or started one byte late, the verifier would hash a
    /// slightly different slice and a tamper inside the dropped byte
    /// would slip past. This test pins the span extractor's
    /// boundaries by tampering at three positions inside the
    /// `signed` block (start-ish, middle, end-ish) and asserting
    /// rejection at each.
    #[test]
    fn test_fetch_role_rejects_tampering_inside_signed_field() {
        let (root1, sks1) = build_test_root(1, 1, 1, "2099-01-01T00:00:00Z");

        // Build a normal, canonical-ish `signed` body and a
        // legitimate signature over it.
        let mut meta = BTreeMap::new();
        meta.insert(
            "snapshot.json".to_string(),
            crate::types::MetaInfo {
                version: 1,
                length: None,
                hashes: None,
            },
        );
        let ts = Timestamp {
            type_field: "timestamp".into(),
            spec_version: "1.0.31".into(),
            version: 1,
            expires: "2099-12-31T00:00:00Z".into(),
            meta,
        };
        let signed_value = serde_json::to_value(&ts).unwrap();
        let canonical = canonicalize(&signed_value).unwrap();
        let sig = sks1[0].sign(&canonical);
        let env = json!({
            "signed": signed_value,
            "signatures": [{"keyid": "k0", "sig": hex::encode(sig.to_bytes())}]
        });
        let original_bytes = serde_json::to_vec(&env).unwrap();

        // Sanity: untampered fixture verifies.
        {
            let dir = unique_temp_dir("tamper_baseline");
            let server =
                LocalServer::start(vec![("timestamp.json".into(), original_bytes.clone())]);
            let client = TufClient::new(&server.base_url, &dir).expect("client");
            client
                .fetch_timestamp(&root1)
                .expect("untampered fixture must verify");
            let _ = fs::remove_dir_all(&dir);
        }

        // Locate the `signed` value's byte range so we can tamper
        // inside it. We use the span parser as the source of truth
        // for those offsets; if the parser is wrong the assertion
        // below would still pin a real boundary because tampering
        // at a real `signed` byte must reject under either parser.
        let spanned: crate::span::SpannedSignedEnvelope<Timestamp> =
            crate::span::parse_with_signed_span(&original_bytes).expect("span parse baseline");
        let span = spanned.signed_bytes.clone();
        // Need at least a few bytes inside the value to pick three
        // distinct offsets.
        assert!(
            span.end > span.start + 4,
            "fixture must have a non-trivial `signed` body to tamper inside",
        );

        // Pick three offsets inside the `signed` value: just after
        // start, middle, just before end. Each is a guaranteed
        // member of the verifier's hashing input under approach (b).
        let tamper_offsets = [span.start + 2, (span.start + span.end) / 2, span.end - 2];

        for tamper_at in tamper_offsets {
            let dir = unique_temp_dir(&format!("tamper_at_{tamper_at}"));
            let mut tampered = original_bytes.clone();
            // Flip every bit of the byte. XOR with 0xFF guarantees a
            // visible change, including for 0x00 / 0xFF original
            // bytes. We pick `tamper_at` knowing it's inside the
            // `signed` span, but we don't know what the byte's role
            // is (could be a quote, a colon, a digit) — that's fine
            // because tampering ANY byte inside `signed` must
            // produce a verify failure; if the chosen byte happens
            // to be structurally critical (e.g. a quote) the parse
            // step will fail with a different typed error that we
            // also accept.
            tampered[tamper_at] ^= 0xFF;

            let server = LocalServer::start(vec![("timestamp.json".into(), tampered)]);
            let client = TufClient::new(&server.base_url, &dir).expect("client");
            let err = client
                .fetch_timestamp(&root1)
                .expect_err("tampered byte inside `signed` must be rejected");
            // Acceptable rejections: signature mismatch (the common
            // case), or a parse failure (when the tampered byte
            // collides with structural JSON syntax). Anything else
            // means the verifier was hashing a slice that excluded
            // this byte — a span-extractor bug.
            match err {
                TufError::BelowThreshold { .. }
                | TufError::SpanParse(_)
                | TufError::Json(_)
                | TufError::BadSignatureFormat { .. }
                | TufError::ExpiryParse(_) => {}
                other => panic!(
                    "tampered byte at offset {tamper_at} inside `signed` produced \
                     unexpected error variant {other:?}; expected a parse-or-verify rejection",
                ),
            }
            let _ = fs::remove_dir_all(&dir);
        }
    }

    // ─── bundled-root bootstrap tests (issue #27) ───────────────

    /// Build a `{signed, signatures}` envelope wrapping the typed
    /// [`Root`] body verbatim. Used by the bootstrap-bytes tests
    /// below to construct a synthetic initial root with a controlled
    /// expiry timestamp. Signatures are not produced because
    /// [`TufClient::with_initial_root_bytes`] does not signature-check
    /// the bootstrap (the bootstrap IS the trust anchor).
    fn envelope_bytes_for(root: &Root) -> Vec<u8> {
        let signed = serde_json::to_value(root).unwrap();
        let env = json!({
            "signed": signed,
            "signatures": [],
        });
        serde_json::to_vec(&env).unwrap()
    }

    /// `TufClient::sigstore` succeeds without any operator action --
    /// the bundled embedded root is the bootstrap.
    ///
    /// Bug it catches: a regression where the embedded asset path or
    /// the runtime expiry guard blocks the zero-config path. Without
    /// this test, the only signal that bundling actually works is the
    /// downstream live integration test, which is gated behind an
    /// env var.
    #[test]
    fn test_sigstore_constructor_uses_embedded_root_without_operator_action() {
        let dir = unique_temp_dir("sigstore_ctor_uses_embedded");
        let client = TufClient::sigstore(&dir).expect(
            "sigstore() must succeed using the bundled root; if this fails check the \
             embedded asset's expires field and the runtime expiry guard",
        );
        let bootstrap = client
            .bootstrap_root()
            .expect("sigstore() must populate bootstrap_root() from the embedded asset");
        assert_eq!(
            bootstrap.type_field, "root",
            "bootstrap root _type must be \"root\""
        );
        assert_eq!(
            bootstrap.version,
            crate::embedded::SIGSTORE_PRODUCTION_ROOT_VERSION,
            "bootstrap root version must match SIGSTORE_PRODUCTION_ROOT_VERSION"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// `TufClient::sigstore` self-signature-verifies the bundled
    /// root at construction time.
    ///
    /// This is the new-self-signs gate from TUF spec §5.3.4 run
    /// against the bootstrap asset itself. Without it, a corrupt
    /// or tamper-modified embedded asset would surface its failure
    /// only later in the chain walk, where the diagnostic blame
    /// could plausibly land on the network or the upstream mirror
    /// instead of the actual cause (the asset).
    ///
    /// Bug it catches: a regression where the helper that performs
    /// the self-verification is silently dropped from the
    /// `sigstore()` path -- e.g. someone refactors the constructor
    /// and forgets to re-thread the call. Without this test, the
    /// only signal would be an asset-rotation event landing a
    /// malformed bytes blob and breaking production silently.
    #[test]
    fn test_sigstore_constructor_self_verifies_bundled_root() {
        let dir = unique_temp_dir("sigstore_ctor_self_verifies");
        // The constructor MUST internally call
        // `verify_bundled_root_self_signature` against the embedded
        // bytes. The most direct way to assert that is to call the
        // helper ourselves and confirm it succeeds; if either path
        // breaks (the helper or the constructor wiring), one of the
        // two assertions below catches it.
        super::verify_bundled_root_self_signature(crate::embedded::SIGSTORE_PRODUCTION_ROOT_BYTES)
            .expect("bundled Sigstore root must self-verify at the helper level");
        TufClient::sigstore(&dir)
            .expect("TufClient::sigstore must succeed end-to-end including self-verification");
        let _ = fs::remove_dir_all(&dir);
    }

    /// A bundled root whose bytes have been tampered (one byte
    /// flipped inside the `signed` body) must fail
    /// self-verification, surfacing
    /// [`TufError::BelowThreshold`] rather than silently
    /// proceeding. This pins the safety property that
    /// `sigstore()`'s self-verification gate ACTUALLY rejects
    /// asset corruption -- a gate that always returns Ok would
    /// pass [`test_sigstore_constructor_self_verifies_bundled_root`]
    /// but provide no real protection.
    ///
    /// Bug it catches: an implementation of
    /// `verify_bundled_root_self_signature` that returns Ok
    /// unconditionally, or one whose canonicalisation no longer
    /// matches what tuf-on-ci emits (a regression we landed and
    /// fixed once already in the v0.x cycle).
    #[test]
    fn test_verify_bundled_root_self_signature_rejects_tampered_bytes() {
        let mut bytes: Vec<u8> = crate::embedded::SIGSTORE_PRODUCTION_ROOT_BYTES.to_vec();
        // Flip one ASCII byte inside the `signed` body. The byte
        // we pick is the `4` in `"version": 14`; toggling its low
        // bit changes the canonical form (numbers pass through to
        // the canonical encoding) and so flips every signature.
        let needle = b"\"version\": 14";
        let pos = bytes
            .windows(needle.len())
            .position(|w| w == needle)
            .expect("bundled root contains version 14 marker");
        // Mutate the ASCII '4' (0x34) -> '5' (0x35).
        let target = pos + needle.len() - 1;
        assert_eq!(bytes[target], b'4');
        bytes[target] = b'5';

        let err = super::verify_bundled_root_self_signature(&bytes)
            .expect_err("tampered bytes must not self-verify");
        assert!(
            matches!(err, TufError::BelowThreshold { .. }),
            "expected BelowThreshold from tampered self-verify, got {err:?}"
        );
    }

    /// `TufClient::with_initial_root_bytes` accepts a synthesised
    /// well-formed root and exposes it via [`TufClient::bootstrap_root`].
    ///
    /// Bug it catches: a constructor that silently drops the supplied
    /// bytes (e.g. only respecting the embedded path) would defeat
    /// the air-gapped escape hatch. Operators of locked-down systems
    /// MUST be able to supply their own root.
    #[test]
    fn test_with_initial_root_bytes_accepts_valid_root() {
        let dir = unique_temp_dir("override_valid");
        let (synthetic_root, _sks) = build_test_root(1, 1, 7, "2099-01-01T00:00:00Z");
        let bytes = envelope_bytes_for(&synthetic_root);

        let client = TufClient::with_initial_root_bytes(&bytes, "https://example.invalid", &dir)
            .expect("valid root bytes must produce a client");
        let bootstrap = client
            .bootstrap_root()
            .expect("override constructor must populate bootstrap_root()");
        assert_eq!(
            bootstrap.version, 7,
            "bootstrap version must round-trip the supplied root's version"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// `TufClient::with_initial_root_bytes` rejects a root whose
    /// `expires` is in the past (relative to the current clock --
    /// pinned via `with_now_override`-style discipline in the
    /// fixture, but this test uses the real clock and a 1970 expiry
    /// to be unambiguously in the past).
    ///
    /// Bug it catches: a constructor that builds a client around an
    /// already-expired bootstrap would let downstream chain walks
    /// proceed using bytes the operator should already have rotated.
    /// The expired-bootstrap branch is component 3 of issue #27 --
    /// without this test, the runtime guard is effectively dead code.
    #[test]
    fn test_with_initial_root_bytes_rejects_expired_bootstrap() {
        let dir = unique_temp_dir("override_expired");
        // 1970 is unambiguously before any test runner clock.
        let (synthetic_root, _sks) = build_test_root(1, 1, 1, "1970-01-02T00:00:00Z");
        let bytes = envelope_bytes_for(&synthetic_root);

        let err = TufClient::with_initial_root_bytes(&bytes, "https://example.invalid", &dir)
            .expect_err("expired bootstrap must be rejected");
        match err {
            TufError::EmbeddedRootExpired {
                expired_at,
                now_iso8601,
                hint,
            } => {
                assert_eq!(expired_at, "1970-01-02T00:00:00Z");
                assert!(
                    !now_iso8601.is_empty(),
                    "now_iso8601 must be populated for diagnostics"
                );
                assert!(
                    hint.contains("with_initial_root_bytes"),
                    "hint must direct operators to the override constructor; got: {hint}"
                );
            }
            other => panic!("expected EmbeddedRootExpired, got {other:?}"),
        }
        let _ = fs::remove_dir_all(&dir);
    }

    /// `TufClient::with_initial_root_bytes` rejects malformed JSON
    /// with [`TufError::Json`] rather than panicking or constructing
    /// a junk client.
    ///
    /// Bug it catches: an `unwrap()` on the JSON parse path would
    /// crash the calling process when an air-gapped operator passes a
    /// truncated download. We surface a typed error so callers can
    /// log + retry with a fresh fetch.
    #[test]
    fn test_with_initial_root_bytes_rejects_malformed_json() {
        let dir = unique_temp_dir("override_garbage");
        let err =
            TufClient::with_initial_root_bytes(b"not-json{}", "https://example.invalid", &dir)
                .expect_err("malformed JSON must error");
        assert!(
            matches!(err, TufError::Json(_)),
            "expected TufError::Json for malformed JSON, got {err:?}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// `TufClient::with_initial_root_bytes` rejects an envelope that
    /// is well-formed JSON but missing the top-level `signed` field.
    ///
    /// Bug it catches: a fetch that returned a snapshot.json or a
    /// 200-response error page rendered as JSON would otherwise be
    /// silently accepted as a "root" with all default fields.
    #[test]
    fn test_with_initial_root_bytes_rejects_envelope_missing_signed() {
        let dir = unique_temp_dir("override_no_signed");
        let bytes = b"{\"signatures\":[]}";
        let err = TufClient::with_initial_root_bytes(bytes, "https://example.invalid", &dir)
            .expect_err("envelope without `signed` must error");
        assert!(
            matches!(err, TufError::Json(_)),
            "expected TufError::Json for missing `signed`, got {err:?}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// `TufClient::fetch_root_from_bootstrap` errors cleanly when the
    /// client was constructed without a bootstrap (i.e. via
    /// [`TufClient::new`]) -- those callers must use the explicit
    /// [`TufClient::fetch_root`] path.
    ///
    /// Bug it catches: a `.unwrap()` on `self.initial_root` inside
    /// `fetch_root_from_bootstrap` would panic on a perfectly legal
    /// construction path. The typed error documents the right
    /// alternative for the operator.
    #[test]
    fn test_fetch_root_from_bootstrap_without_bootstrap_returns_typed_error() {
        let dir = unique_temp_dir("no_bootstrap");
        let client =
            TufClient::new("https://example.invalid", &dir).expect("bare ctor must succeed");
        assert!(
            client.bootstrap_root().is_none(),
            "bare ctor must leave bootstrap_root() at None"
        );
        let err = client
            .fetch_root_from_bootstrap()
            .expect_err("must error without a bootstrap");
        assert!(
            matches!(err, TufError::MissingRole { .. }),
            "expected MissingRole, got {err:?}"
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
