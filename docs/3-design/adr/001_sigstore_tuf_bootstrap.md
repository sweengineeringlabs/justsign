# ADR-001: Sigstore TUF root bootstrap policy

**Audience**: Architects, security reviewers, and operators evaluating the trust path from a justsign install to the Sigstore public-good production root.

- Status: accepted
- Date: 2026-04-27
- Deciders: justsign maintainers
- Related: issue #27, `tuf/src/embedded.rs`, `tuf/src/client.rs`,
  `tuf/build.rs`

## Context

`swe_justsign_tuf::TufClient` implements the TUF spec §5.3 client
workflow: chained-root walk, hash-pinned freshness, threshold
signature verification. The walker requires a *trusted initial root*
to start from. Until this ADR, callers had to obtain that root
themselves (the live integration test reads it from a path supplied
via `JUSTSIGN_TUF_BOOTSTRAP`); there was no built-in zero-config
bootstrap.

That is correct from a TUF-spec purity perspective -- the trust root
is the security boundary, and baking unverifiable bytes into a binary
is a non-trivial decision -- but it is a usability cliff. Every
downstream caller (cosign-style CLIs, attest verifiers, CI gates)
re-implements the same fetch-and-pin dance.

issue #27 captures the decision four ways. We picked option (a). The
runner-up was (b).

## Considered options

### (a) Bake the current Sigstore production root via `include_bytes!`

- Pros: zero-config bootstrap; chained-root walking covers Sigstore's
  signed rotations transparently; the asset is build-pipeline
  reviewable as part of every release; bytes are reproducible (we
  cross-check against `tuf-repo-cdn.sigstore.dev`,
  `sigstore/root-signing` repo `metadata/root.json`, and
  `sigstore/root-signing` repo `metadata/root_history/<N>.root.json`).
- Cons: rotation that breaks the chain (no precedent in Sigstore's
  history, but possible in principle) requires a justsign release;
  build-pipeline compromise affects everyone who installs justsign
  past the compromise (mitigated by the ordinary release-signing
  story we already have for the binaries themselves).

### (b) Bundle a list of historical roots and chain-walk forward

- Pros: same zero-config bootstrap as (a); larger asset gives the
  walker more starting points, so a single missed release is less
  likely to leave callers stranded; each pinned root self-validates
  against the next via the chain walk, so every additional root is
  one more cross-check against build-pipeline tampering.
- Cons: every release must vendor an extra asset and bump a manifest;
  binary size grows roughly linearly in the number of bundled roots
  (~5 KB each, so still small, but it is an unbounded growth curve);
  not materially safer than (a) for the threat model that matters
  (build-pipeline integrity), because the bundled set is still a
  build-time decision.

### (c) `justsign init` CLI command that fetches + verifies + writes

- Pros: no compile-time pinning; the operator sees the URL, sees the
  bytes, signs off; rotation is "re-init"; the CLI command can do
  cross-mirror verification at install time which a `include_bytes!`
  asset cannot; air-gapped operators are first-class.
- Cons: TOFU on first run unless the operator manually verifies; the
  zero-config promise breaks ("you have to run init first"); every
  downstream tool that wraps justsign has to surface the init step
  too; a missed init is a broken trust path that fails late.

### (d) Stay as-is -- caller's problem

- Pros: cleanest security boundary; we never bake unverifiable bytes;
  every downstream is forced to think about trust roots explicitly.
- Cons: every downstream re-implements fetch-and-pin; the cliff is
  the cliff; the live integration test is the only pre-existing
  signal that the fetcher even works against the live mirror.

## Decision

**(a). Bake the current Sigstore production root via `include_bytes!`,
plus a `with_initial_root_bytes()` override.**

Rationale:

1. **Chained-root walking absorbs ordinary rotations.** Sigstore
   rotates via the spec's "old signs new" flow. The walker fetches
   `N+1.root.json`, verifies it against root `N`'s keys, then
   verifies it against its own keys, and repeats. We embed root `N`;
   the walker reaches root `M >= N` for any rotation Sigstore has
   ever performed. (b) only adds value if Sigstore stops doing
   chained rotations, which would itself be a far larger event.

2. **(c) defeats the zero-config goal.** Justsign's design point is
   "drop the binary in a CI pipeline; it works". A mandatory `init`
   step pushes that work onto every operator. The escape hatch
   (`with_initial_root_bytes()`) preserves (c)'s value for the
   operators who actually need it -- air-gapped, locked-down,
   security-paranoid -- without forcing it on everyone.

3. **(d) is reasonable but pessimistic.** Every justsign caller
   already trusts our build-pipeline output (the CLI binary, the
   library code). Refusing to ship a pinned trust root because we do
   not trust our own pipeline is internally inconsistent -- if the
   pipeline is compromised, an attacker has options far worse than
   swapping the embedded root.

4. **(a) is what cosign does.** sigstore-go and cosign both bundle
   a Sigstore root; our policy aligns with the rest of the
   ecosystem, which means operators who already trust cosign's
   bundling story have one fewer threat-model exception to track.

## Implementation

Components landed in this slice (issue #27, components 1-4):

1. **Asset.** `tuf/assets/sigstore_prod.root.json`. Verbatim copy of
   `https://tuf-repo-cdn.sigstore.dev/14.root.json`, cross-checked
   against `https://raw.githubusercontent.com/sigstore/root-signing/main/metadata/root.json`
   and `.../metadata/root_history/14.root.json`. SHA-256 +
   fetched-at + version are recorded in `tuf/src/embedded.rs` and
   the landing commit message.
2. **Constants + override constructor** (`tuf/src/embedded.rs` +
   `tuf/src/client.rs`). `SIGSTORE_PRODUCTION_ROOT_BYTES` exposes
   the bytes; `TufClient::sigstore` parses them as the bootstrap;
   `TufClient::with_initial_root_bytes` accepts an arbitrary
   caller-supplied root for air-gapped deploys.
3. **Build-time integrity check** (`tuf/build.rs`). Parses the asset
   on every build; fails the build if shape is wrong, JSON is
   malformed, or `expires` is in the past. Emits `cargo:warning` if
   `expires` is within 30 days. Surfaces the version as a
   `JUSTSIGN_TUF_BAKED_ROOT_VERSION` env var to the compile.
4. **Runtime expiry guard** (`tuf/src/client.rs`). Both
   `sigstore()` and `with_initial_root_bytes()` re-check expiry on
   construction and surface `TufError::EmbeddedRootExpired` --
   distinct from the post-fetch `TufError::Expired` so operators can
   route on it.

Out of scope for this ADR (filed as follow-up issues): a monthly CI
watcher that opens a refresh PR when Sigstore rotates, a
cross-verification with cosign's bundled root at build time, a
`justsign tuf-root verify` CLI subcommand, and an operator runbook
at `docs/7-operations/sigstore_bootstrap.md`.

## Rotation policy

Sigstore publishes new root versions that are signed by the previous
root (the "old signs new" half of TUF spec §5.3.4). The chain walker
in `TufClient::fetch_root` walks forward until a 404, so a Sigstore
rotation is invisible to operators who run a justsign release that
embeds *any* ancestor of the current production root. The embedded
root only needs to be a valid ancestor, not the current production
root itself.

A justsign release with a refreshed asset is required only when:

- Sigstore publishes a non-chained rotation. There is no precedent
  for this in Sigstore's history. If it happens we will publish a
  patch release.
- The embedded root expires before chain-walking can reach a
  successor. The build-time check warns 30 days out; the monthly CI
  watcher (component 5, deferred) will be the long-term fix.

## Consequences

- **Operators get zero-config trust.** `TufClient::sigstore()` works
  out of the box.
- **Air-gapped operators have an explicit escape hatch.**
  `TufClient::with_initial_root_bytes()` accepts caller-supplied
  bytes; the existing `TufClient::fetch_root(initial_root)` API also
  remains, so the live integration test path is unchanged.
- **Build pipeline becomes a documented trust assumption.** This was
  already the case for the binary itself; the asset is now part of
  the same trust boundary.
- **Asset freshness is a release-cadence concern.** The build-time
  check + the runtime guard prevent a stale asset from being
  silently shipped. Refreshing the asset is mechanical: download,
  cross-check, replace, update constants.

## Status

Accepted on 2026-04-27. Will be revisited if Sigstore changes its
rotation policy or if the ecosystem shifts to a managed-trust model
(e.g. Sigstore-managed mirrors that issue per-tenant trust roots).
