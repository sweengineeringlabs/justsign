# MSRV stability policy

**Audience**: Library consumers, distro packagers, and CI maintainers who need to know which Rust toolchains justsign commits to supporting.

This document describes when justsign bumps its Minimum Supported Rust Version (MSRV), how that decision propagates downstream, and how operators / distros can reason about which Rust toolchains we commit to building on.

## Current MSRV

**1.88**, pinned in workspace `Cargo.toml` (`rust-version = "1.88"`).

Enforced by the `cargo check (MSRV 1.88)` job in `.github/workflows/ci.yml` on every push to all six branches.

## Why 1.88

The active dep graph requires it. Specifically:

- `base64ct` 1.7+ requires `edition2024` (Rust 1.85+).
- `icu_collections` 2.x declared `rust-version = "1.86"`.
- `time` 0.3.47 (transitively pulled in by `rcgen`, a dev-dep used in keyless tests) declared `rust-version = "1.88"`.

We could pin each transitive back to a 1.86-compatible version (`cargo update <name> --precise <ver>`), but pinning back is whack-a-mole — the next time `rcgen` updates we'd hit the same cliff. Tracking the ecosystem is cheaper to maintain than fighting it.

## When we bump

A bump is justified when ANY of:

1. **A direct dep we depend on** drops support for the current MSRV in a release we want to use. We'd lose security fixes / features by pinning back.
2. **A transitive dep** declared a higher MSRV and pinning back is impractical (e.g. it's a dev-dep we can't easily fork). We bump rather than maintain a private fork.
3. **A new Rust feature** materially simplifies a load-bearing piece of the codebase (`let-else`, `#[cfg(...)]` patterns, etc.) AND the next bump cycle is acceptable for downstreams.

A bump is NOT justified when:

- A nice-to-have lint or syntactic sugar requires it but the code works fine on the current MSRV.
- A non-essential dep wants the bump but a substitute exists.

## Communication

Every MSRV bump:

- Lands as a dedicated commit (no other unrelated changes in the same PR).
- Updates `Cargo.toml` `rust-version` AND the `.github/workflows/ci.yml` `cargo check (MSRV X)` job's pinned toolchain.
- Names the triggering dep + version in the commit message body so future maintainers see the chain.
- Adds a row to the table at the bottom of this document.
- Triggers a **minor** version bump on next release (semver: MSRV is a soft API contract).

## What we promise to downstream consumers

- We don't bump MSRV in a patch release. Patch releases stay buildable on the same toolchain as the minor before.
- We don't drop support for a Rust toolchain that's < 6 months old at release time. (Currently this is mostly aspirational — we've been chasing latest. The 6-month floor is the post-v0.1.0 commitment.)
- The `cargo check (MSRV X)` CI job is the source of truth. If a PR changes `Cargo.toml`'s `rust-version` without updating that job, review will reject.

## What we DON'T promise

- We don't promise compatibility with Rust toolchains older than the current MSRV. Distros that ship Rust 6+ months behind upstream will pin justsign to a release that still supports their toolchain.
- We don't promise the MSRV will track Rust stable forever. Specific deps may pull us forward; we name the trigger and bump.

## History

| Bump | From → To | Trigger | Commit |
|---|---|---|---|
| Initial | (n/a) → 1.75 | workspace bootstrap | (slice 0) |
| 1 | 1.75 → 1.85 | `base64ct` 1.7+ requires `edition2024` (Cargo 1.85) | (slice 0) |
| 2 | 1.85 → 1.86 | `reqwest → idna → icu_collections` 2.x declared 1.86 | (slice 0) |
| 3 | 1.86 → 1.88 | `rcgen → time` 0.3.47 (dev-dep, transitive) declared 1.88 | (slice 0) |

Future entries land here in chronological order.

## Action for downstream consumers

If you're packaging justsign for a distro:

1. Pin to the latest MSRV-compatible release (`cargo install --version <ver>` or `Cargo.toml = "<ver>"`).
2. Subscribe to the release notes — every minor that bumps MSRV calls it out in the changelog header.
3. If you absolutely cannot ship with our MSRV, file an issue on the repo with your distro's MSRV ceiling. We'll consider whether a pin-back is feasible for that specific transitive dep.

## See also

- [`developer_guide.md`](./developer_guide.md) — how the workspace is structured + the six-branch flow.
- [`migration_guide.md`](./migration_guide.md) — API migration notes between releases (MSRV bumps land here when relevant).
