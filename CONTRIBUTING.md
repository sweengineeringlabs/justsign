# Contributing to justsign

**Audience**: Anyone planning to land code, docs, or issues in justsign.

Thanks for considering a contribution. justsign is a security-critical library — every change is reviewed against the test-pyramid and architectural-compliance gates documented below.

## Quick links

- [Developer guide](docs/4-development/developer_guide.md) — local clone-to-PR workflow.
- [Testing strategy](docs/5-testing/testing_strategy.md) — what we test, why, what's NOT tested.
- [Architecture compliance checklist](docs/3-design/compliance/compliance_checklist.md) — pre-merge gate for any architecture-touching PR.
- [Code of Conduct](CODE_OF_CONDUCT.md) — Contributor Covenant 2.1.

## How to contribute

### 1. Pick something to work on

- Open issues at <https://github.com/sweengineeringlabs/justsign/issues>.
- Issues labelled `prod-ready` are required for the v0.1.0 cut.
- Issues labelled `good first issue` are deliberately scoped for newcomers.
- Want to propose something not in the issue list? Open an issue first to align on shape before writing code.

### 2. Set up locally

See [`docs/4-development/developer_guide.md`](docs/4-development/developer_guide.md) for the full setup. Short version:

```sh
git clone git@github.com:sweengineeringlabs/justsign.git
cd justsign
cargo build --workspace
cargo test --workspace
```

### 3. Branch + commit

- Branch off `dev`. We cascade `dev → test → int → uat → prd → main` ff-only; never push directly to `main`.
- Commit messages follow `type(scope): description`. Examples:
  - `feat(rekor): add HttpRekorClient::fetch`
  - `fix(spec): canonical Sigstore Bundle v0.3 mediaType`
  - `docs: refresh #23 round-trip runbook`
- Reference the issue: include `Closes #N` in the commit body when the commit resolves an issue.
- **Do not include AI-attribution lines** (no `Co-Authored-By: Claude…` etc.) unless a maintainer explicitly approves.

### 4. Run the gates

Before opening a PR:

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test --workspace --doc
```

All four must pass. CI runs the same gates against your PR — fix locally first.

If your PR touches an architectural boundary (crate-graph, wire format, trait SPI), also walk through [`docs/3-design/compliance/compliance_checklist.md`](docs/3-design/compliance/compliance_checklist.md) before requesting review.

### 5. Open the PR

- PR title mirrors the commit message.
- PR body explains WHY (not what — the diff is the what). Link the issue. List any caller-visible API changes.
- Wire-format changes MUST trigger a re-run of the [production round-trip runbook](docs/6-deployment/production_round_trip_runbook.md) before merge. Paste the result (Rekor logIndex + cosign output) in the PR.

### 6. Review + merge

- A maintainer reviews against the compliance checklist.
- Address review comments via additional commits on the branch (no force-push to a PR branch — keeps the review history readable).
- Merge is ff-only on `dev`, then cascaded by a maintainer.

## What we look for in a PR

- **Tests that can fail** — every test must catch a specific bug. No trophy tests, no happy-path-only coverage on safety surfaces, no tautological assertions.
- **Honest scope** — a bug fix doesn't need surrounding cleanup; a one-shot operation doesn't need a helper. Don't design for hypothetical future requirements.
- **No silent gaps** — half-finished implementations, ignored errors, and TODO-driven development get bounced. If something can't be fully done in this PR, scope it out explicitly.
- **Production-grade defaults** — no panics in library code, no unbounded operations, no hardcoded secrets, no overly permissive error messages that leak internals.

## Reporting bugs

See [`SECURITY.md`](SECURITY.md) for security-sensitive reports.

For non-security bugs: open an issue with steps to reproduce, expected vs actual behaviour, and the relevant version(s) of `justsign` + `cosign` + `rustc`.

## License

By contributing, you agree your contributions are licensed under the same MIT licence as the rest of the project. See [`LICENSE`](LICENSE).
