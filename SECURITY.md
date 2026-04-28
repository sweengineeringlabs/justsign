# Security Policy

**Audience**: Security researchers, downstream library consumers, anyone reporting a vulnerability or auditing justsign.

## WHAT: Coverage and supported versions

justsign is a security library. Its primary responsibility is producing and verifying Sigstore bundles — a vulnerability here can change verification outcomes or compromise signing guarantees in any system that depends on it.

### Supported versions

justsign is pre-1.0. The supported version is the most recent published `0.x.y` release plus the current `main` branch. Older `0.x.*` releases are not patched separately — upgrade to the latest.

| Version | Supported |
|---|---|
| Latest `0.x.y` published release | yes |
| `main` branch | yes (rolling) |
| Older `0.x.*` releases | no — upgrade |

Once justsign reaches 1.0, this table will be updated with a stable-release support window.

### What's in scope

- Anything in `verify_blob`, `verify_blob_keyless`, `verify_attestation`, `verify_oci`, `verify_blob_message`, `verify_blob_message_keyless` that returns `Ok(())` for input that should be rejected.
- Anything in `sign_blob`, `sign_blob_keyless`, `attest`, `sign_oci`, `sign_blob_message`, `sign_blob_message_keyless` that produces a signature an attacker can replay or substitute.
- TUF root walking and trust-root bootstrap correctness.
- OIDC token handling (interactive-browser provider) — token leakage, redirect-URI injection, PKCE downgrade.
- Memory safety in `unsafe` blocks (currently zero `unsafe` in the workspace; any future addition is in scope).

### What's out of scope

- The Sigstore public-good infrastructure itself (Fulcio, Rekor, Sigstore TUF root) — report those upstream at <https://github.com/sigstore>.
- Network-level denial-of-service against `fulcio.sigstore.dev` / `rekor.sigstore.dev`.
- Reports that require the operator to ship a malicious `Cargo.toml` or `build.rs` — that's covered by Cargo's threat model.
- Local-machine attacks where the attacker already has code execution as the operator.

## WHY: Why private disclosure matters

A vulnerability in a verification library does not crash the caller — it silently changes the answer from `Err` to `Ok`. An attacker can forge attestations, substitute signatures, or bypass transparency checks without any observable signal to the operator. Premature public disclosure gives attackers a head start before callers can patch.

We triage security reports privately, issue CVEs under coordinated disclosure, and document confirmed issues in a public advisory once callers have had time to upgrade.

## HOW: Reporting, response, and known limitations

### Reporting a vulnerability

**Do NOT open a public issue for a security report.**

Use one of:

1. **GitHub Security Advisory** — preferred. Open a private advisory at <https://github.com/sweengineeringlabs/justsign/security/advisories/new>.
2. **Email** — `engineers@swelabs.io`. Include `[justsign security]` in the subject. PGP encryption optional; if you want a key, email first and we will respond with one.

Please include:

- A description of the issue and its impact (what changes in a verification outcome, what an attacker can forge, what trust the user thought they had).
- A minimum reproduction — code, command, or attacker-controlled input.
- Affected versions / commits, if known.
- Any suggested mitigation or fix.
- Whether you want public credit in the eventual advisory.

### Response SLA

| Action | Target |
|---|---|
| Acknowledge receipt | 3 business days |
| Initial triage + severity decision | 7 business days |
| Patch released for confirmed high-severity issues | 30 days from confirmation |
| Public advisory + CVE | Coordinated with reporter; default 90-day disclosure window |

Severity follows [CVSS v3.1](https://www.first.org/cvss/v3.1/specification-document) calculated on the verification or signing surface, NOT the codebase volume. A 5-line change to the verifier that makes invalid signatures verify is `Critical`.

### Known limitations (pre-1.0)

The following gaps in the v0 verifier surface are **acknowledged and tracked** — they are not hidden, but they are not yet fixed. Reports confirming these specific gaps will be triaged as expected until the linked issue closes.

| Gap | Detail | Tracked |
|---|---|---|
| Cert expiry not enforced | `VerifyError::CertExpired` is defined but never constructed; `notBefore`/`notAfter` is not checked during `verify_blob_keyless`. | [#26](https://github.com/sweengineeringlabs/justsign/issues/26) |
| No Rekor checkpoint cosigning | Inclusion proofs verify against the bundle's own embedded root, not a trusted external witness. A log that controls both the log and the bundle producer can present a self-consistent fake root. | [#23](https://github.com/sweengineeringlabs/justsign/issues/23) |
| No replay gate | `tlog_entry.integrated_time` is wired through but not validated against any freshness window. A bundle valid on day N remains valid on day N+365. | [#26](https://github.com/sweengineeringlabs/justsign/issues/26) |
| Caller-supplied TUF root | `TufClient` does not bootstrap itself; the caller threads in the trusted initial root. No default Sigstore public-good root is bundled. | [#27](https://github.com/sweengineeringlabs/justsign/issues/27) |

For the full verifier threat model — what every parameter controls, the complete attacker model, and the caller-side enforcement checklist — see [`docs/3-design/threat_model.md`](docs/3-design/threat_model.md).

### Hall of fame

Reporters who choose public credit are listed in [`docs/3-design/threat_model.md`](docs/3-design/threat_model.md) once the corresponding advisory is public.

## Summary

justsign is a security-critical verification library; a silent bypass in the verifier is more dangerous than a crash. Reports that change a verification outcome from `Err` to `Ok` are treated as high or critical severity regardless of code volume. Disclose privately via GitHub Security Advisory or `engineers@swelabs.io`; expect acknowledgement within 3 business days and a coordinated advisory within 90 days of confirmation.

**Key takeaways**:
1. Use the GitHub Security Advisory for private, structured disclosure — do not open a public issue.
2. Include a minimum reproduction and impact description (what trust the caller thought they had).
3. Pre-1.0 known gaps are tracked in the table above; reports confirming those are expected and will be acknowledged but not treated as novel until the tracking issue closes.

---

**Related documentation**:
- [`docs/3-design/threat_model.md`](docs/3-design/threat_model.md) — v0 verifier surface: trust assumptions, attacker model, failure modes, caller enforcement checklist
- [`docs/3-design/compliance/compliance_checklist.md`](docs/3-design/compliance/compliance_checklist.md) — architecture compliance gate for security-touching PRs
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — contribution process, including security-aware review criteria

**Last Updated**: 2026-04-28
**Version**: 0.1
**Next Review**: 2026-07-28
