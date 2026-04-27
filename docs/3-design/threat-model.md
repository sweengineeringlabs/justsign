# justsign threat model (v0 verifier surface)

This document is for security reviewers and downstream library consumers
evaluating what `verify_blob`, `verify_blob_keyless`, `verify_attestation`,
and `verify_oci` actually guarantee in `swe_justsign_sign` v0. It does
NOT cover operational deployment guidance (key custody, CI runner
hardening, registry ACLs) — those live with the operator, not the
library. Every guarantee below is anchored to a file:line; every gap
is anchored to a tracking issue.

## Trust assumptions

The verifier trusts:

- **The `trusted_keys` slice** passed to `verify_blob`. At least one
  key must validate at least one envelope signature
  (`sign/src/lib.rs:467`: `if !any_valid { return Err(VerifyError::SignatureInvalid …) }`).
- **The `trust_anchors_der` slice** passed to `verify_blob_keyless`.
  Empty anchor lists are rejected with `ChainError::EmptyTrustAnchors`
  (`sign/src/cert_chain.rs:212`: `return Err(ChainError::EmptyTrustAnchors)`).
- **The caller-supplied initial TUF root.** `TufClient` does NOT bootstrap
  itself; the caller threads in the trusted root (`tuf/src/client.rs:31`:
  `// **Bootstrap.** The caller supplies the trusted initial root.`).
- **The system clock**, but only inside `TufClient` for TUF role expiry
  (`tuf/src/client.rs:240`: `if is_expired(&current_root.expires, self.now())?`).
  Cert chain expiry is NOT clocked yet — see Failure modes below.

The verifier explicitly does NOT trust:

- **DSSE envelope contents until cryptographically validated.** The
  payload is parsed AFTER signature verification
  (`sign/src/lib.rs:768-770`: `Statement::decode_json(&envelope.payload)`
  runs after `verify_blob` returns Ok).
- **The Rekor server's bare word.** The library re-runs the inclusion
  proof locally rather than accepting a "trust me" response
  (`rekor/src/client.rs:7`: `// uses the local merkle::verify_inclusion`).
- **Fulcio cert subject claims beyond the cryptographic chain.** The
  chain walker proves the leaf was issued by a trust-anchor-rooted
  CA; it does NOT validate that the SAN identity policy beyond an
  exact-string match the caller pinned (`sign/src/lib.rs:1054`:
  `if !actual.iter().any(|entry| entry == expected)`).

## Attacker model

**Network attacker (MITM on Fulcio/Rekor).** Fulcio and Rekor traffic
is HTTPS; `HttpFulcioClient` and `HttpRekorClient` use
`reqwest::blocking::Client` with the system CA store. A MITM with a
bogus TLS cert is rejected at the TLS layer (system trust store), not
by justsign. Fulcio chain trust is independent: the returned cert
chain is rejected unless it terminates at one of the
caller-supplied `trust_anchors_der` (`sign/src/cert_chain.rs:281`:
`return Err(ChainError::RootNotTrusted …)`).

**Malicious Rekor (compromised log).** `verify_blob` re-runs the
RFC 6962 inclusion proof on every `tlog_entry` against the entry's
claimed root (`sign/src/lib.rs:552`:
`rekor::verify_inclusion(&leaf, log_index, tree_size, &path, &root)?`).
A Rekor that fabricates an inconsistent proof fails. **What this does
NOT catch:** a Rekor that controls both the log AND the bundle producer
can present a self-consistent fake root. The proof is verified against
the bundle's OWN root, not against a trusted witness — the rekor
client's own docs flag this directly (`rekor/src/client.rs:117-120`:
`// using self.root_hash here only proves the proof is internally
consistent, not that the log itself is genuine`). External witness /
checkpoint cosigning is not enforced today (tracked in `#23`).

**Malicious Fulcio (compromised CA).** Chain validation walks every
adjacent pair (`sign/src/cert_chain.rs:235`:
`for i in 0..parsed.len().saturating_sub(1)`) and terminates at a
caller-supplied anchor. A compromised Fulcio CA whose key is in the
caller's `trust_anchors_der` can issue any leaf it likes; justsign
catches this only if the caller ALSO pins `expected_san`. v0 is
exact-string SAN match — pattern matching against issuer-prefix is
not implemented (`sign/src/lib.rs:1024-1026`).

**Malicious signer with valid cert.** A valid Fulcio leaf with an
`expected_san` match passes `verify_blob_keyless`. Attestation policy
is the caller's responsibility: `verify_attestation` enforces
`expected_predicate_type` (`sign/src/lib.rs:775`) and (if pinned)
`expected_subject_digest` (`sign/src/lib.rs:786-795`), but NOT predicate
body schema or builder identity.

**Replay (old valid bundle).** No timestamp gate exists in v0. The
verifier does NOT check `tlog_entry.integrated_time` against any
window; the field is wired through (`sign/src/lib.rs:604`:
`integrated_time: 0,`) but not consulted. A bundle valid on day N
remains valid on day N+365. Tracked in `#26`.

**Stolen OIDC token.** The Fulcio leaf is short-lived (Sigstore default
~10min). Once `#26` lands the cert's `notAfter` will gate verification
(`sign/src/error.rs:157`: `VerifyError::CertExpired { not_after }`,
defined but not constructed today).

## Failure modes

> Note: every "skip" mode below is a deliberate caller-side switch,
> not a verifier bug. The library defaults to "verify what you were
> given"; pinning policy is the caller's job.

- **`rekor: None`** — transparency check is skipped entirely
  (`sign/src/lib.rs:474`: `if let Some(client) = rekor`). The bundle's
  embedded `tlog_entries` are not inspected. Use this only if your
  policy doesn't require transparency.
- **`expected_san: None`** — any leaf whose chain terminates at the
  trust anchors is accepted (`sign/src/lib.rs:1053`:
  `if let Some(expected) = expected_san`). Equivalent to "I trust
  every Fulcio identity equally," which is almost never what callers want.
- **Leaf-only chain (no intermediates / root).** A 1-element
  `chain_der` skips the pairwise loop (`sign/src/cert_chain.rs:235`:
  `0..parsed.len().saturating_sub(1)` is empty for length 1) and goes
  directly to the anchor check. The leaf must itself match an anchor
  by exact DER OR be signed by one. This is rejected for production
  Fulcio bundles (the production chain is leaf+intermediate).
- **`SignedNotRecorded`-equivalent.** No such variant exists in
  `VerifyError` today. `NoTlogEntry` (`sign/src/error.rs:104`) is
  returned when `rekor: Some` is passed but `tlog_entries` is empty —
  policy callers requiring transparency MUST pass `rekor: Some` to
  reach this gate.
- **Clock skew.** `TufClient` enforces TUF role expiry against
  `self.now()` (`tuf/src/client.rs:151`:
  `self.now_override.unwrap_or_else(SystemTime::now)`). Cert chain
  `notBefore`/`notAfter` is NOT enforced (`sign/src/cert_chain.rs:28`:
  `// **Expiry is NOT enforced.**`). Tracked in `#26`.

## Out-of-scope

- **Side-channel attacks on the signing key.** The signing primitives
  come from RustCrypto (`p256`, `ecdsa`); their threat model applies.
- **Malicious TUF mirror serving stale-but-fresh metadata.** TUF's
  threshold model + the role expiry enforced at
  `tuf/src/client.rs:240` handles this within the freshness window.
- **Compromised system CA store** affecting `HttpFulcioClient` /
  `HttpRekorClient` TLS. justsign inherits the system store's trust
  posture; deployments needing a smaller surface should configure
  `reqwest` with a pinned root.

## Verifier checklist

Callers SHOULD enforce these. The library does NOT enforce them
unless the caller passes the relevant policy parameter.

- [ ] **Pin `expected_subject_digest`** when calling
      `verify_attestation`. Passing `None` skips the subject-digest
      gate (`sign/src/lib.rs:786`: `if let Some((algo, hex)) = …`).
- [ ] **Pass `expected_san`** to `verify_blob_keyless`. `None`
      accepts any leaf the trust anchors will issue
      (`sign/src/lib.rs:1053`).
- [ ] **Pass a `RekorClient`** to `verify_blob` if your policy
      requires transparency. `None` skips re-verification entirely
      (`sign/src/lib.rs:474`).
- [ ] **Enforce cert expiry caller-side** until `#26` lands.
      `VerifyError::CertExpired` is defined (`sign/src/error.rs:158`)
      but not constructed by the v0 verifier.
- [ ] **Pin Fulcio trust roots from a TUF-validated source.**
      `TufClient` requires a caller-supplied initial root
      (`tuf/src/client.rs:31`); `#27` tracks bundling a default.
- [ ] **Require `tlog_entries.len() >= 1`** if policy requires
      transparency. The verifier returns `NoTlogEntry`
      (`sign/src/lib.rs:480`) only when `rekor: Some` is passed AND
      the slice is empty.
- [ ] **Validate a trusted Merkle root out-of-band.** Inclusion
      proofs verify against the bundle's own root
      (`rekor/src/client.rs:117-120`); cosign-style witness
      verification is tracked in `#23`.
- [ ] **Pin Bundle JSON shape.** `Bundle::decode_json` accepts the
      Sigstore protobuf JSON shape; drift between the v0.3 spec and
      what the producer emits is tracked in `#31`.
- [ ] **Treat `RekorError` opaquely until `#32` lands.** Granular
      variant routing (network vs malformed-proof vs forged-root) is
      not yet stabilised.
