# justsign value proposition

**Audience**: Project sponsors, prospective users, contributors evaluating whether to adopt or contribute to justsign.

## Numbers at a glance

| | justsign | cosign (subprocess) | sigstore-rs |
|---|---|---|---|
| Dep count (transitive) | **198** | ~300 Go modules | ~300+ Rust crates (est.) |
| Binary size | **4.5 MB** | ~50 MB | N/A (library) |
| Windows native | **yes** | no supported build | yes |
| Sync (blocking) clients | **yes** | yes (subprocess) | no (async-only) |
| Embeddable in Rust | **yes** | no | yes |
| PKCS#11 support | **yes** | via plugin | no |
| MSRV stable | **yes (1.75)** | N/A | no commitment |
| `sign_blob` latency (1 KB) | **234 µs** | ≥ 50 ms (process start) | similar to justsign |

## Why this exists

Sigstore is the industry standard for keyless software signing, but
the existing Rust client surface is structurally awkward for several
production deployment shapes that justsign was built to serve.
`sigstore-rs` (the official Rust client) ships a wide dependency
graph and a layered async API that is hard to thin out; the cosign Go
binary is a clean operator UX but a poor library dependency for a
Rust codebase; and hand-rolling DSSE + Fulcio + Rekor + TUF against
the wire specs is a six-week project that every Rust-side consumer
ends up re-doing badly.

`justsign` is the third option. It is a pure-Rust Sigstore client,
producer, and verifier whose ship-stable surface is six functions:
`sign_blob`, `verify_blob`, `attest`, `verify_attestation`,
`sign_oci`, `verify_oci`, plus the keyless variants. It produces and
verifies Sigstore Bundle v0.3 wire bytes, talks to a real Fulcio and
Rekor over HTTPS, walks a TUF root chain against the Sigstore mirror,
and hosts those clients behind trait SPIs so test doubles cost
nothing.

## Market context

Three alternatives exist today, each with a real but structural cost:

- **`sigstore-rs`** (official Rust client). Comprehensive, but pulls
  a heavy transitive dep graph (TUF, Rekor, Fulcio, OIDC, DSSE all
  routed through their own crates with their own re-exports), and
  the high-level API is pinned to async tokio. For consumers that
  want a thin synchronous library or a clean dep graph for audit, the
  swap cost is high.
- **cosign as a subprocess**. Operationally clean — one binary, well
  documented. Not viable when (a) the consumer wants to ship as a
  single static Rust binary (no `cosign` on `PATH`), (b) the consumer
  targets `wasm32-*` or another platform where shelling out is not an
  option, or (c) the threat model demands an audit-clean process tree
  (no fork/exec of a Go binary inside a signing-critical loop).
- **Hand-rolled crypto + curl**. Always available, always wrong in
  some subtle way (PAE pre-encoding, RFC 6962 leaf-vs-node hashing,
  TUF span-preserving signature verification — each of these has
  silent failure modes that don't surface until production).

`justsign` exists because Rust-side consumers of Sigstore needed a
stack that did not pull `sigstore-rs`'s tree, did not shell out, and
did not require re-implementing DSSE PAE from scratch.

## Target users

- **Platform engineers** building a release pipeline in Rust who
  need a deterministic, dep-light signing library they can pin and
  audit alongside their build tooling.
- **CI/CD operators** running keyless signing in GitHub Actions /
  GCP Cloud Build / on-prem runners who want a single static binary
  rather than a Go subprocess and a shell-script wrapper.
- **Sigstore-curious teams** evaluating Sigstore for their artifact
  pipeline who want a smaller, more legible reference implementation
  to read alongside the spec — one whose modules map 1:1 to the
  Sigstore Bundle v0.3, DSSE, in-toto Statement v1, and Rekor entry
  schemas without intermediate abstraction layers.
- **Embedded / WASM consumers** that cannot use `sigstore-rs`'s async
  surface or cannot fit cosign's binary footprint.

## Non-goals

`justsign` is deliberately scoped to be a producer and consumer
client, not infrastructure:

- **Not a Sigstore service operator.** It does not provision Fulcio
  CA hierarchies, run a Rekor log, or operate trillian. If you are
  hosting Sigstore for your org, you want
  [sigstore/sigstore](https://github.com/sigstore/sigstore), not us.
- **Not a TUF mirror operator.** It walks a TUF root and verifies
  metadata it pulled from a mirror; it does not publish, sign, or
  rotate root keys. The mirror you point it at is yours (or the
  public Sigstore mirror).
- **Not a cosign CLI ergonomic replacement.** The `justsign` binary
  is intentionally minimal — four subcommands today (`sign-blob`,
  `verify-blob`, `generate-key-pair`, `oidc-token`). We are not
  trying to clone every cosign verb. The library is the product;
  the binary is a thin demo.
- **Not a multi-language client.** Rust only. If you need Python,
  use `sigstore-python`; for Go use `cosign`.

The shape of the project — six small workspace crates, ~10 trait
SPIs, default sync with opt-in async — falls out of these
constraints. The README's "What works / What's stub / What's NOT
done" section ([README.md:17](../../README.md)) is the canonical
truth on per-feature status; this document only frames the why.
