# justsign documentation hub

**Audience**: All readers — start here, then route to the document that matches what you're trying to do.

This hub maps every document in this tree to the audience it was written for. Pick the row that describes you; follow the link.

> mdBook-rendered version at [GitHub Pages](https://sweengineeringlabs.github.io/justsign/) — drives off [`SUMMARY.md`](SUMMARY.md). This README is the **source-tree** entry point; the SUMMARY is the **rendered-site** entry point. Same content, two surfaces.

## WHAT

justsign is a pure-Rust Sigstore client, producer, and verifier. The docs cover what justsign is, how it's put together, how to integrate it, how to develop / test / deploy / operate it, and the security guarantees it offers.

## WHY

The docs are organised around a five-phase OSS-slim SDLC (`0-ideation` / `3-design` / `4-development` / `5-testing` / `6-deployment`) so each reader can drop straight into the phase that matters to them without paging through stages that don't.

## HOW: pick a path

### "I'm evaluating whether to use or contribute to justsign"

→ [`0-ideation/value_proposition.md`](0-ideation/value_proposition.md) — what problem justsign solves, who it's for, where it sits in the Sigstore ecosystem, and the alternatives.

→ [`0-ideation/market_research.md`](0-ideation/market_research.md) — ecosystem survey: existing Rust Sigstore clients, cosign subprocess problems, producer categories who need an embeddable pure-Rust library.

### "I'm an architect or security reviewer — show me the system"

| Doc | What it covers |
|---|---|
| [`3-design/architecture.md`](3-design/architecture.md) | Crate layout, runtime wiring, sign-call data flow, sequence diagrams. Start here. |
| [`3-design/threat_model.md`](3-design/threat_model.md) | What `verify_blob`, `verify_blob_keyless`, `verify_attestation`, `verify_oci` actually guarantee at v0; explicit non-goals. |
| [`3-design/adr/README.md`](3-design/adr/README.md) | Architecture Decision Records — durable rationale for the load-bearing decisions. |
| [`3-design/compliance/compliance_checklist.md`](3-design/compliance/compliance_checklist.md) | Per-PR compliance review against the architectural rules above. |

### "I'm integrating justsign into something else"

→ [`3-design/integration_guide.md`](3-design/integration_guide.md) — three integration shapes (Rust library, CLI binary, sigstore-rs replacement) with worked examples.

### "I'm contributing — how do I build, test, and ship?"

| Doc | What it covers |
|---|---|
| [`4-development/developer_guide.md`](4-development/developer_guide.md) | Local clone-to-PR workflow, build commands, lint / test gates. |
| [`4-development/guide/msrv_policy.md`](4-development/guide/msrv_policy.md) | When MSRV bumps and what that means for downstream. |
| [`4-development/guide/migration_guide.md`](4-development/guide/migration_guide.md) | API changes between justsign releases that need caller adjustment. |
| [`5-testing/testing_strategy.md`](5-testing/testing_strategy.md) | Four-layer test pyramid, regression-test convention, what's NOT yet tested. |

### "I'm operating justsign in a release pipeline"

| Doc | What it covers |
|---|---|
| [`6-deployment/deployment_guide.md`](6-deployment/deployment_guide.md) | Keyless-CI and static-key-with-PKCS#11 release patterns. |
| [`6-deployment/production_round_trip_runbook.md`](6-deployment/production_round_trip_runbook.md) | Operator-actionable cosign-against-production-Sigstore regression check. Re-run on every wire-shape change. |

### "I hit a term I don't know"

→ [`glossary.md`](glossary.md) — alphabetised definitions for every Sigstore-specific and justsign-specific term used in the rest of the docs.

## Repo-root governance files

Outside this `docs/` tree, the repo root carries the standard OSS governance set:

| File | Audience |
|---|---|
| [`../README.md`](../README.md) | First-time visitors — pitch + quickstart + status. |
| [`../CONTRIBUTING.md`](../CONTRIBUTING.md) | Contributors — branch model, commit / PR conventions, lint+test gates. |
| [`../CHANGELOG.md`](../CHANGELOG.md) | Library consumers — Keep-a-Changelog-format release log. |
| [`../SECURITY.md`](../SECURITY.md) | Security researchers — supported versions, private disclosure path, response SLA. |
| [`../CODE_OF_CONDUCT.md`](../CODE_OF_CONDUCT.md) | All participants — Contributor Covenant 2.1, enforcement contact. |
| [`../SUPPORT.md`](../SUPPORT.md) | Users with a question — where to ask, what gets answered, what doesn't. |
| [`../LICENSE`](../LICENSE) | Library consumers — MIT licence text. |

## SDLC phase reference

Numbered directories follow the [template-engine framework](../README.md#what-s-not-done) SDLC convention. Justsign uses an OSS-slim subset:

| Phase | Folder | Purpose |
|---|---|---|
| 0 | [`0-ideation/`](0-ideation/) | Research & exploration — why justsign exists, alternatives surveyed. |
| 3 | [`3-design/`](3-design/) | How it works — architecture, ADRs, threat model, compliance checklist. |
| 4 | [`4-development/`](4-development/) | How to develop — setup, MSRV, migration. |
| 5 | [`5-testing/`](5-testing/) | Test strategy — layers, conventions, gaps. |
| 6 | [`6-deployment/`](6-deployment/) | How to deploy — release patterns, production round-trip runbook. |

Phases 1 (requirements), 2 (planning), and 7 (operation) are intentionally absent — justsign is a library, not a service, and the phases that matter for service-shaped projects don't apply. Add them if a future operational concern demands one.
