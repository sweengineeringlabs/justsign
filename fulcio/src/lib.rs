//! Fulcio client — OIDC token → CSR → short-lived cert chain.
//!
//! v0 surface (kept narrow on purpose):
//!
//! * [`build_csr`] — given an ECDSA P-256 signing key + an OIDC
//!   subject string (e.g. `dev@example.com`), produce a PKCS#10
//!   CSR with the email in a `subjectAltName` extension.
//! * [`parse_chain`] — split the PEM chain Fulcio returns
//!   (leaf-first) into a `Vec<X509Cert>`, where each entry carries
//!   the verbatim DER bytes, the parsed subject, and the SAN.
//! * [`FulcioClient`] — trait with a single
//!   [`sign_csr`](FulcioClient::sign_csr) method.
//!   [`MockFulcioClient`] returns a canned chain; [`HttpFulcioClient`]
//!   talks to a real Fulcio over `POST /api/v2/signingCert`.
//! * [`FulcioError`] — `thiserror`-derived error enum used by the
//!   trait + helpers.
//!
//! What's intentionally out of scope for v0: chain trust validation
//! against TUF (lives in `swe_justsign_tuf`), Rekor proof
//! verification (`swe_justsign_rekor`), async client.

mod chain;
mod client;
mod csr;
mod error;

#[cfg(feature = "async")]
pub mod async_client;

pub use chain::{parse_chain, X509Cert};
pub use client::{CertChain, FulcioClient, HttpFulcioClient, MockFulcioClient};
pub use csr::{build_csr, Csr};
pub use error::FulcioError;

#[cfg(feature = "async")]
pub use async_client::{AsyncFulcioClient, HttpFulcioClientAsync};
