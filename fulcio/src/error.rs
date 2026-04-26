//! Error type for the v0 Fulcio surface.
//!
//! One enum, `thiserror`-derived. Each variant names the actual
//! failure mode rather than aliasing a foreign error verbatim, so
//! callers can match without depending on `reqwest` / `pem` /
//! `x509-cert` themselves.

use thiserror::Error;

/// Errors surfaced by the Fulcio client + CSR + chain helpers.
#[derive(Debug, Error)]
pub enum FulcioError {
    /// Transport-level failure talking to a Fulcio HTTP endpoint.
    /// Wraps a `reqwest::Error` (connect, TLS, status, body read).
    #[error("HTTP transport error: {0}")]
    Http(#[from] reqwest::Error),

    /// Fulcio returned a non-2xx status. The body is captured raw
    /// because Fulcio's error shape is not stable across versions.
    #[error("fulcio HTTP {status}: {body}")]
    Status {
        /// HTTP status code.
        status: u16,
        /// Response body, lossily UTF-8-decoded.
        body: String,
    },

    /// PEM decode failed when splitting the cert chain.
    #[error("PEM decode error: {0}")]
    Pem(#[from] pem::PemError),

    /// X.509 parse failed on a DER-encoded leaf or intermediate.
    /// Wraps the underlying `der` error message; the variant is
    /// named X509 because it's surfaced from x509-cert decoding.
    #[error("X.509 parse error: {0}")]
    X509(String),

    /// Fulcio returned an empty PEM chain. Always a server bug or
    /// malformed mock — there must be at least a leaf.
    #[error("fulcio returned an empty cert chain")]
    EmptyChain,

    /// The Subject Alternative Name extension in the leaf cert
    /// did not match the OIDC subject the caller asked Fulcio for,
    /// or was malformed in a way the v0 client refuses to accept.
    #[error("bad SAN extension: {detail}")]
    BadSan {
        /// Human-readable explanation of what was wrong.
        detail: String,
    },

    /// CSR construction failed — DER encoding or signing returned
    /// an error. Wraps a stringified inner error so we don't leak
    /// `der` / `signature` types into the public API.
    #[error("CSR build error: {0}")]
    Csr(String),
}
