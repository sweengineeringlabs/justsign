//! OIDC identity-token providers for keyless signing.
//!
//! Sigstore's keyless flow needs a JWT whose `aud` claim is
//! `sigstore`. The JWT is then handed to Fulcio in exchange for a
//! short-lived signing certificate. This module ONLY surfaces the
//! token; it does NOT call Fulcio. The caller (typically the CLI
//! or a higher-level keyless-sign helper) wires the token into
//! [`fulcio::FulcioClient::sign_csr`].
//!
//! ## Provider catalogue
//!
//! Four [`OidcProvider`] impls cover the v0 use-cases:
//!
//! * [`StaticOidcProvider`] — reads `SIGSTORE_ID_TOKEN` /
//!   `OIDC_TOKEN` from the process environment. The default fallback;
//!   matches the precedence used by `attest/sigstore_invoker` in
//!   justoci, which pre-dates this module.
//! * [`GitHubActionsOidcProvider`] — calls the GHA token-issuance
//!   endpoint (`ACTIONS_ID_TOKEN_REQUEST_URL` +
//!   `ACTIONS_ID_TOKEN_REQUEST_TOKEN`) and pulls the `value` field
//!   out of the JSON response.
//! * [`GcpMetadataOidcProvider`] — calls the GCE metadata server
//!   for an instance-identity token. The response body is the JWT
//!   verbatim (no JSON wrapper).
//! * [`InteractiveBrowserOidcProvider`] — opens a browser, listens on
//!   localhost for the OAuth-redirect, exchanges the code for an
//!   `id_token`. Cosign's `--oidc-issuer` flow uses the same shape.
//!   Gated behind the `oidc-browser` feature because it pulls the
//!   `open` crate.
//!
//! ## Which provider should I use?
//!
//! ```text
//! In CI on GitHub Actions ........ GitHubActionsOidcProvider
//! On a GCE / GKE node ............ GcpMetadataOidcProvider
//! Operator at a workstation ...... InteractiveBrowserOidcProvider
//! Token already in env ........... StaticOidcProvider
//! ```
//!
//! ## v0 limitations
//!
//! * No token caching — each [`OidcProvider::fetch_token`] call goes
//!   over the wire (for the network providers). Fulcio certs are
//!   short-lived (~10 minutes) so a cache would only help if multiple
//!   signs ran inside that window.
//! * No JWT validation — the providers return whatever string the
//!   issuer hands back. Fulcio re-validates on its end; making the
//!   provider a second validator would only duplicate that work.
//! * The interactive-browser provider does NOT do PKCE in v0. The
//!   `redirect_uri=http://localhost:<port>/` callback prevents code
//!   leakage to a third party already; PKCE adds defense-in-depth
//!   and lands in a follow-up.

#![cfg(feature = "oidc")]

pub mod gcp_metadata;
pub mod github_actions;
#[cfg(feature = "oidc-browser")]
pub mod interactive_browser;
pub mod static_provider;

pub use gcp_metadata::GcpMetadataOidcProvider;
pub use github_actions::GitHubActionsOidcProvider;
#[cfg(feature = "oidc-browser")]
pub use interactive_browser::InteractiveBrowserOidcProvider;
pub use static_provider::StaticOidcProvider;

/// Common surface every OIDC provider implements.
///
/// `Send + Sync` so callers can stash a `Box<dyn OidcProvider>` in
/// long-lived state shared across threads — the providers themselves
/// are stateless (they read the env or hit the network on each
/// call), so the trait-object shape is honest.
///
/// The returned `String` is a JWT in compact-serialisation form —
/// `<header>.<payload>.<signature>` — ready to drop into Fulcio's
/// `Authorization: Bearer <token>` request.
pub trait OidcProvider: Send + Sync {
    /// Fetch a fresh OIDC ID token. May block (network calls,
    /// listener accept). Returns the token verbatim — no parsing,
    /// no normalisation; the caller pipes it to Fulcio as-is.
    fn fetch_token(&self) -> Result<String, OidcError>;
}

/// Failure surface common to every [`OidcProvider`] impl.
///
/// Construction sites are tightly scoped per provider:
///
/// * `EnvVarMissing` — Static + GHA (env-driven config).
/// * `Http` / `HttpStatus` — GHA + GCP (over-the-wire fetch).
/// * `BrowserLaunchFailed` / `RedirectListenerFailed` / `Timeout` —
///   InteractiveBrowser only.
///
/// Variant names are stable across the trait so callers can route on
/// the typed shape without caring which provider produced it.
#[derive(Debug, thiserror::Error)]
pub enum OidcError {
    /// A required env var is unset or empty. Surfaces from
    /// [`StaticOidcProvider`] when none of the configured names are
    /// set, and from [`GitHubActionsOidcProvider`] when the GHA
    /// runner did NOT inject `ACTIONS_ID_TOKEN_REQUEST_URL` /
    /// `ACTIONS_ID_TOKEN_REQUEST_TOKEN` (most commonly: the workflow
    /// forgot `permissions: id-token: write`).
    #[error("oidc: required env var '{name}' is unset or empty")]
    EnvVarMissing { name: String },

    /// The interactive browser launch failed. The provider falls back
    /// to printing the URL to stderr and continues — this variant is
    /// surfaced only when the operator opted out of the fallback or
    /// the listener also failed afterwards. Held as `String` so we
    /// don't leak the underlying `open::Error` shape.
    #[error("oidc: failed to launch browser: {0}")]
    BrowserLaunchFailed(String),

    /// Couldn't bind the localhost listener for the OAuth redirect,
    /// or the listener accept-loop failed before a request arrived.
    /// Most common cause: the requested port is already bound by
    /// another process.
    #[error("oidc: failed to start redirect listener: {0}")]
    RedirectListenerFailed(String),

    /// HTTP transport error (DNS, connect, TLS, body decode). Distinct
    /// from `HttpStatus` so callers can decide whether to retry: a
    /// transport error is usually transient; a 4xx is usually not.
    #[error("oidc: http transport error: {0}")]
    Http(String),

    /// HTTP request reached the server but came back with a non-2xx
    /// status. Body is included so operators can read the issuer's
    /// error message without re-running with verbose logs.
    #[error("oidc: http status {status}: {body}")]
    HttpStatus {
        /// HTTP status code (e.g. 401, 403, 500).
        status: u16,
        /// Response body verbatim (truncated by the provider if huge;
        /// providers cap at a few KB to keep error messages bounded).
        body: String,
    },

    /// The interactive-browser provider waited for the OAuth redirect
    /// but never got one within the configured deadline.
    #[error("oidc: timed out waiting for browser redirect")]
    Timeout,
}
