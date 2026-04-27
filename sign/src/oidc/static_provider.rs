//! [`StaticOidcProvider`] — env-var driven OIDC token resolver.
//!
//! Reads from a configurable list of env-var names in priority order
//! and returns the first non-empty value. Empty strings are treated
//! as unset; CI templates frequently expand to the empty string when
//! a variable is intentionally unconfigured (e.g.
//! `SIGSTORE_ID_TOKEN=${TOKEN_VAR:-}`), and treating those as "the
//! token" would push a garbage value at Fulcio.

use super::{OidcError, OidcProvider};

/// OIDC provider that reads a JWT directly from a configurable list
/// of env vars.
///
/// The default constructor mirrors the precedence used by the
/// `attest::sigstore_invoker` helper in justoci:
///
/// 1. `SIGSTORE_ID_TOKEN` — sigstore convention; what cosign and the
///    Sigstore Rust SDK both check first.
/// 2. `OIDC_TOKEN` — generic fallback used by some CI templates.
///
/// Custom env-var sets are accepted via [`StaticOidcProvider::new`]
/// for callers that wire to a non-standard ambient identity (e.g.
/// `WORKLOAD_IDENTITY_TOKEN`).
#[derive(Debug, Clone)]
pub struct StaticOidcProvider {
    /// Env-var names to consult, in priority order.
    env_vars: Vec<String>,
}

impl StaticOidcProvider {
    /// Build a provider that consults the supplied env-var names in
    /// priority order. Empty input vector is allowed but means
    /// `fetch_token` will always return `EnvVarMissing` — useful only
    /// in tests that want to exercise the no-vars path.
    pub fn new(env_vars: Vec<String>) -> Self {
        Self { env_vars }
    }
}

impl Default for StaticOidcProvider {
    fn default() -> Self {
        Self::new(vec![
            "SIGSTORE_ID_TOKEN".to_string(),
            "OIDC_TOKEN".to_string(),
        ])
    }
}

impl OidcProvider for StaticOidcProvider {
    fn fetch_token(&self) -> Result<String, OidcError> {
        // Walk env vars in declared priority order. An empty string
        // is treated as "unset" — see the module docstring for why.
        for name in &self.env_vars {
            match std::env::var(name) {
                Ok(v) if !v.is_empty() => return Ok(v),
                _ => continue,
            }
        }
        // Surface the FIRST configured name in the error so the
        // operator's first instinct ("set $NAME") matches the most
        // sigstore-canonical variable.
        let first = self
            .env_vars
            .first()
            .cloned()
            .unwrap_or_else(|| "SIGSTORE_ID_TOKEN".to_string());
        Err(OidcError::EnvVarMissing { name: first })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Serialises tests that mutate process-global env vars so cargo's
    /// default parallel test runner doesn't observe transient state
    /// across sibling tests. Pattern matches the justoci helper that
    /// owns the canonical env-precedence test.
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    /// SIGSTORE_ID_TOKEN beats OIDC_TOKEN when both are set; OIDC_TOKEN
    /// wins when only it is set; both unset returns the typed
    /// `EnvVarMissing` error.
    ///
    /// Bug it catches: a regression that swaps the precedence (or
    /// drops one of the two names) would silently grab the wrong
    /// token in CI environments where both are set — exactly the
    /// scenario the justoci sibling test pins.
    #[test]
    fn test_fetch_token_with_both_env_vars_prefers_sigstore_id_token() {
        let _g = ENV_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        let prev_sig = std::env::var("SIGSTORE_ID_TOKEN").ok();
        let prev_oidc = std::env::var("OIDC_TOKEN").ok();

        std::env::set_var("SIGSTORE_ID_TOKEN", "sigstore-wins");
        std::env::set_var("OIDC_TOKEN", "oidc-loses");
        let provider = StaticOidcProvider::default();
        assert_eq!(provider.fetch_token().unwrap(), "sigstore-wins");

        std::env::remove_var("SIGSTORE_ID_TOKEN");
        assert_eq!(provider.fetch_token().unwrap(), "oidc-loses");

        std::env::remove_var("OIDC_TOKEN");
        let err = provider.fetch_token().expect_err("both unset must err");
        match err {
            OidcError::EnvVarMissing { name } => {
                assert_eq!(name, "SIGSTORE_ID_TOKEN");
            }
            other => panic!("expected EnvVarMissing, got {other:?}"),
        }

        // Restore, in case sibling tests in the same process expect
        // the env they entered with.
        if let Some(v) = prev_sig {
            std::env::set_var("SIGSTORE_ID_TOKEN", v);
        }
        if let Some(v) = prev_oidc {
            std::env::set_var("OIDC_TOKEN", v);
        }
    }

    /// An empty-string env var is treated as unset and the provider
    /// falls through to the next name in the list.
    ///
    /// Bug it catches: CI templates that expand to `""` when a token
    /// is unconfigured would otherwise hand an empty string to
    /// Fulcio, which fails with a confusing "Malformed JWT" error.
    /// The empty-as-unset rule keeps the operator-facing message
    /// pinned to the actionable "env var unset" wording.
    #[test]
    fn test_fetch_token_with_empty_env_var_falls_through_to_next() {
        let _g = ENV_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        let prev_sig = std::env::var("SIGSTORE_ID_TOKEN").ok();
        let prev_oidc = std::env::var("OIDC_TOKEN").ok();

        std::env::set_var("SIGSTORE_ID_TOKEN", "");
        std::env::set_var("OIDC_TOKEN", "fallback-token");
        let provider = StaticOidcProvider::default();
        assert_eq!(provider.fetch_token().unwrap(), "fallback-token");

        std::env::remove_var("SIGSTORE_ID_TOKEN");
        std::env::remove_var("OIDC_TOKEN");
        if let Some(v) = prev_sig {
            std::env::set_var("SIGSTORE_ID_TOKEN", v);
        }
        if let Some(v) = prev_oidc {
            std::env::set_var("OIDC_TOKEN", v);
        }
    }

    /// A custom env-var list (no defaults) is honoured verbatim and
    /// names from the default list are NOT consulted.
    ///
    /// Bug it catches: a constructor that silently merges the
    /// caller's list with the defaults would leak an ambient
    /// SIGSTORE_ID_TOKEN into a flow that explicitly opted into
    /// e.g. WORKLOAD_IDENTITY_TOKEN only.
    #[test]
    fn test_fetch_token_with_custom_env_var_list_ignores_defaults() {
        let _g = ENV_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        let prev_sig = std::env::var("SIGSTORE_ID_TOKEN").ok();
        let prev_custom = std::env::var("CUSTOM_OIDC_TOKEN_FOR_TEST").ok();

        std::env::set_var("SIGSTORE_ID_TOKEN", "would-be-leaked");
        std::env::set_var("CUSTOM_OIDC_TOKEN_FOR_TEST", "custom-value");
        let provider = StaticOidcProvider::new(vec!["CUSTOM_OIDC_TOKEN_FOR_TEST".to_string()]);
        assert_eq!(provider.fetch_token().unwrap(), "custom-value");

        std::env::remove_var("CUSTOM_OIDC_TOKEN_FOR_TEST");
        let err = provider
            .fetch_token()
            .expect_err("custom var unset must err");
        match err {
            OidcError::EnvVarMissing { name } => {
                assert_eq!(name, "CUSTOM_OIDC_TOKEN_FOR_TEST");
            }
            other => panic!("expected EnvVarMissing, got {other:?}"),
        }

        std::env::remove_var("SIGSTORE_ID_TOKEN");
        if let Some(v) = prev_sig {
            std::env::set_var("SIGSTORE_ID_TOKEN", v);
        }
        if let Some(v) = prev_custom {
            std::env::set_var("CUSTOM_OIDC_TOKEN_FOR_TEST", v);
        }
    }
}
