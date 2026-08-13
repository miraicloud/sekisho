//! Boot configuration. Delivered in production by argonaut's one-shot boot
//! config over VSOCK (`docs/SPEC.md` §4) and written to a JSON file at the
//! path named by `SEKISHO_CONFIG`; this module just reads that path. Falls
//! back to individual env vars for local dev when `SEKISHO_CONFIG` is unset.
//!
//! **Security property (SPEC §4, load-bearing):** provider base URLs are
//! NOT part of this config. They are compile-time constants in
//! `providers::anthropic`/`providers::openai`, covered by the PCR
//! measurement of the image. If they came from boot config, an operator
//! could point an adapter at a server they control and still emit receipts
//! that verify onchain. `RawConfig` therefore has no base-URL field, and
//! `#[serde(deny_unknown_fields)]` rejects a config file that tries to add
//! one rather than silently ignoring it.
//!
//! `config_hash` covers the policy document only — never secrets — so key
//! rotation doesn't change the attested policy identity and no secret is
//! ever hash-committed into a public receipt.

use serde::Deserialize;

use crate::canonical::sha256_of;
use crate::policy::{CompiledPolicy, PolicyDocument, PolicyLoadError};
use crate::receipt::DEFAULT_RING_BUFFER_SIZE;
use crate::server::{DEFAULT_CONCURRENCY_LIMIT, DEFAULT_MAX_BODY_BYTES};

/// Raw config as parsed from the boot-config JSON file. Deliberately has NO
/// provider base-URL field — see module docs.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    /// Anthropic API key (`x-api-key`). Absent/empty disables `/v1/messages`.
    #[serde(default)]
    anthropic_api_key: Option<String>,
    /// OpenAI-compatible API key (`Authorization: Bearer`). Absent/empty
    /// disables `/v1/chat/completions`.
    #[serde(default)]
    openai_api_key: Option<String>,
    /// Bearer keys accepted from callers of this gateway.
    caller_keys: Vec<String>,
    policy: PolicyDocument,
    #[serde(default = "default_max_body_bytes")]
    max_body_bytes: usize,
    #[serde(default = "default_concurrency_limit")]
    concurrency_limit: usize,
    #[serde(default = "default_ring_buffer_size")]
    receipt_ring_buffer_size: usize,
}

const fn default_max_body_bytes() -> usize {
    DEFAULT_MAX_BODY_BYTES
}

const fn default_concurrency_limit() -> usize {
    DEFAULT_CONCURRENCY_LIMIT
}

const fn default_ring_buffer_size() -> usize {
    DEFAULT_RING_BUFFER_SIZE
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file {path:?}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse config JSON: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("failed to hash policy JSON: {0}")]
    Hash(serde_json::Error),
    #[error("invalid policy: {0}")]
    Policy(#[from] PolicyLoadError),
    #[error("no caller_keys configured; the gateway would accept no authenticated callers")]
    NoCallerKeys,
}

/// The fully loaded, validated boot configuration. Secrets (`anthropic_api_key`,
/// `openai_api_key`, `caller_keys`) live here, never in `config_hash`.
pub struct AppConfig {
    pub anthropic_api_key: Option<String>,
    pub openai_api_key: Option<String>,
    pub caller_keys: Vec<String>,
    pub policy: CompiledPolicy,
    pub max_body_bytes: usize,
    pub concurrency_limit: usize,
    pub receipt_ring_buffer_size: usize,
    /// SHA-256 of the canonical policy JSON only. Computed once at boot.
    pub config_hash: [u8; 32],
}

impl AppConfig {
    /// Loads config from `SEKISHO_CONFIG` (a JSON file path) if set,
    /// otherwise falls back to individual `SEKISHO_*` env vars for dev.
    pub fn load_from_env() -> Result<Self, ConfigError> {
        match std::env::var("SEKISHO_CONFIG") {
            Ok(path) => Self::load_from_file(&path),
            Err(_) => Self::load_from_dev_env(),
        }
    }

    pub fn load_from_file(path: &str) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_owned(),
            source,
        })?;
        let raw: RawConfig = serde_json::from_str(&contents)?;
        Self::from_raw(raw)
    }

    /// Dev-only fallback: builds a `RawConfig` from individual env vars.
    /// `SEKISHO_CALLER_KEYS` is comma-separated; `SEKISHO_POLICY_JSON` is an
    /// inline JSON `PolicyDocument`, defaulting to an allow-all policy with
    /// no caps if unset (dev convenience only — never used in production,
    /// where `SEKISHO_CONFIG` is always set by the boot-config delivery
    /// path).
    fn load_from_dev_env() -> Result<Self, ConfigError> {
        let caller_keys = std::env::var("SEKISHO_CALLER_KEYS")
            .ok()
            .map(|value| {
                value
                    .split(',')
                    .map(str::trim)
                    .filter(|item| !item.is_empty())
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let policy: PolicyDocument = match std::env::var("SEKISHO_POLICY_JSON") {
            Ok(json) => serde_json::from_str(&json)?,
            Err(_) => PolicyDocument {
                rules: vec![crate::policy::PolicyRule {
                    name: "dev-allow-all".to_owned(),
                    action: crate::policy::PolicyAction::Allow,
                    enabled: true,
                    caller_keys: None,
                    allowed_models: None,
                    max_tokens: None,
                    max_request_bytes: None,
                }],
            },
        };

        let raw = RawConfig {
            anthropic_api_key: nonempty_env("SEKISHO_ANTHROPIC_API_KEY"),
            openai_api_key: nonempty_env("SEKISHO_OPENAI_API_KEY"),
            caller_keys,
            policy,
            max_body_bytes: default_max_body_bytes(),
            concurrency_limit: default_concurrency_limit(),
            receipt_ring_buffer_size: default_ring_buffer_size(),
        };
        Self::from_raw(raw)
    }

    fn from_raw(raw: RawConfig) -> Result<Self, ConfigError> {
        if raw.caller_keys.is_empty() {
            return Err(ConfigError::NoCallerKeys);
        }
        let config_hash = sha256_of(&raw.policy).map_err(ConfigError::Hash)?;
        let policy = CompiledPolicy::compile(&raw.policy)?;

        Ok(Self {
            anthropic_api_key: raw.anthropic_api_key,
            openai_api_key: raw.openai_api_key,
            caller_keys: raw.caller_keys,
            policy,
            max_body_bytes: raw.max_body_bytes,
            concurrency_limit: raw.concurrency_limit,
            receipt_ring_buffer_size: raw.receipt_ring_buffer_size,
            config_hash,
        })
    }
}

fn nonempty_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_json() -> serde_json::Value {
        serde_json::json!({
            "caller_keys": ["sk-test"],
            "policy": { "rules": [] }
        })
    }

    #[test]
    fn rejects_unknown_top_level_field_including_a_base_url_attempt() {
        // The load-bearing security test: a config file cannot smuggle in a
        // provider base URL override. `deny_unknown_fields` rejects it at
        // load rather than silently accepting/ignoring it.
        let mut value = minimal_json();
        value["anthropic_base_url"] = serde_json::json!("https://evil.example.com");
        let result: Result<RawConfig, _> = serde_json::from_value(value);
        assert!(
            result.is_err(),
            "config with a base-url field must be rejected at load"
        );
    }

    #[test]
    fn openai_base_url_field_is_also_rejected() {
        let mut value = minimal_json();
        value["openai_base_url"] = serde_json::json!("https://evil.example.com");
        let result: Result<RawConfig, _> = serde_json::from_value(value);
        assert!(result.is_err());
    }

    #[test]
    fn config_hash_covers_policy_only_not_secrets() {
        let mut a = minimal_json();
        a["anthropic_api_key"] = serde_json::json!("secret-a");
        let mut b = minimal_json();
        b["anthropic_api_key"] = serde_json::json!("secret-b-totally-different");

        let raw_a: RawConfig = serde_json::from_value(a).unwrap();
        let raw_b: RawConfig = serde_json::from_value(b).unwrap();
        let config_a = AppConfig::from_raw(raw_a).unwrap();
        let config_b = AppConfig::from_raw(raw_b).unwrap();

        // Same policy, different secrets => identical config_hash.
        assert_eq!(config_a.config_hash, config_b.config_hash);
    }

    #[test]
    fn config_hash_changes_when_policy_changes() {
        let a = minimal_json();
        let mut b = minimal_json();
        b["policy"]["rules"] = serde_json::json!([{ "name": "r", "allowed_models": ["*"] }]);

        let raw_a: RawConfig = serde_json::from_value(a).unwrap();
        let raw_b: RawConfig = serde_json::from_value(b).unwrap();
        let config_a = AppConfig::from_raw(raw_a).unwrap();
        let config_b = AppConfig::from_raw(raw_b).unwrap();

        assert_ne!(config_a.config_hash, config_b.config_hash);
    }

    #[test]
    fn empty_caller_keys_is_rejected() {
        let mut value = minimal_json();
        value["caller_keys"] = serde_json::json!([]);
        let raw: RawConfig = serde_json::from_value(value).unwrap();
        assert!(matches!(
            AppConfig::from_raw(raw),
            Err(ConfigError::NoCallerKeys)
        ));
    }
}
