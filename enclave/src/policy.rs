//! Policy engine: onara's design (`docs/research/local-patterns.md` §2.1)
//! ported to Rust — JSON policies validated fail-fast at boot, precompiled
//! into cheap-to-evaluate matchers, deny-first then allow-first-match with
//! soft-skip on a non-matching constraint (so one policy's mismatch doesn't
//! abort evaluation of the rest).
//!
//! v1 rule vocabulary (`docs/SPEC.md` §4): allowed models (exact/wildcard)
//! per caller key, a `max_tokens` cap, and a `max_request_bytes` cap.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAction {
    Allow,
    Deny,
}

fn default_action() -> PolicyAction {
    PolicyAction::Allow
}

fn default_true() -> bool {
    true
}

/// Raw, on-the-wire policy rule as delivered in boot config JSON.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRule {
    pub name: String,
    #[serde(default = "default_action")]
    pub action: PolicyAction,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Bearer caller keys this rule applies to. `None` = applies to every caller.
    #[serde(default)]
    pub caller_keys: Option<Vec<String>>,
    /// Exact or `*`-suffix wildcard model patterns (e.g. `"claude-*"`).
    /// `None` = no model restriction.
    #[serde(default)]
    pub allowed_models: Option<Vec<String>>,
    #[serde(default)]
    pub max_tokens: Option<u64>,
    #[serde(default)]
    pub max_request_bytes: Option<usize>,
}

/// Top-level policy document. This is the exact struct whose canonical JSON
/// is SHA-256'd into `config_hash` — it must never contain secrets.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDocument {
    pub rules: Vec<PolicyRule>,
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyLoadError {
    #[error("policy rule {name:?} is invalid: {reason}")]
    InvalidRule { name: String, reason: String },
}

/// A precompiled model matcher: either an exact-match set or a set of
/// prefix (wildcard) patterns, split apart once at load time so per-request
/// evaluation never re-parses a pattern string.
#[derive(Debug, Clone)]
enum ModelMatcher {
    Exact(std::collections::HashSet<String>),
    Prefix(Vec<String>),
    Mixed {
        exact: std::collections::HashSet<String>,
        prefixes: Vec<String>,
    },
}

impl ModelMatcher {
    fn compile(patterns: &[String]) -> Self {
        let mut exact = std::collections::HashSet::new();
        let mut prefixes = Vec::new();
        for pattern in patterns {
            if let Some(prefix) = pattern.strip_suffix('*') {
                prefixes.push(prefix.to_owned());
            } else {
                exact.insert(pattern.clone());
            }
        }
        match (exact.is_empty(), prefixes.is_empty()) {
            (false, true) => Self::Exact(exact),
            (true, false) => Self::Prefix(prefixes),
            _ => Self::Mixed { exact, prefixes },
        }
    }

    fn matches(&self, model: &str) -> bool {
        match self {
            Self::Exact(set) => set.contains(model),
            Self::Prefix(prefixes) => prefixes.iter().any(|p| model.starts_with(p.as_str())),
            Self::Mixed { exact, prefixes } => {
                exact.contains(model) || prefixes.iter().any(|p| model.starts_with(p.as_str()))
            }
        }
    }
}

#[derive(Debug, Clone)]
struct CompiledRule {
    name: String,
    caller_keys: Option<std::collections::HashSet<String>>,
    model_matcher: Option<ModelMatcher>,
    max_tokens: Option<u64>,
    max_request_bytes: Option<usize>,
}

impl CompiledRule {
    fn applies_to_caller(&self, caller_key: &str) -> bool {
        match &self.caller_keys {
            None => true,
            Some(keys) => keys.contains(caller_key),
        }
    }
}

/// A policy document parsed and precompiled once at boot.
#[derive(Debug, Clone)]
pub struct CompiledPolicy {
    deny: Vec<CompiledRule>,
    allow: Vec<CompiledRule>,
}

/// Why a request failed policy evaluation, with per-rule diagnostics
/// (mirrors onara's `policyErrors` aggregation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDenial {
    pub reason: String,
}

pub struct EvaluationRequest<'a> {
    pub caller_key: &'a str,
    pub model: &'a str,
    pub max_tokens: Option<u64>,
    pub request_bytes: usize,
}

impl CompiledPolicy {
    /// Validates and precompiles a raw policy document. Fails fast on any
    /// structurally invalid rule (empty name, etc.) — mirrors onara's
    /// "malformed policy throws at cold start, not per-request".
    pub fn compile(document: &PolicyDocument) -> Result<Self, PolicyLoadError> {
        let mut deny = Vec::new();
        let mut allow = Vec::new();

        for rule in &document.rules {
            if !rule.enabled {
                continue;
            }
            if rule.name.trim().is_empty() {
                return Err(PolicyLoadError::InvalidRule {
                    name: rule.name.clone(),
                    reason: "rule name must not be empty".to_owned(),
                });
            }
            let compiled = CompiledRule {
                name: rule.name.clone(),
                caller_keys: rule
                    .caller_keys
                    .as_ref()
                    .map(|keys| keys.iter().cloned().collect()),
                model_matcher: rule.allowed_models.as_deref().map(ModelMatcher::compile),
                max_tokens: rule.max_tokens,
                max_request_bytes: rule.max_request_bytes,
            };
            match rule.action {
                PolicyAction::Deny => deny.push(compiled),
                PolicyAction::Allow => allow.push(compiled),
            }
        }

        Ok(Self { deny, allow })
    }

    /// Deny-first (any match rejects immediately, regardless of config
    /// order), then allow-first-match with soft-skip on a non-matching
    /// constraint. No matching allow rule => denied, with aggregated
    /// per-rule diagnostics.
    pub fn evaluate(&self, request: &EvaluationRequest<'_>) -> Result<&str, PolicyDenial> {
        for rule in &self.deny {
            if !rule.applies_to_caller(request.caller_key) {
                continue;
            }
            let model_ok = rule
                .model_matcher
                .as_ref()
                .is_none_or(|matcher| matcher.matches(request.model));
            if model_ok {
                return Err(PolicyDenial {
                    reason: format!("denied by policy {:?}", rule.name),
                });
            }
        }

        let mut errors = Vec::new();
        for rule in &self.allow {
            if !rule.applies_to_caller(request.caller_key) {
                continue;
            }
            if let Some(matcher) = &rule.model_matcher
                && !matcher.matches(request.model)
            {
                errors.push(format!(
                    "{}: model {:?} not allowed",
                    rule.name, request.model
                ));
                continue;
            }
            // An absent max_tokens means "whatever the model will emit", which
            // is unbounded and therefore exceeds any cap — it must not slip
            // past the check. max_tokens is required on the Anthropic surface
            // but optional on the OpenAI-compatible one, so treating None as
            // "no violation" would let a caller bypass the cap by omitting the
            // field.
            if let Some(cap) = rule.max_tokens {
                match request.max_tokens {
                    Some(requested) if requested > cap => {
                        errors.push(format!(
                            "{}: max_tokens {requested} exceeds cap {cap}",
                            rule.name
                        ));
                        continue;
                    }
                    None => {
                        errors.push(format!(
                            "{}: request omits max_tokens (unbounded) but the rule caps it at {cap}",
                            rule.name
                        ));
                        continue;
                    }
                    Some(_) => {}
                }
            }
            if let Some(cap) = rule.max_request_bytes
                && request.request_bytes > cap
            {
                errors.push(format!(
                    "{}: request_bytes {} exceeds cap {cap}",
                    rule.name, request.request_bytes
                ));
                continue;
            }
            return Ok(rule.name.as_str());
        }

        Err(PolicyDenial {
            reason: if errors.is_empty() {
                "no policy matched this caller".to_owned()
            } else {
                errors.join(" | ")
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(rules: Vec<PolicyRule>) -> PolicyDocument {
        PolicyDocument { rules }
    }

    fn rule(name: &str) -> PolicyRule {
        PolicyRule {
            name: name.to_owned(),
            action: PolicyAction::Allow,
            enabled: true,
            caller_keys: None,
            allowed_models: None,
            max_tokens: None,
            max_request_bytes: None,
        }
    }

    #[test]
    fn deny_wins_regardless_of_order() {
        let mut allow_all = rule("allow-all");
        allow_all.allowed_models = Some(vec!["*".to_owned()]);
        let mut deny_bad = rule("deny-bad-key");
        deny_bad.action = PolicyAction::Deny;
        deny_bad.caller_keys = Some(vec!["bad".to_owned()]);

        let policy = CompiledPolicy::compile(&doc(vec![allow_all, deny_bad])).unwrap();

        let request = EvaluationRequest {
            caller_key: "bad",
            model: "claude-sonnet-5",
            max_tokens: Some(100),
            request_bytes: 10,
        };
        assert!(policy.evaluate(&request).is_err());
    }

    #[test]
    fn wildcard_model_matches_prefix() {
        let mut allow = rule("allow-claude");
        allow.allowed_models = Some(vec!["claude-*".to_owned()]);
        let policy = CompiledPolicy::compile(&doc(vec![allow])).unwrap();

        assert!(
            policy
                .evaluate(&EvaluationRequest {
                    caller_key: "any",
                    model: "claude-sonnet-5",
                    max_tokens: None,
                    request_bytes: 1,
                })
                .is_ok()
        );
        assert!(
            policy
                .evaluate(&EvaluationRequest {
                    caller_key: "any",
                    model: "gpt-5.2",
                    max_tokens: None,
                    request_bytes: 1,
                })
                .is_err()
        );
    }

    /// Omitting max_tokens must not bypass a cap: it is optional on the
    /// OpenAI-compatible surface, where absent means "model default", i.e.
    /// unbounded.
    #[test]
    fn max_tokens_cap_denies_a_request_that_omits_max_tokens() {
        let mut allow = rule("capped");
        allow.max_tokens = Some(4096);
        let policy = CompiledPolicy::compile(&doc(vec![allow])).unwrap();

        assert!(
            policy
                .evaluate(&EvaluationRequest {
                    caller_key: "any",
                    model: "m",
                    max_tokens: None,
                    request_bytes: 1,
                })
                .is_err()
        );
    }

    /// A rule with no cap still accepts an unbounded request.
    #[test]
    fn uncapped_rule_allows_a_request_that_omits_max_tokens() {
        let policy = CompiledPolicy::compile(&doc(vec![rule("uncapped")])).unwrap();

        assert!(
            policy
                .evaluate(&EvaluationRequest {
                    caller_key: "any",
                    model: "m",
                    max_tokens: None,
                    request_bytes: 1,
                })
                .is_ok()
        );
    }

    #[test]
    fn max_tokens_cap_denies_when_exceeded() {
        let mut allow = rule("capped");
        allow.max_tokens = Some(4096);
        let policy = CompiledPolicy::compile(&doc(vec![allow])).unwrap();

        assert!(
            policy
                .evaluate(&EvaluationRequest {
                    caller_key: "any",
                    model: "m",
                    max_tokens: Some(4097),
                    request_bytes: 1,
                })
                .is_err()
        );
        assert!(
            policy
                .evaluate(&EvaluationRequest {
                    caller_key: "any",
                    model: "m",
                    max_tokens: Some(4096),
                    request_bytes: 1,
                })
                .is_ok()
        );
    }

    #[test]
    fn max_request_bytes_cap_denies_when_exceeded() {
        let mut allow = rule("size-capped");
        allow.max_request_bytes = Some(1024);
        let policy = CompiledPolicy::compile(&doc(vec![allow])).unwrap();

        assert!(
            policy
                .evaluate(&EvaluationRequest {
                    caller_key: "any",
                    model: "m",
                    max_tokens: None,
                    request_bytes: 2048,
                })
                .is_err()
        );
    }

    #[test]
    fn soft_skip_falls_through_to_next_matching_rule() {
        let mut too_strict = rule("too-strict");
        too_strict.caller_keys = Some(vec!["caller".to_owned()]);
        too_strict.max_tokens = Some(10);
        let mut fallback = rule("fallback");
        fallback.caller_keys = Some(vec!["caller".to_owned()]);
        fallback.max_tokens = Some(10_000);

        let policy = CompiledPolicy::compile(&doc(vec![too_strict, fallback])).unwrap();
        let matched = policy
            .evaluate(&EvaluationRequest {
                caller_key: "caller",
                model: "m",
                max_tokens: Some(500),
                request_bytes: 1,
            })
            .unwrap();
        assert_eq!(matched, "fallback");
    }

    #[test]
    fn disabled_rule_is_ignored() {
        let mut disabled = rule("disabled-allow-all");
        disabled.enabled = false;
        let policy = CompiledPolicy::compile(&doc(vec![disabled])).unwrap();
        assert!(
            policy
                .evaluate(&EvaluationRequest {
                    caller_key: "any",
                    model: "m",
                    max_tokens: None,
                    request_bytes: 1,
                })
                .is_err()
        );
    }

    #[test]
    fn empty_rule_name_fails_fast_at_compile() {
        let mut bad = rule("");
        bad.name = String::new();
        let error = CompiledPolicy::compile(&doc(vec![bad]));
        assert!(error.is_err());
    }

    #[test]
    fn unknown_field_in_policy_json_is_rejected() {
        let raw = serde_json::json!({
            "rules": [{ "name": "x", "unexpected_field": true }]
        });
        let result: Result<PolicyDocument, _> = serde_json::from_value(raw);
        assert!(result.is_err());
    }
}
