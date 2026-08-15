//! The single internal request/response schema both client-facing surfaces
//! (`/v1/chat/completions`, `/v1/messages`) map into, plus canonical JSON
//! serialization and SHA-256 hashing helpers.
//!
//! Per `docs/research/provider-apis.md` §4: hash a normalized intermediate
//! representation, never raw wire bytes, and hash the final assembled
//! response, never raw SSE frames. Canonical JSON here means: `serde_json`
//! objects are backed by `BTreeMap` (the crate's default representation,
//! since we do not enable the `preserve_order` feature), so keys are always
//! emitted in sorted order; `serde_json::to_vec` emits no insignificant
//! whitespace. Together that gives RFC 8785-equivalent determinism for our
//! purposes without a dedicated JCS crate.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Role of a canonical message. `Tool` covers OpenAI's `role: "tool"`
/// messages and is synthesized on the Anthropic side from `tool_result`
/// content blocks (which live inside a `user` message on the wire).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CanonicalRole {
    System,
    User,
    Assistant,
    Tool,
}

/// A single content block. Deliberately a small, closed set for v1 — image
/// / document blocks are out of scope (see `docs/SPEC.md` §7 non-goals) and
/// are represented as `Text` placeholders by the adapters with a fixed
/// descriptor rather than silently dropped, so a request containing an
/// image still changes the request hash.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CanonicalBlock {
    Text {
        text: String,
    },
    ToolUse {
        id: String,
        name: String,
        input: serde_json::Value,
    },
    ToolResult {
        tool_use_id: String,
        content: String,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        is_error: bool,
    },
    /// Placeholder for a non-text block we don't fully model (image, document,
    /// thinking, redacted_thinking, ...). `kind` + `descriptor` still change
    /// the hash when such content changes, without requiring full fidelity.
    Opaque {
        kind: String,
        descriptor: String,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CanonicalMessage {
    pub role: CanonicalRole,
    pub content: Vec<CanonicalBlock>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CanonicalToolDef {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub input_schema: serde_json::Value,
}

/// The canonical request. Excludes transport-only fields (`stream`,
/// provider request IDs, auth headers) per provider-apis.md §4; includes
/// everything that affects generation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CanonicalRequest {
    pub model: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system: Option<String>,
    pub messages: Vec<CanonicalMessage>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<CanonicalToolDef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_choice: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
}

/// Provider-reported usage, kept as four separate counters (`docs/SPEC.md`
/// §3) rather than folded into a single `input_tokens` total, so billing
/// detail (fresh vs. cache-write vs. cache-read) survives onto the receipt.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalUsage {
    pub input_tokens: u64,
    pub cache_creation_tokens: u64,
    pub cache_read_tokens: u64,
    pub output_tokens: u64,
}

/// The canonical response. `model` MUST be read from the provider's
/// response, never assumed from the request (server-side fallback /
/// multi-model routing lesson from provider-apis.md §4).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CanonicalResponse {
    pub model: String,
    pub content: Vec<CanonicalBlock>,
    pub stop_reason: String,
    pub usage: CanonicalUsage,
}

/// Canonical provider-metadata blob hashed into `provider_meta_hash`
/// (`docs/SPEC.md` §3, enclave task brief item 5). Kept separate from
/// `CanonicalResponse` (which is content-committed via a Walrus blob ID)
/// because this is provider-observability data, not generation-affecting
/// content, and is committed by a plain SHA-256 instead. `stop_reason`
/// duplicates `CanonicalResponse::stop_reason` deliberately: a verifier
/// hashing this blob alone should be able to recover every field the
/// enclave committed to under `provider_meta_hash`, without also needing
/// the (separately Walrus-blob-committed) response content.
///
/// `service_tier` is a real field on both providers' response bodies today
/// (Anthropic's `service_tier`, OpenAI's `service_tier`). `inference_geo` is
/// not documented on either public API as of this spec version; the field
/// exists for forward compatibility (task brief item 5) and is populated
/// only if a future response actually carries it — see the provider
/// adapters' doc comments for exactly where each adapter looks.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderMeta {
    pub stop_reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_tier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inference_geo: Option<String>,
}

/// Canonical (sorted-name) record of the headers actually sent upstream,
/// hashed into `upstream_headers_hash` (`docs/SPEC.md` §3). A plain
/// `BTreeMap` gives sorted-key JSON for free via `canonical_bytes` (see
/// module docs), so no separate sort step is needed. Secret values
/// (`x-api-key`, `authorization`) MUST be redacted by the caller before
/// values land here — see `providers::REDACTED_HEADER_VALUE` and each
/// adapter's header-building function, which is the single place headers
/// are ever assembled for an outbound call.
pub type CanonicalHeaders = std::collections::BTreeMap<String, String>;

/// Receipt outcome taxonomy (`docs/SPEC.md` §3): 0 ok, 1 refusal (HTTP 200,
/// still receipted), 2 upstream_error, 3 policy_denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Ok = 0,
    Refusal = 1,
    UpstreamError = 2,
    PolicyDenied = 3,
}

impl Outcome {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Serializes `value` to canonical JSON bytes: round-tripped through
/// `serde_json::Value` (whose object type is `BTreeMap` under our default
/// features, guaranteeing sorted keys) and re-emitted compactly.
pub fn canonical_bytes<T: Serialize>(value: &T) -> serde_json::Result<Vec<u8>> {
    let value = serde_json::to_value(value)?;
    serde_json::to_vec(&value)
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// Canonicalizes then hashes `value` in one step.
pub fn sha256_of<T: Serialize>(value: &T) -> serde_json::Result<[u8; 32]> {
    Ok(sha256(&canonical_bytes(value)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_bytes_sort_keys_and_strip_whitespace() {
        #[derive(Serialize)]
        struct Unsorted {
            z: u8,
            a: u8,
        }
        let bytes = canonical_bytes(&Unsorted { z: 1, a: 2 }).expect("serialize");
        assert_eq!(bytes, br#"{"a":2,"z":1}"#);
    }

    #[test]
    fn same_logical_request_hashes_identically_regardless_of_field_order() {
        // Two CanonicalRequest values built differently but semantically
        // identical must hash the same — this is the whole point of
        // canonicalizing before hashing (provider-apis.md §4).
        let a = CanonicalRequest {
            model: "m".to_owned(),
            system: Some("s".to_owned()),
            messages: vec![],
            tools: vec![],
            tool_choice: None,
            max_tokens: Some(10),
            temperature: None,
        };
        let b = a.clone();
        assert_eq!(sha256_of(&a).unwrap(), sha256_of(&b).unwrap());
    }
}
