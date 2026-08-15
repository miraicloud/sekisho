//! Anthropic Messages API adapter, backing the native passthrough surface
//! `POST /v1/messages` (`docs/research/provider-apis.md` §1, §5). Kept
//! thin and mostly-passthrough: the original request JSON is forwarded
//! upstream near-verbatim (only `stream` is normalized and auth headers are
//! swapped), while a lightweight typed view is extracted alongside for
//! canonicalization. This preserves fidelity for anything not explicitly
//! modeled (thinking blocks, cache_control, mid-conversation system
//! messages, etc.) rather than lossily round-tripping through a narrower
//! struct.

use std::collections::BTreeMap;

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::tls::TlsInfo;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::canonical::{
    CanonicalBlock, CanonicalMessage, CanonicalRequest, CanonicalResponse, CanonicalRole,
    CanonicalToolDef, CanonicalUsage, Outcome, ProviderMeta, sha256,
};

use super::{ProviderError, REDACTED_HEADER_VALUE, UpstreamMeta};

/// PCR-measured provider endpoint (`docs/SPEC.md` §4, load-bearing security
/// property): NEVER sourced from boot config. An operator who controls
/// config could otherwise repoint this adapter at a server they control and
/// still emit onchain-verifiable receipts. `call_non_streaming` and
/// `start_streaming` below take `base_url` as a plain function parameter
/// rather than reading it from any config/env source themselves; the only
/// production call site (`server::app`) always passes this constant. Tests
/// pass a local mock-server URL through the same parameter — an ordinary
/// function argument, not a runtime-configurable override, and reachable
/// only from `#[cfg(test)]` code (see `server.rs`'s test-only router
/// constructor). `unsafe_code = "forbid"` on this crate also rules out an
/// env-var-mutation-based escape hatch (`std::env::set_var` is `unsafe` as
/// of the 2024 edition), which is a second, independent reason not to wire
/// one up.
pub const BASE_URL: &str = "https://api.anthropic.com";
/// `endpoint_host` for every receipt this adapter produces (`docs/SPEC.md`
/// §3, task brief item 4): the bare hostname, compile-time-constant for the
/// same PCR-measurement reason as `BASE_URL` above.
pub const HOST: &str = "api.anthropic.com";
pub const ANTHROPIC_VERSION: &str = "2023-06-01";

/// Response header this adapter falls back to for `provider_request_id`
/// when the response body carries no `id` field (task brief item 5: "prefer
/// the body `id`, fall back to header, empty string if neither"). Anthropic
/// documents `request-id` as the header carrying its own request
/// identifier.
const REQUEST_ID_HEADER: &str = "request-id";

#[derive(Debug, Clone, Deserialize)]
struct WireRequestFields {
    model: String,
    #[serde(default)]
    max_tokens: Option<u64>,
    #[serde(default)]
    system: Option<Value>,
    #[serde(default)]
    messages: Vec<WireMessage>,
    #[serde(default)]
    tools: Option<Vec<WireTool>>,
    #[serde(default)]
    tool_choice: Option<Value>,
    #[serde(default)]
    temperature: Option<f64>,
}

#[derive(Debug, Clone, Deserialize)]
struct WireMessage {
    role: String,
    content: Value,
}

#[derive(Debug, Clone, Deserialize)]
struct WireTool {
    name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    input_schema: Option<Value>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
struct WireUsage {
    #[serde(default)]
    input_tokens: u64,
    #[serde(default)]
    output_tokens: u64,
    #[serde(default)]
    cache_creation_input_tokens: u64,
    #[serde(default)]
    cache_read_input_tokens: u64,
}

impl WireUsage {
    /// Merges present fields from a raw JSON usage object, leaving fields
    /// this event doesn't report untouched (streaming `usage` updates are
    /// cumulative per-field, not always-complete — see `apply_usage_delta`).
    fn merge_from(&mut self, value: &Value) {
        if let Some(v) = value.get("input_tokens").and_then(Value::as_u64) {
            self.input_tokens = v;
        }
        if let Some(v) = value.get("output_tokens").and_then(Value::as_u64) {
            self.output_tokens = v;
        }
        if let Some(v) = value
            .get("cache_creation_input_tokens")
            .and_then(Value::as_u64)
        {
            self.cache_creation_input_tokens = v;
        }
        if let Some(v) = value.get("cache_read_input_tokens").and_then(Value::as_u64) {
            self.cache_read_input_tokens = v;
        }
    }

    /// Maps the four Anthropic usage counters onto `CanonicalUsage`
    /// one-to-one (`docs/SPEC.md` §3, task brief item 6): unlike the
    /// removed `ReceiptV1` schema, `Receipt` keeps fresh / cache-write /
    /// cache-read / output tokens separate rather than folding cache
    /// counters into `input_tokens`, so billing detail survives onto the
    /// receipt.
    fn to_canonical_usage(&self) -> CanonicalUsage {
        CanonicalUsage {
            input_tokens: self.input_tokens,
            cache_creation_tokens: self.cache_creation_input_tokens,
            cache_read_tokens: self.cache_read_input_tokens,
            output_tokens: self.output_tokens,
        }
    }
}

fn extract_system_text(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Array(blocks) => {
            let parts: Vec<String> = blocks
                .iter()
                .filter_map(|block| block.get("text").and_then(Value::as_str))
                .map(str::to_owned)
                .collect();
            if parts.is_empty() {
                None
            } else {
                Some(parts.join("\n"))
            }
        }
        _ => None,
    }
}

fn stringify_tool_result_content(content: Option<&Value>) -> String {
    match content {
        None => String::new(),
        Some(Value::String(text)) => text.clone(),
        Some(Value::Array(blocks)) => blocks
            .iter()
            .map(|block| {
                block
                    .get("text")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .unwrap_or_else(|| block.to_string())
            })
            .collect::<Vec<_>>()
            .join("\n"),
        Some(other) => other.to_string(),
    }
}

/// Descriptor for a content block type we don't model precisely (image,
/// document, thinking, redacted_thinking, a server-side `fallback` marker,
/// ...): the SHA-256 of its raw JSON, so any change to unmodeled content
/// still changes the canonical hash without requiring full field-by-field
/// modeling.
fn opaque_descriptor(block: &Value) -> String {
    let bytes = serde_json::to_vec(block).unwrap_or_default();
    hex::encode(sha256(&bytes))
}

fn block_to_canonical(block: &Value) -> CanonicalBlock {
    match block.get("type").and_then(Value::as_str) {
        Some("text") => CanonicalBlock::Text {
            text: block
                .get("text")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
        },
        Some("tool_use") => CanonicalBlock::ToolUse {
            id: block
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            name: block
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            input: block.get("input").cloned().unwrap_or(Value::Null),
        },
        Some("tool_result") => CanonicalBlock::ToolResult {
            tool_use_id: block
                .get("tool_use_id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            content: stringify_tool_result_content(block.get("content")),
            is_error: block
                .get("is_error")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        },
        other => CanonicalBlock::Opaque {
            kind: other.unwrap_or("unknown").to_owned(),
            descriptor: opaque_descriptor(block),
        },
    }
}

fn content_blocks(content: &Value) -> Vec<CanonicalBlock> {
    match content {
        Value::String(text) => vec![CanonicalBlock::Text { text: text.clone() }],
        Value::Array(blocks) => blocks.iter().map(block_to_canonical).collect(),
        _ => Vec::new(),
    }
}

fn message_to_canonical(message: &WireMessage) -> CanonicalMessage {
    let role = match message.role.as_str() {
        "assistant" => CanonicalRole::Assistant,
        // Mid-conversation `role: "system"` messages (Opus 5, Fable 5, ...)
        // per provider-apis.md §1.
        "system" => CanonicalRole::System,
        _ => CanonicalRole::User,
    };
    CanonicalMessage {
        role,
        content: content_blocks(&message.content),
    }
}

fn to_canonical_request(fields: &WireRequestFields) -> CanonicalRequest {
    CanonicalRequest {
        model: fields.model.clone(),
        system: fields.system.as_ref().and_then(extract_system_text),
        messages: fields.messages.iter().map(message_to_canonical).collect(),
        tools: fields
            .tools
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(|tool| CanonicalToolDef {
                name: tool.name.clone(),
                description: tool.description.clone(),
                input_schema: tool.input_schema.clone().unwrap_or(Value::Null),
            })
            .collect(),
        tool_choice: fields.tool_choice.clone(),
        max_tokens: fields.max_tokens,
        temperature: fields.temperature,
    }
}

/// Parses a raw request body, returning the original JSON (for upstream
/// forwarding), whether the client asked for streaming, and the canonical
/// form (for hashing/policy).
pub fn parse_request(raw_bytes: &[u8]) -> Result<(Value, bool, CanonicalRequest), ProviderError> {
    let raw: Value = serde_json::from_slice(raw_bytes)
        .map_err(|error| ProviderError::Decode(error.to_string()))?;
    let fields: WireRequestFields = serde_json::from_value(raw.clone())
        .map_err(|error| ProviderError::Decode(error.to_string()))?;
    let stream = raw.get("stream").and_then(Value::as_bool).unwrap_or(false);
    Ok((raw, stream, to_canonical_request(&fields)))
}

#[derive(Debug, Clone, Deserialize)]
struct WireResponse {
    model: String,
    #[serde(default)]
    content: Vec<Value>,
    #[serde(default)]
    stop_reason: Option<String>,
    #[serde(default)]
    usage: WireUsage,
}

/// Parses a non-streaming response into the canonical response (content-
/// committed via `response_blob`), the canonical provider-meta blob
/// (SHA-256'd into `provider_meta_hash`), and the provider's own request id
/// (task brief item 5). `service_tier` is read from the raw body since
/// `WireResponse` doesn't model it; `inference_geo` is speculative — see
/// `ProviderMeta`'s doc comment — Anthropic does not document this field
/// today, so it is always `None` in practice.
pub fn to_canonical_response(
    raw: &Value,
) -> Result<(CanonicalResponse, ProviderMeta, String), ProviderError> {
    let response: WireResponse = serde_json::from_value(raw.clone())
        .map_err(|error| ProviderError::Decode(error.to_string()))?;
    let stop_reason = response.stop_reason.unwrap_or_default();
    let provider_request_id = raw
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let meta = ProviderMeta {
        stop_reason: stop_reason.clone(),
        service_tier: raw
            .get("service_tier")
            .and_then(Value::as_str)
            .map(str::to_owned),
        inference_geo: raw
            .get("inference_geo")
            .and_then(Value::as_str)
            .map(str::to_owned),
    };
    let canonical = CanonicalResponse {
        model: response.model,
        content: response.content.iter().map(block_to_canonical).collect(),
        stop_reason,
        usage: response.usage.to_canonical_usage(),
    };
    Ok((canonical, meta, provider_request_id))
}

/// `stop_reason: "refusal"` is an HTTP 200 policy decline, not an error
/// (`docs/research/provider-apis.md` §1/§4) — still receipted, but flagged.
pub fn outcome_for_stop_reason(stop_reason: &str) -> Outcome {
    if stop_reason == "refusal" {
        Outcome::Refusal
    } else {
        Outcome::Ok
    }
}

/// Builds the exact headers sent upstream, plus the canonical (redacted)
/// record of them hashed into `upstream_headers_hash` (`docs/SPEC.md` §3,
/// task brief item 7). Building both from one pass — rather than hashing
/// whatever `reqwest::RequestBuilder` ends up with — guarantees the hash
/// covers exactly what this function sets, with `x-api-key` redacted to
/// `REDACTED_HEADER_VALUE` so the hash never lets a verifier learn anything
/// about the real key.
fn upstream_headers(api_key: &str) -> (HeaderMap, BTreeMap<String, String>) {
    let mut headers = HeaderMap::new();
    let mut canonical = BTreeMap::new();
    let mut set = |name: &'static str, value: String, secret: bool| {
        if let Ok(header_value) = HeaderValue::from_str(&value) {
            headers.insert(HeaderName::from_static(name), header_value);
        }
        canonical.insert(
            name.to_owned(),
            if secret {
                REDACTED_HEADER_VALUE.to_owned()
            } else {
                value
            },
        );
    };
    set("x-api-key", api_key.to_owned(), true);
    set("anthropic-version", ANTHROPIC_VERSION.to_owned(), false);
    set("content-type", "application/json".to_owned(), false);
    (headers, canonical)
}

/// Extracts `UpstreamMeta` from a live response (before its body is
/// consumed — `Response::extensions`/`headers` borrow `&self`, so this must
/// run before `.bytes()`/`.bytes_stream()` takes ownership).
fn upstream_meta(
    response: &reqwest::Response,
    upstream_headers: BTreeMap<String, String>,
) -> UpstreamMeta {
    let tls_cert_sha256 = response
        .extensions()
        .get::<TlsInfo>()
        .and_then(TlsInfo::peer_certificate)
        .map(sha256)
        .unwrap_or([0u8; 32]);
    let request_id_header = response
        .headers()
        .get(REQUEST_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    UpstreamMeta {
        upstream_headers,
        tls_cert_sha256,
        request_id_header,
    }
}

/// Sends a non-streaming request upstream and returns `(status, body,
/// upstream_meta)`. `base_url` is an ordinary parameter, not read from
/// config/env — see the `BASE_URL` doc comment above.
pub async fn call_non_streaming(
    client: &reqwest::Client,
    base_url: &str,
    api_key: &str,
    raw_request: &Value,
) -> Result<(u16, Value, UpstreamMeta), ProviderError> {
    let mut body = raw_request.clone();
    if let Value::Object(map) = &mut body {
        map.insert("stream".to_owned(), Value::Bool(false));
    }
    let (headers, canonical_headers) = upstream_headers(api_key);
    let request = client
        .post(format!("{base_url}/v1/messages"))
        .headers(headers)
        .json(&body);
    let response = request
        .send()
        .await
        .map_err(|error| ProviderError::Transport(error.to_string()))?;
    let status = response.status().as_u16();
    let meta = upstream_meta(&response, canonical_headers);
    let bytes = response
        .bytes()
        .await
        .map_err(|error| ProviderError::Transport(error.to_string()))?;
    let json: Value = serde_json::from_slice(&bytes).map_err(|error| {
        ProviderError::Decode(format!(
            "{error} (body: {})",
            String::from_utf8_lossy(&bytes)
        ))
    })?;
    Ok((status, json, meta))
}

/// Sends a streaming request upstream and returns the raw response (for the
/// caller to drain via `.bytes_stream()`) plus `UpstreamMeta`, captured
/// before the body is consumed. `base_url` — see above.
pub async fn start_streaming(
    client: &reqwest::Client,
    base_url: &str,
    api_key: &str,
    raw_request: &Value,
) -> Result<(reqwest::Response, UpstreamMeta), ProviderError> {
    let mut body = raw_request.clone();
    if let Value::Object(map) = &mut body {
        map.insert("stream".to_owned(), Value::Bool(true));
    }
    let (headers, canonical_headers) = upstream_headers(api_key);
    let request = client
        .post(format!("{base_url}/v1/messages"))
        .headers(headers)
        .json(&body);
    let response = request
        .send()
        .await
        .map_err(|error| ProviderError::Transport(error.to_string()))?;
    let meta = upstream_meta(&response, canonical_headers);
    Ok((response, meta))
}

/// Accumulates Anthropic SSE events into the same canonical response shape
/// used for non-streaming — per provider-apis.md §4: concatenate
/// `text_delta`s within a block by index, accumulate `input_json_delta` as
/// a partial string and parse only once the block closes, take usage from
/// the terminal `message_delta` (cumulative, not summed).
#[derive(Debug, Default)]
pub struct StreamAccumulator {
    buffer: String,
    model: Option<String>,
    blocks: Vec<Option<AccBlock>>,
    stop_reason: Option<String>,
    usage: WireUsage,
    /// `message.id` from `message_start` — the provider request id (task
    /// brief item 5); empty when a stream is aborted before that event.
    id: Option<String>,
    service_tier: Option<String>,
    /// Speculative — see `ProviderMeta`'s doc comment; not documented on
    /// the Anthropic streaming API today, so always `None` in practice.
    inference_geo: Option<String>,
}

#[derive(Debug, Clone)]
enum AccBlock {
    Text(String),
    ToolUse {
        id: String,
        name: String,
        partial_json: String,
    },
    Opaque {
        kind: String,
        raw: Value,
    },
}

impl AccBlock {
    fn from_start(block: &Value) -> Self {
        match block.get("type").and_then(Value::as_str) {
            Some("text") => Self::Text(
                block
                    .get("text")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
            ),
            Some("tool_use") => Self::ToolUse {
                id: block
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                name: block
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                partial_json: String::new(),
            },
            other => Self::Opaque {
                kind: other.unwrap_or("unknown").to_owned(),
                raw: block.clone(),
            },
        }
    }

    fn apply_delta(&mut self, delta: &Value) {
        match (self, delta.get("type").and_then(Value::as_str)) {
            (Self::Text(text), Some("text_delta")) => {
                text.push_str(
                    delta
                        .get("text")
                        .and_then(Value::as_str)
                        .unwrap_or_default(),
                );
            }
            (Self::ToolUse { partial_json, .. }, Some("input_json_delta")) => {
                partial_json.push_str(
                    delta
                        .get("partial_json")
                        .and_then(Value::as_str)
                        .unwrap_or_default(),
                );
            }
            _ => {}
        }
    }

    fn into_canonical(self) -> CanonicalBlock {
        match self {
            Self::Text(text) => CanonicalBlock::Text { text },
            Self::ToolUse {
                id,
                name,
                partial_json,
            } => {
                let input = if partial_json.trim().is_empty() {
                    Value::Object(Default::default())
                } else {
                    serde_json::from_str(&partial_json).unwrap_or(Value::Null)
                };
                CanonicalBlock::ToolUse { id, name, input }
            }
            Self::Opaque { kind, raw } => CanonicalBlock::Opaque {
                kind,
                descriptor: opaque_descriptor(&raw),
            },
        }
    }
}

impl StreamAccumulator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feeds a raw chunk of bytes as received on the wire (may split a
    /// line, an event, or contain several events). Buffers a partial line
    /// across calls.
    pub fn feed(&mut self, chunk: &[u8]) {
        self.buffer.push_str(&String::from_utf8_lossy(chunk));
        while let Some(pos) = self.buffer.find("\n\n") {
            let event_block: String = self.buffer.drain(..=pos + 1).collect();
            self.handle_event_block(&event_block);
        }
    }

    fn handle_event_block(&mut self, block: &str) {
        for line in block.lines() {
            let Some(data) = line.strip_prefix("data:") else {
                continue;
            };
            let data = data.trim();
            if data.is_empty() {
                continue;
            }
            if let Ok(value) = serde_json::from_str::<Value>(data) {
                self.apply_event(&value);
            }
        }
    }

    fn apply_event(&mut self, value: &Value) {
        match value.get("type").and_then(Value::as_str) {
            Some("message_start") => {
                if let Some(model) = value.pointer("/message/model").and_then(Value::as_str) {
                    self.model = Some(model.to_owned());
                }
                if let Some(id) = value.pointer("/message/id").and_then(Value::as_str) {
                    self.id = Some(id.to_owned());
                }
                if let Some(tier) = value
                    .pointer("/message/service_tier")
                    .and_then(Value::as_str)
                {
                    self.service_tier = Some(tier.to_owned());
                }
                if let Some(geo) = value
                    .pointer("/message/inference_geo")
                    .and_then(Value::as_str)
                {
                    self.inference_geo = Some(geo.to_owned());
                }
                if let Some(usage) = value.pointer("/message/usage") {
                    self.usage.merge_from(usage);
                }
            }
            Some("content_block_start") => {
                let index = value.get("index").and_then(Value::as_u64).unwrap_or(0) as usize;
                self.ensure_len(index + 1);
                let block = value.get("content_block").cloned().unwrap_or(Value::Null);
                self.blocks[index] = Some(AccBlock::from_start(&block));
            }
            Some("content_block_delta") => {
                let index = value.get("index").and_then(Value::as_u64).unwrap_or(0) as usize;
                self.ensure_len(index + 1);
                if let Some(Some(block)) = self.blocks.get_mut(index) {
                    block.apply_delta(value.get("delta").unwrap_or(&Value::Null));
                }
            }
            Some("message_delta") => {
                if let Some(reason) = value.pointer("/delta/stop_reason").and_then(Value::as_str) {
                    self.stop_reason = Some(reason.to_owned());
                }
                if let Some(usage) = value.get("usage") {
                    self.usage.merge_from(usage);
                }
            }
            _ => {}
        }
    }

    fn ensure_len(&mut self, len: usize) {
        while self.blocks.len() < len {
            self.blocks.push(None);
        }
    }

    /// Finalizes accumulation into the canonical response shape, the
    /// canonical provider-meta blob, and the provider request id. Call
    /// after the stream ends (successfully via `message_stop`, or because
    /// the upstream connection dropped mid-stream — either way, whatever
    /// was accumulated so far is what gets committed).
    pub fn finish(self, fallback_model: &str) -> (CanonicalResponse, ProviderMeta, String) {
        let content = self
            .blocks
            .into_iter()
            .flatten()
            .map(AccBlock::into_canonical)
            .collect();
        let stop_reason = self.stop_reason.unwrap_or_default();
        let canonical = CanonicalResponse {
            model: self.model.unwrap_or_else(|| fallback_model.to_owned()),
            content,
            stop_reason: stop_reason.clone(),
            usage: self.usage.to_canonical_usage(),
        };
        let meta = ProviderMeta {
            stop_reason,
            service_tier: self.service_tier,
            inference_geo: self.inference_geo,
        };
        (canonical, meta, self.id.unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_string_content_as_single_text_block() {
        let raw = serde_json::json!({
            "model": "claude-sonnet-5",
            "max_tokens": 100,
            "messages": [{"role": "user", "content": "hello"}]
        });
        let (_, stream, canonical) = parse_request(raw.to_string().as_bytes()).unwrap();
        assert!(!stream);
        assert_eq!(canonical.messages.len(), 1);
        assert_eq!(
            canonical.messages[0].content,
            vec![CanonicalBlock::Text {
                text: "hello".to_owned()
            }]
        );
    }

    #[test]
    fn system_array_of_blocks_joins_text() {
        let raw = serde_json::json!({
            "model": "m",
            "system": [{"type": "text", "text": "a"}, {"type": "text", "text": "b", "cache_control": {"type": "ephemeral"}}],
            "messages": []
        });
        let (_, _, canonical) = parse_request(raw.to_string().as_bytes()).unwrap();
        assert_eq!(canonical.system, Some("a\nb".to_owned()));
    }

    #[test]
    fn unmodeled_block_becomes_opaque_and_changes_hash_on_change() {
        let mut raw = serde_json::json!({
            "model": "m",
            "messages": [{"role": "user", "content": [{"type": "image", "source": {"data": "AAAA"}}]}]
        });
        let (_, _, canonical_a) = parse_request(raw.to_string().as_bytes()).unwrap();

        raw["messages"][0]["content"][0]["source"]["data"] = serde_json::json!("BBBB");
        let (_, _, canonical_b) = parse_request(raw.to_string().as_bytes()).unwrap();

        assert_ne!(
            crate::canonical::sha256_of(&canonical_a).unwrap(),
            crate::canonical::sha256_of(&canonical_b).unwrap()
        );
    }

    #[test]
    fn stream_accumulator_matches_non_streaming_for_same_content() {
        let non_streaming_response = serde_json::json!({
            "model": "claude-sonnet-5",
            "content": [{"type": "text", "text": "Hello, world!"}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 10, "output_tokens": 3}
        });
        let expected = to_canonical_response(&non_streaming_response).unwrap();

        let mut acc = StreamAccumulator::new();
        let events = [
            r#"{"type":"message_start","message":{"model":"claude-sonnet-5","usage":{"input_tokens":10,"output_tokens":0}}}"#,
            r#"{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}"#,
            r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello, "}}"#,
            r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"world!"}}"#,
            r#"{"type":"content_block_stop","index":0}"#,
            r#"{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":3}}"#,
            r#"{"type":"message_stop"}"#,
        ];
        for event in events {
            acc.feed(format!("data: {event}\n\n").as_bytes());
        }
        let assembled = acc.finish("fallback-model");

        assert_eq!(assembled, expected);
    }

    #[test]
    fn stream_accumulator_handles_chunk_split_mid_line() {
        let mut acc = StreamAccumulator::new();
        let event =
            r#"{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}"#;
        let full = format!("data: {event}\n\n");
        let (first, second) = full.split_at(full.len() / 2);
        acc.feed(first.as_bytes());
        acc.feed(second.as_bytes());
        acc.feed(br#"data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"ok"}}

"#);
        let (assembled, _meta, _id) = acc.finish("m");
        assert_eq!(
            assembled.content,
            vec![CanonicalBlock::Text {
                text: "ok".to_owned()
            }]
        );
    }

    #[test]
    fn refusal_stop_reason_maps_to_refusal_outcome() {
        assert_eq!(outcome_for_stop_reason("refusal"), Outcome::Refusal);
        assert_eq!(outcome_for_stop_reason("end_turn"), Outcome::Ok);
    }

    /// Replaces the old `ReceiptV1`-era
    /// `cache_tokens_are_folded_into_total_input_tokens` test: `Receipt`
    /// keeps the four usage counters separate (task brief item 6), so this
    /// now asserts they stay separate instead of asserting they get folded.
    #[test]
    fn usage_counters_stay_separate_not_folded() {
        let raw = serde_json::json!({
            "model": "m",
            "content": [],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 5, "cache_creation_input_tokens": 2, "cache_read_input_tokens": 3, "output_tokens": 1}
        });
        let (response, _meta, _id) = to_canonical_response(&raw).unwrap();
        assert_eq!(response.usage.input_tokens, 5);
        assert_eq!(response.usage.cache_creation_tokens, 2);
        assert_eq!(response.usage.cache_read_tokens, 3);
        assert_eq!(response.usage.output_tokens, 1);
    }

    #[test]
    fn provider_request_id_prefers_body_id_over_header() {
        let raw = serde_json::json!({
            "model": "m",
            "id": "msg_from_body",
            "content": [],
            "stop_reason": "end_turn",
            "usage": {}
        });
        let (_response, _meta, provider_request_id) = to_canonical_response(&raw).unwrap();
        assert_eq!(provider_request_id, "msg_from_body");
    }

    #[test]
    fn provider_request_id_empty_when_body_has_no_id() {
        let raw = serde_json::json!({
            "model": "m",
            "content": [],
            "stop_reason": "end_turn",
            "usage": {}
        });
        let (_response, _meta, provider_request_id) = to_canonical_response(&raw).unwrap();
        assert_eq!(provider_request_id, "");
    }

    #[test]
    fn service_tier_is_captured_when_present() {
        let raw = serde_json::json!({
            "model": "m",
            "content": [],
            "stop_reason": "end_turn",
            "service_tier": "standard",
            "usage": {}
        });
        let (_response, meta, _id) = to_canonical_response(&raw).unwrap();
        assert_eq!(meta.service_tier, Some("standard".to_owned()));
        assert_eq!(meta.inference_geo, None);
    }

    #[test]
    fn upstream_headers_redact_the_api_key_but_keep_the_version_header() {
        let (_headers, canonical) = upstream_headers("sk-super-secret");
        assert_eq!(
            canonical.get("x-api-key").map(String::as_str),
            Some(REDACTED_HEADER_VALUE)
        );
        assert_eq!(
            canonical.get("anthropic-version").map(String::as_str),
            Some(ANTHROPIC_VERSION)
        );
        assert!(!canonical.values().any(|v| v.contains("sk-super-secret")));
    }
}
