//! OpenAI-compatible Chat Completions adapter, backing the primary surface
//! `POST /v1/chat/completions` (`docs/research/provider-apis.md` §2, §5).
//! Also covers OpenRouter/DeepSeek/self-hosted vLLM-style backends, since
//! they mirror this same wire shape — which concrete host is dialed is
//! fixed by `BASE_URL` at build time (see its doc comment).

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
/// property) — see `providers::anthropic::BASE_URL` doc comment for the
/// full rationale (including why `base_url` is a plain function parameter
/// on the call functions below, not read from config/env); identical
/// reasoning applies here.
pub const BASE_URL: &str = "https://api.openai.com";
/// `endpoint_host` for every receipt this adapter produces (`docs/SPEC.md`
/// §3, task brief item 4) — see `providers::anthropic::HOST`.
pub const HOST: &str = "api.openai.com";

/// Response header this adapter falls back to for `provider_request_id`
/// when the response body carries no `id` field — see
/// `providers::anthropic::REQUEST_ID_HEADER`. OpenAI documents
/// `x-request-id` as the header carrying its own request identifier.
const REQUEST_ID_HEADER: &str = "x-request-id";

#[derive(Debug, Clone, Deserialize)]
struct WireRequestFields {
    model: String,
    #[serde(default)]
    messages: Vec<WireMessage>,
    #[serde(default)]
    max_tokens: Option<u64>,
    #[serde(default)]
    temperature: Option<f64>,
    #[serde(default)]
    tools: Option<Vec<WireTool>>,
    #[serde(default)]
    tool_choice: Option<Value>,
}

#[derive(Debug, Clone, Deserialize)]
struct WireMessage {
    role: String,
    #[serde(default)]
    content: Option<Value>,
    #[serde(default)]
    tool_calls: Option<Vec<WireToolCall>>,
    #[serde(default)]
    tool_call_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct WireToolCall {
    id: String,
    function: WireFunctionCall,
}

#[derive(Debug, Clone, Deserialize)]
struct WireFunctionCall {
    name: String,
    #[serde(default)]
    arguments: String,
}

#[derive(Debug, Clone, Deserialize)]
struct WireTool {
    function: WireFunctionDef,
}

#[derive(Debug, Clone, Deserialize)]
struct WireFunctionDef {
    name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    parameters: Option<Value>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
struct WireUsage {
    #[serde(default)]
    prompt_tokens: u64,
    #[serde(default)]
    completion_tokens: u64,
    #[serde(default)]
    prompt_tokens_details: Option<WirePromptTokensDetails>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
struct WirePromptTokensDetails {
    #[serde(default)]
    cached_tokens: u64,
}

impl WireUsage {
    /// Maps OpenAI's usage shape onto `CanonicalUsage` (`docs/SPEC.md` §3,
    /// task brief item 6). OpenAI has no "cache creation" concept — prompt
    /// caching there is automatic and reported only as a portion of
    /// `prompt_tokens` already billed at the cached rate
    /// (`usage.prompt_tokens_details.cached_tokens`), unlike Anthropic's
    /// mutually-exclusive `cache_creation_input_tokens` /
    /// `cache_read_input_tokens` counters that are additional to
    /// `input_tokens`. So for provider=1 receipts, `cache_creation_tokens`
    /// is always 0, `cache_read_tokens` is the cached portion, and
    /// `input_tokens` is `prompt_tokens` minus that cached portion — the
    /// four counters sum to the provider's total token accounting, mirroring
    /// Anthropic's additive semantics rather than double-counting.
    /// Documented deviation — see task report.
    fn to_canonical_usage(&self) -> CanonicalUsage {
        let cache_read_tokens = self
            .prompt_tokens_details
            .as_ref()
            .map(|details| details.cached_tokens)
            .unwrap_or(0);
        CanonicalUsage {
            input_tokens: self.prompt_tokens.saturating_sub(cache_read_tokens),
            cache_creation_tokens: 0,
            cache_read_tokens,
            output_tokens: self.completion_tokens,
        }
    }
}

/// Descriptor for content we don't model precisely (multimodal parts other
/// than `text`): SHA-256 of the raw JSON, so a change still changes the hash.
fn opaque_descriptor(value: &Value) -> String {
    hex::encode(sha256(&serde_json::to_vec(value).unwrap_or_default()))
}

fn stringify_content(content: &Value) -> Vec<CanonicalBlock> {
    match content {
        Value::String(text) => vec![CanonicalBlock::Text { text: text.clone() }],
        Value::Array(parts) => parts
            .iter()
            .map(|part| match part.get("type").and_then(Value::as_str) {
                Some("text") => CanonicalBlock::Text {
                    text: part
                        .get("text")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                },
                other => CanonicalBlock::Opaque {
                    kind: other.unwrap_or("unknown").to_owned(),
                    descriptor: opaque_descriptor(part),
                },
            })
            .collect(),
        Value::Null => Vec::new(),
        other => vec![CanonicalBlock::Text {
            text: other.to_string(),
        }],
    }
}

fn tool_call_to_block(call: &WireToolCall) -> CanonicalBlock {
    let input = if call.function.arguments.trim().is_empty() {
        Value::Object(Default::default())
    } else {
        serde_json::from_str(&call.function.arguments)
            .unwrap_or_else(|_| Value::String(call.function.arguments.clone()))
    };
    CanonicalBlock::ToolUse {
        id: call.id.clone(),
        name: call.function.name.clone(),
        input,
    }
}

fn message_to_canonical(message: &WireMessage) -> CanonicalMessage {
    let role = match message.role.as_str() {
        "system" | "developer" => CanonicalRole::System,
        "assistant" => CanonicalRole::Assistant,
        "tool" => CanonicalRole::Tool,
        _ => CanonicalRole::User,
    };

    let mut content = message
        .content
        .as_ref()
        .map(stringify_content)
        .unwrap_or_default();

    if role == CanonicalRole::Tool {
        let text = content
            .iter()
            .filter_map(|block| match block {
                CanonicalBlock::Text { text } => Some(text.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("\n");
        content = vec![CanonicalBlock::ToolResult {
            tool_use_id: message.tool_call_id.clone().unwrap_or_default(),
            content: text,
            is_error: false,
        }];
    }

    if let Some(tool_calls) = &message.tool_calls {
        content.extend(tool_calls.iter().map(tool_call_to_block));
    }

    CanonicalMessage { role, content }
}

fn to_canonical_request(fields: &WireRequestFields) -> CanonicalRequest {
    // OpenAI has no top-level `system` field; a leading `role: "system"`
    // message is just a regular message in the canonical schema, matching
    // its own wire semantics rather than forcing it into Anthropic's shape.
    CanonicalRequest {
        model: fields.model.clone(),
        system: None,
        messages: fields.messages.iter().map(message_to_canonical).collect(),
        tools: fields
            .tools
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(|tool| CanonicalToolDef {
                name: tool.function.name.clone(),
                description: tool.function.description.clone(),
                input_schema: tool.function.parameters.clone().unwrap_or(Value::Null),
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
struct WireChoice {
    message: WireResponseMessage,
    #[serde(default)]
    finish_reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct WireResponseMessage {
    #[serde(default)]
    content: Option<Value>,
    #[serde(default)]
    tool_calls: Option<Vec<WireToolCall>>,
}

#[derive(Debug, Clone, Deserialize)]
struct WireResponse {
    model: String,
    // v1 supports a single choice (`choices[0]`) — see task report deviations.
    #[serde(default)]
    choices: Vec<WireChoice>,
    #[serde(default)]
    usage: WireUsage,
}

/// Parses a non-streaming response into the canonical response (content-
/// committed via `response_blob`), the canonical provider-meta blob
/// (SHA-256'd into `provider_meta_hash`), and the provider's own request id
/// (task brief item 5). `service_tier` is a real OpenAI response field;
/// `inference_geo` is speculative — see `ProviderMeta`'s doc comment.
pub fn to_canonical_response(
    raw: &Value,
) -> Result<(CanonicalResponse, ProviderMeta, String), ProviderError> {
    let response: WireResponse = serde_json::from_value(raw.clone())
        .map_err(|error| ProviderError::Decode(error.to_string()))?;
    let choice = response.choices.first();
    let mut content = choice
        .and_then(|c| c.message.content.as_ref())
        .map(stringify_content)
        .unwrap_or_default();
    if let Some(tool_calls) = choice.and_then(|c| c.message.tool_calls.as_ref()) {
        content.extend(tool_calls.iter().map(tool_call_to_block));
    }
    let stop_reason = choice
        .and_then(|c| c.finish_reason.clone())
        .unwrap_or_default();
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
        content,
        stop_reason,
        usage: response.usage.to_canonical_usage(),
    };
    Ok((canonical, meta, provider_request_id))
}

/// `finish_reason: "content_filter"` is the OpenAI-shape analog of
/// Anthropic's `stop_reason: "refusal"` — an HTTP 200 policy decline, not
/// an error (`docs/research/provider-apis.md` §2/§4).
pub fn outcome_for_finish_reason(finish_reason: &str) -> Outcome {
    if finish_reason == "content_filter" {
        Outcome::Refusal
    } else {
        Outcome::Ok
    }
}

/// Builds the exact headers sent upstream, plus the canonical (redacted)
/// record of them hashed into `upstream_headers_hash` — see
/// `providers::anthropic::upstream_headers` for the full rationale.
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
    set("authorization", format!("Bearer {api_key}"), true);
    set("content-type", "application/json".to_owned(), false);
    (headers, canonical)
}

/// Extracts `UpstreamMeta` from a live response before its body is consumed
/// — see `providers::anthropic::upstream_meta`.
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

/// `base_url` is an ordinary parameter, not read from config/env — see the
/// `BASE_URL` doc comment above.
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
        .post(format!("{base_url}/v1/chat/completions"))
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

/// Sends a streaming request. Forces `stream_options.include_usage = true`
/// — a genuine gateway transform (provider-apis.md §4: "a relay must
/// request it explicitly on every streamed call if the receipt needs token
/// counts"), which is why the dispatched `Value` is returned alongside the
/// response: it's what `upstream_request_blob` is computed from, separately
/// from `request_blob`.
pub async fn start_streaming(
    client: &reqwest::Client,
    base_url: &str,
    api_key: &str,
    raw_request: &Value,
) -> Result<(reqwest::Response, Value, UpstreamMeta), ProviderError> {
    let mut body = raw_request.clone();
    if let Value::Object(map) = &mut body {
        map.insert("stream".to_owned(), Value::Bool(true));
        map.insert(
            "stream_options".to_owned(),
            serde_json::json!({"include_usage": true}),
        );
    }
    let (headers, canonical_headers) = upstream_headers(api_key);
    let request = client
        .post(format!("{base_url}/v1/chat/completions"))
        .headers(headers)
        .json(&body);
    let response = request
        .send()
        .await
        .map_err(|error| ProviderError::Transport(error.to_string()))?;
    let meta = upstream_meta(&response, canonical_headers);
    Ok((response, body, meta))
}

/// Accumulates OpenAI-shape SSE chunks into the canonical response shape.
/// Concatenates `delta.content` and `delta.tool_calls[].function.arguments`
/// per index, terminates on the literal `data: [DONE]` sentinel (not a
/// typed event — provider-apis.md §2).
#[derive(Debug, Default)]
pub struct StreamAccumulator {
    buffer: String,
    model: Option<String>,
    text: String,
    tool_calls: std::collections::BTreeMap<usize, AccToolCall>,
    finish_reason: Option<String>,
    usage: WireUsage,
    done: bool,
    /// Top-level chunk `id` (`chatcmpl-...`) — the provider request id
    /// (task brief item 5); empty when a stream is aborted before the
    /// first chunk.
    id: Option<String>,
    service_tier: Option<String>,
    /// Speculative — see `ProviderMeta`'s doc comment; not documented on
    /// the OpenAI streaming API today, so always `None` in practice.
    inference_geo: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct AccToolCall {
    id: String,
    name: String,
    arguments: String,
}

impl StreamAccumulator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn feed(&mut self, chunk: &[u8]) {
        self.buffer.push_str(&String::from_utf8_lossy(chunk));
        while let Some(pos) = self.buffer.find('\n') {
            let line: String = self.buffer.drain(..=pos).collect();
            self.handle_line(line.trim());
        }
    }

    fn handle_line(&mut self, line: &str) {
        let Some(data) = line.strip_prefix("data:") else {
            return;
        };
        let data = data.trim();
        if data.is_empty() {
            return;
        }
        if data == "[DONE]" {
            self.done = true;
            return;
        }
        if let Ok(value) = serde_json::from_str::<Value>(data) {
            self.apply_chunk(&value);
        }
    }

    fn apply_chunk(&mut self, value: &Value) {
        if let Some(model) = value.get("model").and_then(Value::as_str) {
            self.model = Some(model.to_owned());
        }
        if let Some(id) = value.get("id").and_then(Value::as_str) {
            self.id = Some(id.to_owned());
        }
        if let Some(tier) = value.get("service_tier").and_then(Value::as_str) {
            self.service_tier = Some(tier.to_owned());
        }
        if let Some(geo) = value.get("inference_geo").and_then(Value::as_str) {
            self.inference_geo = Some(geo.to_owned());
        }
        if let Some(usage) = value.get("usage")
            && let Ok(parsed) = serde_json::from_value::<WireUsage>(usage.clone())
        {
            self.usage = parsed;
        }
        let Some(choices) = value.get("choices").and_then(Value::as_array) else {
            return;
        };
        let Some(choice) = choices.first() else {
            return;
        };
        if let Some(reason) = choice.get("finish_reason").and_then(Value::as_str) {
            self.finish_reason = Some(reason.to_owned());
        }
        let Some(delta) = choice.get("delta") else {
            return;
        };
        if let Some(text) = delta.get("content").and_then(Value::as_str) {
            self.text.push_str(text);
        }
        if let Some(tool_calls) = delta.get("tool_calls").and_then(Value::as_array) {
            for call in tool_calls {
                let index = call.get("index").and_then(Value::as_u64).unwrap_or(0) as usize;
                let entry = self.tool_calls.entry(index).or_default();
                if let Some(id) = call.get("id").and_then(Value::as_str) {
                    entry.id = id.to_owned();
                }
                if let Some(function) = call.get("function") {
                    if let Some(name) = function.get("name").and_then(Value::as_str) {
                        entry.name.push_str(name);
                    }
                    if let Some(arguments) = function.get("arguments").and_then(Value::as_str) {
                        entry.arguments.push_str(arguments);
                    }
                }
            }
        }
    }

    pub fn finish(self, fallback_model: &str) -> (CanonicalResponse, ProviderMeta, String) {
        let mut content = Vec::new();
        if !self.text.is_empty() {
            content.push(CanonicalBlock::Text { text: self.text });
        }
        for (_, call) in self.tool_calls {
            let input = if call.arguments.trim().is_empty() {
                Value::Object(Default::default())
            } else {
                serde_json::from_str(&call.arguments)
                    .unwrap_or_else(|_| Value::String(call.arguments.clone()))
            };
            content.push(CanonicalBlock::ToolUse {
                id: call.id,
                name: call.name,
                input,
            });
        }
        let stop_reason = self.finish_reason.unwrap_or_default();
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
    fn parses_flat_string_content() {
        let raw = serde_json::json!({
            "model": "gpt-5.2",
            "messages": [{"role": "user", "content": "hi"}]
        });
        let (_, stream, canonical) = parse_request(raw.to_string().as_bytes()).unwrap();
        assert!(!stream);
        assert_eq!(
            canonical.messages[0].content,
            vec![CanonicalBlock::Text {
                text: "hi".to_owned()
            }]
        );
    }

    #[test]
    fn tool_role_message_becomes_tool_result_block() {
        let raw = serde_json::json!({
            "model": "m",
            "messages": [{"role": "tool", "tool_call_id": "call_1", "content": "42"}]
        });
        let (_, _, canonical) = parse_request(raw.to_string().as_bytes()).unwrap();
        assert_eq!(canonical.messages[0].role, CanonicalRole::Tool);
        assert_eq!(
            canonical.messages[0].content,
            vec![CanonicalBlock::ToolResult {
                tool_use_id: "call_1".to_owned(),
                content: "42".to_owned(),
                is_error: false
            }]
        );
    }

    #[test]
    fn assistant_tool_calls_become_tool_use_blocks() {
        let raw = serde_json::json!({
            "model": "m",
            "messages": [{
                "role": "assistant",
                "content": null,
                "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "get_weather", "arguments": "{\"city\":\"NYC\"}"}}]
            }]
        });
        let (_, _, canonical) = parse_request(raw.to_string().as_bytes()).unwrap();
        assert_eq!(
            canonical.messages[0].content,
            vec![CanonicalBlock::ToolUse {
                id: "call_1".to_owned(),
                name: "get_weather".to_owned(),
                input: serde_json::json!({"city": "NYC"}),
            }]
        );
    }

    #[test]
    fn content_filter_finish_reason_is_refusal() {
        assert_eq!(
            outcome_for_finish_reason("content_filter"),
            Outcome::Refusal
        );
        assert_eq!(outcome_for_finish_reason("stop"), Outcome::Ok);
    }

    #[test]
    fn stream_accumulator_matches_non_streaming_for_same_content() {
        let non_streaming_response = serde_json::json!({
            "id": "1",
            "model": "gpt-5.2",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "Hello, world!"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 7, "completion_tokens": 3}
        });
        let expected = to_canonical_response(&non_streaming_response).unwrap();

        let mut acc = StreamAccumulator::new();
        let lines = [
            r#"{"id":"1","model":"gpt-5.2","choices":[{"index":0,"delta":{"role":"assistant"},"finish_reason":null}]}"#,
            r#"{"id":"1","model":"gpt-5.2","choices":[{"index":0,"delta":{"content":"Hello, "},"finish_reason":null}]}"#,
            r#"{"id":"1","model":"gpt-5.2","choices":[{"index":0,"delta":{"content":"world!"},"finish_reason":null}]}"#,
            r#"{"id":"1","model":"gpt-5.2","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#,
            r#"{"id":"1","model":"gpt-5.2","choices":[],"usage":{"prompt_tokens":7,"completion_tokens":3}}"#,
        ];
        for line in lines {
            acc.feed(format!("data: {line}\n").as_bytes());
        }
        acc.feed(b"data: [DONE]\n");

        let assembled = acc.finish("fallback");
        assert_eq!(assembled, expected);
    }

    #[test]
    fn stream_accumulator_concatenates_tool_call_arguments_by_index() {
        let mut acc = StreamAccumulator::new();
        let lines = [
            r#"{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_1","function":{"name":"get_weather","arguments":""}}]},"finish_reason":null}]}"#,
            r#"{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"city\":"}}]},"finish_reason":null}]}"#,
            r#"{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"NYC\"}"}}]},"finish_reason":"tool_calls"}]}"#,
        ];
        for line in lines {
            acc.feed(format!("data: {line}\n").as_bytes());
        }
        let (assembled, _meta, _id) = acc.finish("m");
        assert_eq!(
            assembled.content,
            vec![CanonicalBlock::ToolUse {
                id: "call_1".to_owned(),
                name: "get_weather".to_owned(),
                input: serde_json::json!({"city": "NYC"}),
            }]
        );
    }

    /// Documents the deviation in `WireUsage::to_canonical_usage`: OpenAI
    /// has no "cache creation" concept, so `cache_creation_tokens` is
    /// always 0 and `cache_read_tokens` comes from
    /// `prompt_tokens_details.cached_tokens`, subtracted out of
    /// `input_tokens` so the four counters stay additive like Anthropic's.
    #[test]
    fn cached_tokens_are_split_out_of_prompt_tokens_not_double_counted() {
        let raw = serde_json::json!({
            "model": "m",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "hi"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 100, "completion_tokens": 10, "prompt_tokens_details": {"cached_tokens": 40}}
        });
        let (response, _meta, _id) = to_canonical_response(&raw).unwrap();
        assert_eq!(response.usage.input_tokens, 60);
        assert_eq!(response.usage.cache_creation_tokens, 0);
        assert_eq!(response.usage.cache_read_tokens, 40);
        assert_eq!(response.usage.output_tokens, 10);
    }

    #[test]
    fn provider_request_id_prefers_body_id() {
        let raw = serde_json::json!({
            "id": "chatcmpl-abc",
            "model": "m",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "hi"}, "finish_reason": "stop"}],
            "usage": {}
        });
        let (_response, _meta, provider_request_id) = to_canonical_response(&raw).unwrap();
        assert_eq!(provider_request_id, "chatcmpl-abc");
    }

    #[test]
    fn upstream_headers_redact_the_bearer_token() {
        let (_headers, canonical) = upstream_headers("sk-super-secret");
        assert_eq!(
            canonical.get("authorization").map(String::as_str),
            Some(REDACTED_HEADER_VALUE)
        );
        assert!(!canonical.values().any(|v| v.contains("sk-super-secret")));
    }
}
