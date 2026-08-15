//! Provider adapters. `anthropic` backs `POST /v1/messages`, `openai` backs
//! `POST /v1/chat/completions` (OpenAI-compatible: also covers
//! OpenRouter/DeepSeek/self-hosted per `docs/SPEC.md` §4, provided the
//! image is built with that base URL — see the module docs on each
//! adapter's `BASE_URL` constant for why it isn't runtime-configurable).

pub mod anthropic;
pub mod openai;

use crate::canonical::{CanonicalHeaders, CanonicalResponse, Outcome};

/// Normalized provider error taxonomy (`docs/research/provider-apis.md` §4):
/// a relay must branch declines out of the error path entirely (handled via
/// `Outcome::Refusal` on a 2xx response, not via `ProviderError`).
#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    #[error("provider not configured (missing API key)")]
    NotConfigured,
    #[error("failed to decode request/response JSON: {0}")]
    Decode(String),
    #[error("upstream transport error: {0}")]
    Transport(String),
    #[error("upstream returned status {status}: {body}")]
    UpstreamStatus { status: u16, body: String },
}

/// Builds the shared outbound HTTP client. `rustls-tls` only (no
/// `native-tls`) per `docs/SPEC.md` §4 / task brief. `.tls_info(true)`
/// makes each response carry a `reqwest::tls::TlsInfo` extension with the
/// peer's leaf certificate DER, which the adapters SHA-256 into
/// `tls_cert_sha256` (`docs/SPEC.md` §3). Despite the task brief calling
/// this "reqwest's tls-info feature", reqwest 0.12 has no `tls-info` Cargo
/// feature — `TlsInfo` capture is a `ClientBuilder::tls_info(bool)` runtime
/// toggle gated on the `__tls` cfg, which `rustls-tls` (already enabled in
/// `Cargo.toml`) already provides. No `Cargo.toml` feature change was
/// needed for this item; see the task report.
pub fn build_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .tls_info(true)
        .build()
        .expect("reqwest client with rustls-tls builds")
}

/// A minimal canonical record whose Walrus blob ID becomes `response_blob`
/// when no valid assembled response exists (upstream error, or an abort
/// before any content arrived). Keeps `response_blob` meaningful and
/// reproducible even on the error path, instead of committing to nothing /
/// a sentinel.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ErrorResponseRecord<'a> {
    pub error: bool,
    pub status: Option<u16>,
    pub message: &'a str,
}

/// Result of a completed (non-streaming or fully-drained-streaming) call:
/// the assembled canonical response and its derived outcome.
#[derive(Debug, Clone)]
pub struct CallOutcome {
    pub canonical_response: CanonicalResponse,
    pub outcome: Outcome,
}

/// Fixed placeholder written into `upstream_headers_hash`'s canonical
/// header map in place of a secret header VALUE (`docs/SPEC.md` §3, task
/// brief item 7). `upstream_headers_hash` proves which header NAMES (and
/// non-secret values, e.g. an `anthropic-version` pin) were actually sent —
/// it must never let a verifier brute-force or otherwise learn anything
/// about the raw API key, so the secret's value is replaced by this
/// constant before hashing rather than hashed itself. Both adapters'
/// header-building functions are the only places outbound headers are ever
/// assembled, and both redact `x-api-key` / `authorization` through this
/// constant.
pub const REDACTED_HEADER_VALUE: &str = "redacted";

/// Metadata captured from the raw HTTP exchange with a provider, independent
/// of the parsed response body: which headers were actually sent (secret
/// values already redacted, ready to hash into `upstream_headers_hash`),
/// which TLS leaf certificate answered (already SHA-256'd into
/// `tls_cert_sha256`), and the `request-id`-style response header to fall
/// back to if the body carries no provider request id.
#[derive(Debug, Clone, Default)]
pub struct UpstreamMeta {
    pub upstream_headers: CanonicalHeaders,
    pub tls_cert_sha256: [u8; 32],
    pub request_id_header: Option<String>,
}
