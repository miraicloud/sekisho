//! Provider adapters. `anthropic` backs `POST /v1/messages`, `openai` backs
//! `POST /v1/chat/completions` (OpenAI-compatible: also covers
//! OpenRouter/DeepSeek/self-hosted per `docs/SPEC.md` §4, provided the
//! image is built with that base URL — see the module docs on each
//! adapter's `BASE_URL` constant for why it isn't runtime-configurable).

pub mod anthropic;
pub mod openai;

use crate::canonical::{CanonicalResponse, Outcome};

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
/// `native-tls`) per `docs/SPEC.md` §4 / task brief.
pub fn build_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .build()
        .expect("reqwest client with rustls-tls builds")
}

/// A minimal canonical record hashed as the `response_hash` when no valid
/// assembled response exists (upstream error, or an abort before any
/// content arrived). Keeps `response_hash` meaningful and reproducible even
/// on the error path, instead of being a hash of nothing / a sentinel.
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
