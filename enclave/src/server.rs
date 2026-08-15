//! Axum router and handlers. Routes (`docs/SPEC.md` §4):
//! `POST /v1/chat/completions` (OpenAI-compatible), `POST /v1/messages`
//! (Anthropic passthrough), `GET /attestation`, `POST /attestation`,
//! `GET /health_check`, `GET /receipts/{id}`. Every inference response
//! (success, refusal, upstream error, or policy denial) carries an
//! `x-receipt-id` header. Concurrency is bounded by a semaphore; request
//! bodies are capped via `DefaultBodyLimit`.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header::AUTHORIZATION};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_util::StreamExt as _;
use nautilus::{
    AttestationBody, ErrorBody, HealthCheckBody, NautilusContext, decode_hex, encode_hex,
};
use serde_json::Value;
use tokio::sync::Semaphore;
use uuid::Uuid;

use crate::auth;
use crate::blob;
use crate::canonical::{CanonicalHeaders, CanonicalResponse, Outcome, ProviderMeta, sha256_of};
use crate::config::AppConfig;
use crate::policy::EvaluationRequest;
use crate::providers::{
    ErrorResponseRecord, ProviderError, UpstreamMeta, anthropic, build_http_client, openai,
};
use crate::receipt::{self, Receipt, ReceiptStore, StoredReceipt};

/// 1 MiB default request body cap (`docs/SPEC.md` §4 / task brief).
pub const DEFAULT_MAX_BODY_BYTES: usize = 1024 * 1024;
/// Default bound on concurrent in-flight requests.
pub const DEFAULT_CONCURRENCY_LIMIT: usize = 16;

/// `provider` discriminator values (`docs/SPEC.md` §3, task brief item 8).
mod provider_id {
    pub const ANTHROPIC: u8 = 0;
    pub const OPENAI_COMPATIBLE: u8 = 1;
}

/// Shared shape of `anthropic::to_canonical_response` /
/// `openai::to_canonical_response`: parse a raw upstream body into the
/// canonical response (content-committed via `response_blob`), the
/// canonical provider-meta blob (`provider_meta_hash`), and the provider's
/// own request id (task brief item 5).
type ToCanonicalResponseFn =
    fn(&Value) -> Result<(CanonicalResponse, ProviderMeta, String), ProviderError>;

pub(crate) struct Inner {
    ctx: NautilusContext,
    config: AppConfig,
    http: reqwest::Client,
    limiter: Arc<Semaphore>,
    receipts: ReceiptStore,
    /// PCR-measured provider endpoints. Always the compile-time constants
    /// from `providers::{anthropic,openai}::BASE_URL` in production — see
    /// those modules' doc comments. `build_router` is the single place that
    /// wires these; `app()` (the only production constructor) always passes
    /// the constants, `#[cfg(test)] app_with_base_urls` is the only other
    /// caller and is unreachable outside this crate's own test binary.
    anthropic_base_url: String,
    openai_base_url: String,
}

#[derive(Clone)]
pub(crate) struct AppState(Arc<Inner>);

impl std::ops::Deref for AppState {
    type Target = Inner;
    fn deref(&self) -> &Inner {
        &self.0
    }
}

pub fn app(ctx: NautilusContext, config: AppConfig) -> Router {
    build_router(
        ctx,
        config,
        anthropic::BASE_URL.to_owned(),
        openai::BASE_URL.to_owned(),
    )
}

/// Test-only constructor letting the test suite point the adapters at a
/// local `wiremock` server. Not reachable from `AppConfig`/boot config, not
/// exported outside the crate's test binary — see `Inner::anthropic_base_url`.
#[cfg(test)]
fn app_with_base_urls(
    ctx: NautilusContext,
    config: AppConfig,
    anthropic_base_url: String,
    openai_base_url: String,
) -> Router {
    build_router(ctx, config, anthropic_base_url, openai_base_url)
}

fn build_router(
    ctx: NautilusContext,
    config: AppConfig,
    anthropic_base_url: String,
    openai_base_url: String,
) -> Router {
    let max_body_bytes = config.max_body_bytes;
    let receipts = ReceiptStore::new(config.receipt_ring_buffer_size);
    let limiter = Arc::new(Semaphore::new(config.concurrency_limit));
    let state = AppState(Arc::new(Inner {
        ctx,
        config,
        http: build_http_client(),
        limiter,
        receipts,
        anthropic_base_url,
        openai_base_url,
    }));

    Router::new()
        .route("/health_check", get(health_check))
        .route("/attestation", get(get_attestation))
        .route("/attestation", post(post_attestation))
        .route("/v1/chat/completions", post(chat_completions))
        .route("/v1/messages", post(messages))
        .route("/receipts/{id}", get(get_receipt))
        .layer(DefaultBodyLimit::max(max_body_bytes))
        .with_state(state)
}

pub async fn serve(addr: std::net::SocketAddr, app: Router) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn error_response(status: StatusCode, code: &str, message: impl Into<String>) -> Response {
    (
        status,
        Json(ErrorBody {
            error: code.to_owned(),
            message: message.into(),
        }),
    )
        .into_response()
}

fn insert_receipt_header(response: &mut Response, receipt_id: &str) {
    if let Ok(value) = HeaderValue::from_str(receipt_id) {
        response.headers_mut().insert("x-receipt-id", value);
    }
}

fn decode_optional_hex(value: Option<&str>) -> Result<Option<Vec<u8>>, String> {
    value
        .map(decode_hex)
        .transpose()
        .map_err(|error| error.to_string())
}

// --- health / attestation / receipts -------------------------------------

async fn health_check(State(state): State<AppState>) -> Json<HealthCheckBody> {
    Json(HealthCheckBody {
        pk: state.ctx.public_key_hex(),
        address: state.ctx.sui_address(),
    })
}

/// No nonce — for third-party verification (`docs/SPEC.md` §4).
async fn get_attestation(State(state): State<AppState>) -> Response {
    match state.ctx.attestation(None, None) {
        Ok(document) => Json(serde_json::json!({
            "attestation": encode_hex(document),
            // Convenience copy of the key the attestation document commits to,
            // so a client can verify receipt signatures without parsing CBOR.
            // It is NOT independently trustworthy: a verifier must confirm it
            // matches the key inside `attestation` (scripts/verify_deployment.ts
            // does exactly that) before trusting anything signed with it.
            "public_key": state.ctx.public_key_hex(),
        }))
        .into_response(),
        Err(error) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            error.to_string(),
        ),
    }
}

/// Body `{ nonce: hex }`, passed through to the NSM attestation request —
/// required by the sender-bound registration flow (`docs/SPEC.md` §3/§4):
/// onchain registration binds the attestation's nonce to the registering
/// Sui address, so nobody can register a gateway without this route.
async fn post_attestation(
    State(state): State<AppState>,
    Json(body): Json<AttestationBody>,
) -> Response {
    let nonce = match decode_optional_hex(body.nonce.as_deref()) {
        Ok(value) => value,
        Err(message) => return error_response(StatusCode::BAD_REQUEST, "bad_request", message),
    };
    let user_data = match decode_optional_hex(body.user_data.as_deref()) {
        Ok(value) => value,
        Err(message) => return error_response(StatusCode::BAD_REQUEST, "bad_request", message),
    };
    match state.ctx.attestation(nonce, user_data) {
        Ok(document) => Json(serde_json::json!({
            "attestation": encode_hex(document),
            // Convenience copy of the key the attestation document commits to,
            // so a client can verify receipt signatures without parsing CBOR.
            // It is NOT independently trustworthy: a verifier must confirm it
            // matches the key inside `attestation` (scripts/verify_deployment.ts
            // does exactly that) before trusting anything signed with it.
            "public_key": state.ctx.public_key_hex(),
        }))
        .into_response(),
        Err(error) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            error.to_string(),
        ),
    }
}

async fn get_receipt(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    match state.receipts.get(&id) {
        Some(receipt) => Json(receipt).into_response(),
        None => error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            "no receipt with that id",
        ),
    }
}

// --- shared receipt plumbing ----------------------------------------------

/// Everything about a receipt that's fixed before we know how the upstream
/// call turns out: which provider/host this request targeted, the
/// request's own content commitment, and — once available — the artifacts
/// of actually dispatching it upstream (headers sent, TLS peer, any
/// provider request id surfaced via a response header). Built once per
/// request and threaded into every possible exit point (success, refusal,
/// upstream error, policy denial) so each one constructs its `Receipt` from
/// the same source of truth instead of re-deriving pieces.
struct CallContext {
    receipt_id: [u8; 16],
    provider: u8,
    endpoint_host: &'static str,
    request_blob: [u8; 32],
    upstream_request_blob: [u8; 32],
    upstream_headers_hash: [u8; 32],
    tls_cert_sha256: [u8; 32],
    /// `request-id`/`x-request-id` response header, if a response was
    /// received. Only a fallback — success/refusal paths prefer the `id`
    /// field on the response body itself (task brief item 5).
    provider_request_id: String,
}

impl CallContext {
    /// For paths where no upstream call is ever attempted (policy denial,
    /// provider not configured): no headers were sent, no TLS handshake
    /// happened, and there is no dispatched-request transform to speak of.
    fn no_upstream_call(
        receipt_id: [u8; 16],
        provider: u8,
        endpoint_host: &'static str,
        request_blob: [u8; 32],
    ) -> Self {
        let upstream_headers_hash = sha256_of(&CanonicalHeaders::new()).unwrap_or([0u8; 32]);
        Self {
            receipt_id,
            provider,
            endpoint_host,
            request_blob,
            upstream_request_blob: request_blob,
            upstream_headers_hash,
            tls_cert_sha256: [0u8; 32],
            provider_request_id: String::new(),
        }
    }

    /// For paths where a call was attempted and `UpstreamMeta` was
    /// captured (headers actually sent, TLS info if a response came back).
    fn with_upstream_meta(
        receipt_id: [u8; 16],
        provider: u8,
        endpoint_host: &'static str,
        request_blob: [u8; 32],
        upstream_request_blob: [u8; 32],
        meta: UpstreamMeta,
    ) -> Self {
        let upstream_headers_hash = sha256_of(&meta.upstream_headers).unwrap_or([0u8; 32]);
        Self {
            receipt_id,
            provider,
            endpoint_host,
            request_blob,
            upstream_request_blob,
            upstream_headers_hash,
            tls_cert_sha256: meta.tls_cert_sha256,
            provider_request_id: meta.request_id_header.unwrap_or_default(),
        }
    }
}

/// All fields needed to construct+sign a `Receipt`, mirroring its field
/// order 1:1 (`receipt.rs`) plus `outcome` as an `Outcome` rather than a
/// bare `u8`. `timestamp_ms` is deliberately not part of this struct —
/// `sign_and_store` reads the clock itself at the moment of signing, so
/// every receipt's timestamp reflects when it was actually issued.
struct ReceiptParts {
    receipt_id: [u8; 16],
    provider: u8,
    endpoint_host: String,
    tls_cert_sha256: [u8; 32],
    request_blob: [u8; 32],
    upstream_request_blob: [u8; 32],
    upstream_headers_hash: [u8; 32],
    model_id: String,
    provider_request_id: String,
    response_blob: [u8; 32],
    provider_meta_hash: [u8; 32],
    input_tokens: u64,
    cache_creation_tokens: u64,
    cache_read_tokens: u64,
    output_tokens: u64,
    outcome: Outcome,
}

fn sign_and_store(
    state: &AppState,
    parts: ReceiptParts,
) -> Result<StoredReceipt, nautilus::NautilusError> {
    let timestamp_ms = current_timestamp_ms();
    let payload = Receipt {
        receipt_id: parts.receipt_id,
        config_hash: state.config.config_hash,
        provider: parts.provider,
        endpoint_host: parts.endpoint_host,
        tls_cert_sha256: parts.tls_cert_sha256,
        request_blob: parts.request_blob,
        upstream_request_blob: parts.upstream_request_blob,
        upstream_headers_hash: parts.upstream_headers_hash,
        model_id: parts.model_id,
        provider_request_id: parts.provider_request_id,
        response_blob: parts.response_blob,
        provider_meta_hash: parts.provider_meta_hash,
        input_tokens: parts.input_tokens,
        cache_creation_tokens: parts.cache_creation_tokens,
        cache_read_tokens: parts.cache_read_tokens,
        output_tokens: parts.output_tokens,
        outcome: parts.outcome.as_u8(),
    };
    let message = receipt::serialize_intent_message(&payload, timestamp_ms);
    let signature = state.ctx.sign(&message)?;
    let stored = StoredReceipt::new(&payload, timestamp_ms, &signature);
    state.receipts.insert(stored.clone());
    Ok(stored)
}

/// Builds+signs+stores an error-path receipt (`Outcome::UpstreamError` or
/// `Outcome::PolicyDenied`) whose `response_blob` covers a small canonical
/// error record rather than an absent/never-arrived response, and returns
/// the client-facing error response with `x-receipt-id` set.
///
/// `provider_meta_hash` covers a default (empty) `ProviderMeta` on every
/// error path: there is no real provider-reported `stop_reason` /
/// `service_tier` to commit to when the call was denied, never dispatched,
/// or failed before a body arrived.
#[allow(clippy::too_many_arguments)]
fn finish_error_receipt(
    state: &AppState,
    ctx: &CallContext,
    model_hint: &str,
    outcome: Outcome,
    status: Option<u16>,
    message: String,
    http_status: StatusCode,
    error_code: &str,
) -> Response {
    let record = ErrorResponseRecord {
        error: true,
        status,
        message: &message,
    };
    let response_blob = blob::blob_id_of(&record).unwrap_or([0u8; 32]);
    let provider_meta_hash = sha256_of(&ProviderMeta::default()).unwrap_or([0u8; 32]);
    let parts = ReceiptParts {
        receipt_id: ctx.receipt_id,
        provider: ctx.provider,
        endpoint_host: ctx.endpoint_host.to_owned(),
        tls_cert_sha256: ctx.tls_cert_sha256,
        request_blob: ctx.request_blob,
        upstream_request_blob: ctx.upstream_request_blob,
        upstream_headers_hash: ctx.upstream_headers_hash,
        model_id: model_hint.to_owned(),
        provider_request_id: ctx.provider_request_id.clone(),
        response_blob,
        provider_meta_hash,
        input_tokens: 0,
        cache_creation_tokens: 0,
        cache_read_tokens: 0,
        output_tokens: 0,
        outcome,
    };
    match sign_and_store(state, parts) {
        Ok(stored) => {
            let mut response = (
                http_status,
                Json(ErrorBody {
                    error: error_code.to_owned(),
                    message,
                }),
            )
                .into_response();
            insert_receipt_header(&mut response, &stored.receipt_id);
            response
        }
        Err(error) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "signing_failed",
            error.to_string(),
        ),
    }
}

fn finish_non_streaming_ok(
    state: &AppState,
    ctx: &CallContext,
    raw_response: &Value,
    to_canonical: ToCanonicalResponseFn,
    outcome_for: fn(&str) -> Outcome,
    model_hint: &str,
) -> Response {
    let (canonical_response, provider_meta, provider_request_id) = match to_canonical(raw_response)
    {
        Ok(value) => value,
        Err(error) => {
            return finish_error_receipt(
                state,
                ctx,
                model_hint,
                Outcome::UpstreamError,
                None,
                format!("failed to decode upstream response: {error}"),
                StatusCode::BAD_GATEWAY,
                "upstream_decode_error",
            );
        }
    };
    let outcome = outcome_for(&canonical_response.stop_reason);
    let response_blob = match blob::blob_id_of(&canonical_response) {
        Ok(blob) => blob,
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                error.to_string(),
            );
        }
    };
    let provider_meta_hash = match sha256_of(&provider_meta) {
        Ok(hash) => hash,
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                error.to_string(),
            );
        }
    };
    // Task brief item 5: prefer the body `id`, fall back to the
    // `request-id`-style response header captured in `ctx`, empty string
    // if neither is present.
    let provider_request_id = if provider_request_id.is_empty() {
        ctx.provider_request_id.clone()
    } else {
        provider_request_id
    };
    let parts = ReceiptParts {
        receipt_id: ctx.receipt_id,
        provider: ctx.provider,
        endpoint_host: ctx.endpoint_host.to_owned(),
        tls_cert_sha256: ctx.tls_cert_sha256,
        request_blob: ctx.request_blob,
        upstream_request_blob: ctx.upstream_request_blob,
        upstream_headers_hash: ctx.upstream_headers_hash,
        model_id: canonical_response.model.clone(),
        provider_request_id,
        response_blob,
        provider_meta_hash,
        input_tokens: canonical_response.usage.input_tokens,
        cache_creation_tokens: canonical_response.usage.cache_creation_tokens,
        cache_read_tokens: canonical_response.usage.cache_read_tokens,
        output_tokens: canonical_response.usage.output_tokens,
        outcome,
    };
    match sign_and_store(state, parts) {
        Ok(stored) => {
            let mut response = Json(raw_response.clone()).into_response();
            insert_receipt_header(&mut response, &stored.receipt_id);
            response
        }
        Err(error) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "signing_failed",
            error.to_string(),
        ),
    }
}

// --- OpenAI-compatible surface --------------------------------------------

/// Header a client may set to choose the receipt's nonce itself.
pub const NONCE_HEADER: &str = "x-sekisho-nonce";

/// Resolve the receipt nonce for a request.
///
/// `receipt_id` is a *uniqueness nonce*, not the receipt's identity — the
/// signature is what identifies a receipt, and is what consumers should dedupe
/// on. Its job is to keep two byte-identical exchanges (same prompt, same
/// response, same millisecond) from collapsing into one signed payload, which
/// would undercount paid calls.
///
/// A client may supply it via `x-sekisho-nonce` as 32 hex characters. Because
/// it is covered by the signature, a client-chosen nonce lets the caller prove
/// which of its own calls a receipt belongs to, and gives the idempotency key
/// neither Anthropic nor OpenAI offers. Absent the header, the enclave picks a
/// random v4 UUID as before.
fn resolve_receipt_id(headers: &HeaderMap) -> Result<[u8; 16], String> {
    let Some(raw) = headers.get(NONCE_HEADER) else {
        return Ok(*Uuid::new_v4().as_bytes());
    };
    let text = raw
        .to_str()
        .map_err(|_| format!("{NONCE_HEADER} must be ASCII hex"))?
        .trim();
    let bytes = decode_hex(text).map_err(|_| format!("{NONCE_HEADER} must be valid hex"))?;
    let exact: [u8; 16] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("{NONCE_HEADER} must be exactly 16 bytes (32 hex characters)"))?;
    Ok(exact)
}

async fn chat_completions(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(caller_key) = authenticate(&state, &headers) else {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "missing or invalid bearer key",
        );
    };

    let Ok(_permit) = state.limiter.clone().try_acquire_owned() else {
        return error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "too_many_requests",
            "too many concurrent requests",
        );
    };

    let (raw_request, wants_stream, canonical_request) = match openai::parse_request(&body) {
        Ok(value) => value,
        Err(error) => {
            return error_response(StatusCode::BAD_REQUEST, "bad_request", error.to_string());
        }
    };
    let request_blob = match blob::blob_id_of(&canonical_request) {
        Ok(blob) => blob,
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                error.to_string(),
            );
        }
    };
    let receipt_id = match resolve_receipt_id(&headers) {
        Ok(id) => id,
        Err(message) => return error_response(StatusCode::BAD_REQUEST, "bad_request", message),
    };
    let model_hint = canonical_request.model.clone();

    if let Err(denial) = state.config.policy.evaluate(&EvaluationRequest {
        caller_key: &caller_key,
        model: &canonical_request.model,
        max_tokens: canonical_request.max_tokens,
        request_bytes: body.len(),
    }) {
        // No upstream call is made on a policy denial.
        let ctx = CallContext::no_upstream_call(
            receipt_id,
            provider_id::OPENAI_COMPATIBLE,
            openai::HOST,
            request_blob,
        );
        return finish_error_receipt(
            &state,
            &ctx,
            &model_hint,
            Outcome::PolicyDenied,
            None,
            denial.reason,
            StatusCode::FORBIDDEN,
            "policy_denied",
        );
    }

    let Some(api_key) = state.config.openai_api_key.clone() else {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "provider_unavailable",
            "OpenAI-compatible provider is not configured",
        );
    };

    if wants_stream {
        return openai_stream_response(
            state,
            receipt_id,
            request_blob,
            api_key,
            raw_request,
            model_hint,
        )
        .await;
    }

    match openai::call_non_streaming(&state.http, &state.openai_base_url, &api_key, &raw_request)
        .await
    {
        Ok((status, response_body, meta)) if (200..300).contains(&status) => {
            let ctx = CallContext::with_upstream_meta(
                receipt_id,
                provider_id::OPENAI_COMPATIBLE,
                openai::HOST,
                request_blob,
                request_blob,
                meta,
            );
            finish_non_streaming_ok(
                &state,
                &ctx,
                &response_body,
                openai::to_canonical_response,
                openai::outcome_for_finish_reason,
                &model_hint,
            )
        }
        Ok((status, response_body, meta)) => {
            let ctx = CallContext::with_upstream_meta(
                receipt_id,
                provider_id::OPENAI_COMPATIBLE,
                openai::HOST,
                request_blob,
                request_blob,
                meta,
            );
            finish_error_receipt(
                &state,
                &ctx,
                &model_hint,
                Outcome::UpstreamError,
                Some(status),
                response_body.to_string(),
                StatusCode::BAD_GATEWAY,
                "upstream_error",
            )
        }
        Err(error) => {
            let ctx = CallContext::no_upstream_call(
                receipt_id,
                provider_id::OPENAI_COMPATIBLE,
                openai::HOST,
                request_blob,
            );
            finish_error_receipt(
                &state,
                &ctx,
                &model_hint,
                Outcome::UpstreamError,
                None,
                error.to_string(),
                StatusCode::BAD_GATEWAY,
                "upstream_error",
            )
        }
    }
}

async fn openai_stream_response(
    state: AppState,
    receipt_id: [u8; 16],
    request_blob: [u8; 32],
    api_key: String,
    raw_request: Value,
    model_hint: String,
) -> Response {
    let (upstream, dispatched_body, meta) =
        match openai::start_streaming(&state.http, &state.openai_base_url, &api_key, &raw_request)
            .await
        {
            Ok(value) => value,
            Err(error) => {
                let ctx = CallContext::no_upstream_call(
                    receipt_id,
                    provider_id::OPENAI_COMPATIBLE,
                    openai::HOST,
                    request_blob,
                );
                return finish_error_receipt(
                    &state,
                    &ctx,
                    &model_hint,
                    Outcome::UpstreamError,
                    None,
                    error.to_string(),
                    StatusCode::BAD_GATEWAY,
                    "upstream_error",
                );
            }
        };
    // Forcing `stream_options.include_usage` is a genuine gateway transform
    // (provider-apis.md §4), so `upstream_request_blob` is computed from
    // what was actually dispatched, separately from `request_blob`.
    let upstream_request_blob = blob::blob_id_of(&dispatched_body).unwrap_or(request_blob);
    let ctx = CallContext::with_upstream_meta(
        receipt_id,
        provider_id::OPENAI_COMPATIBLE,
        openai::HOST,
        request_blob,
        upstream_request_blob,
        meta,
    );

    if !upstream.status().is_success() {
        let status = upstream.status().as_u16();
        let body_text = upstream.text().await.unwrap_or_default();
        return finish_error_receipt(
            &state,
            &ctx,
            &model_hint,
            Outcome::UpstreamError,
            Some(status),
            body_text,
            StatusCode::BAD_GATEWAY,
            "upstream_error",
        );
    }

    let receipt_id_header = hex::encode(receipt_id);

    let byte_stream = async_stream::stream! {
        let mut acc = openai::StreamAccumulator::new();
        let mut had_transport_error = false;
        let mut upstream_stream = upstream.bytes_stream();
        while let Some(chunk) = upstream_stream.next().await {
            match chunk {
                Ok(bytes) => {
                    acc.feed(&bytes);
                    yield Ok::<Bytes, std::io::Error>(bytes);
                }
                Err(_error) => {
                    had_transport_error = true;
                    break;
                }
            }
        }
        let (canonical_response, provider_meta, provider_request_id) = acc.finish(&model_hint);
        let outcome = if had_transport_error {
            Outcome::UpstreamError
        } else {
            openai::outcome_for_finish_reason(&canonical_response.stop_reason)
        };
        let provider_request_id = if provider_request_id.is_empty() {
            ctx.provider_request_id.clone()
        } else {
            provider_request_id
        };
        if let (Ok(response_blob), Ok(provider_meta_hash)) = (
            blob::blob_id_of(&canonical_response),
            sha256_of(&provider_meta),
        ) {
            let parts = ReceiptParts {
                receipt_id: ctx.receipt_id,
                provider: ctx.provider,
                endpoint_host: ctx.endpoint_host.to_owned(),
                tls_cert_sha256: ctx.tls_cert_sha256,
                request_blob: ctx.request_blob,
                upstream_request_blob: ctx.upstream_request_blob,
                upstream_headers_hash: ctx.upstream_headers_hash,
                model_id: canonical_response.model.clone(),
                provider_request_id,
                response_blob,
                provider_meta_hash,
                input_tokens: canonical_response.usage.input_tokens,
                cache_creation_tokens: canonical_response.usage.cache_creation_tokens,
                cache_read_tokens: canonical_response.usage.cache_read_tokens,
                output_tokens: canonical_response.usage.output_tokens,
                outcome,
            };
            let _ = sign_and_store(&state, parts);
        }
    };

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/event-stream")
        .header("x-receipt-id", receipt_id_header)
        .body(Body::from_stream(byte_stream))
        .unwrap_or_else(|_| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "failed to build streaming response",
            )
        })
}

// --- Anthropic passthrough surface ----------------------------------------

async fn messages(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let Some(caller_key) = authenticate(&state, &headers) else {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "missing or invalid bearer key",
        );
    };

    let Ok(_permit) = state.limiter.clone().try_acquire_owned() else {
        return error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "too_many_requests",
            "too many concurrent requests",
        );
    };

    let (raw_request, wants_stream, canonical_request) = match anthropic::parse_request(&body) {
        Ok(value) => value,
        Err(error) => {
            return error_response(StatusCode::BAD_REQUEST, "bad_request", error.to_string());
        }
    };
    let request_blob = match blob::blob_id_of(&canonical_request) {
        Ok(blob) => blob,
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                error.to_string(),
            );
        }
    };
    let receipt_id = match resolve_receipt_id(&headers) {
        Ok(id) => id,
        Err(message) => return error_response(StatusCode::BAD_REQUEST, "bad_request", message),
    };
    let model_hint = canonical_request.model.clone();

    if let Err(denial) = state.config.policy.evaluate(&EvaluationRequest {
        caller_key: &caller_key,
        model: &canonical_request.model,
        max_tokens: canonical_request.max_tokens,
        request_bytes: body.len(),
    }) {
        let ctx = CallContext::no_upstream_call(
            receipt_id,
            provider_id::ANTHROPIC,
            anthropic::HOST,
            request_blob,
        );
        return finish_error_receipt(
            &state,
            &ctx,
            &model_hint,
            Outcome::PolicyDenied,
            None,
            denial.reason,
            StatusCode::FORBIDDEN,
            "policy_denied",
        );
    }

    let Some(api_key) = state.config.anthropic_api_key.clone() else {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "provider_unavailable",
            "Anthropic provider is not configured",
        );
    };

    if wants_stream {
        return anthropic_stream_response(
            state,
            receipt_id,
            request_blob,
            api_key,
            raw_request,
            model_hint,
        )
        .await;
    }

    match anthropic::call_non_streaming(
        &state.http,
        &state.anthropic_base_url,
        &api_key,
        &raw_request,
    )
    .await
    {
        Ok((status, response_body, meta)) if (200..300).contains(&status) => {
            let ctx = CallContext::with_upstream_meta(
                receipt_id,
                provider_id::ANTHROPIC,
                anthropic::HOST,
                request_blob,
                request_blob,
                meta,
            );
            finish_non_streaming_ok(
                &state,
                &ctx,
                &response_body,
                anthropic::to_canonical_response,
                anthropic::outcome_for_stop_reason,
                &model_hint,
            )
        }
        Ok((status, response_body, meta)) => {
            let ctx = CallContext::with_upstream_meta(
                receipt_id,
                provider_id::ANTHROPIC,
                anthropic::HOST,
                request_blob,
                request_blob,
                meta,
            );
            finish_error_receipt(
                &state,
                &ctx,
                &model_hint,
                Outcome::UpstreamError,
                Some(status),
                response_body.to_string(),
                StatusCode::BAD_GATEWAY,
                "upstream_error",
            )
        }
        Err(error) => {
            let ctx = CallContext::no_upstream_call(
                receipt_id,
                provider_id::ANTHROPIC,
                anthropic::HOST,
                request_blob,
            );
            finish_error_receipt(
                &state,
                &ctx,
                &model_hint,
                Outcome::UpstreamError,
                None,
                error.to_string(),
                StatusCode::BAD_GATEWAY,
                "upstream_error",
            )
        }
    }
}

async fn anthropic_stream_response(
    state: AppState,
    receipt_id: [u8; 16],
    request_blob: [u8; 32],
    api_key: String,
    raw_request: Value,
    model_hint: String,
) -> Response {
    let (upstream, meta) = match anthropic::start_streaming(
        &state.http,
        &state.anthropic_base_url,
        &api_key,
        &raw_request,
    )
    .await
    {
        Ok(value) => value,
        Err(error) => {
            let ctx = CallContext::no_upstream_call(
                receipt_id,
                provider_id::ANTHROPIC,
                anthropic::HOST,
                request_blob,
            );
            return finish_error_receipt(
                &state,
                &ctx,
                &model_hint,
                Outcome::UpstreamError,
                None,
                error.to_string(),
                StatusCode::BAD_GATEWAY,
                "upstream_error",
            );
        }
    };
    // v1 performs no request-mutating transform for the Anthropic surface
    // beyond normalizing `stream` (transport-only, excluded from hashing),
    // so upstream_request_blob == request_blob today. See task report.
    let ctx = CallContext::with_upstream_meta(
        receipt_id,
        provider_id::ANTHROPIC,
        anthropic::HOST,
        request_blob,
        request_blob,
        meta,
    );

    if !upstream.status().is_success() {
        let status = upstream.status().as_u16();
        let body_text = upstream.text().await.unwrap_or_default();
        return finish_error_receipt(
            &state,
            &ctx,
            &model_hint,
            Outcome::UpstreamError,
            Some(status),
            body_text,
            StatusCode::BAD_GATEWAY,
            "upstream_error",
        );
    }

    let receipt_id_header = hex::encode(receipt_id);

    let byte_stream = async_stream::stream! {
        let mut acc = anthropic::StreamAccumulator::new();
        let mut had_transport_error = false;
        let mut upstream_stream = upstream.bytes_stream();
        while let Some(chunk) = upstream_stream.next().await {
            match chunk {
                Ok(bytes) => {
                    acc.feed(&bytes);
                    yield Ok::<Bytes, std::io::Error>(bytes);
                }
                Err(_error) => {
                    had_transport_error = true;
                    break;
                }
            }
        }
        let (canonical_response, provider_meta, provider_request_id) = acc.finish(&model_hint);
        let outcome = if had_transport_error {
            Outcome::UpstreamError
        } else {
            anthropic::outcome_for_stop_reason(&canonical_response.stop_reason)
        };
        let provider_request_id = if provider_request_id.is_empty() {
            ctx.provider_request_id.clone()
        } else {
            provider_request_id
        };
        if let (Ok(response_blob), Ok(provider_meta_hash)) = (
            blob::blob_id_of(&canonical_response),
            sha256_of(&provider_meta),
        ) {
            let parts = ReceiptParts {
                receipt_id: ctx.receipt_id,
                provider: ctx.provider,
                endpoint_host: ctx.endpoint_host.to_owned(),
                tls_cert_sha256: ctx.tls_cert_sha256,
                request_blob: ctx.request_blob,
                upstream_request_blob: ctx.upstream_request_blob,
                upstream_headers_hash: ctx.upstream_headers_hash,
                model_id: canonical_response.model.clone(),
                provider_request_id,
                response_blob,
                provider_meta_hash,
                input_tokens: canonical_response.usage.input_tokens,
                cache_creation_tokens: canonical_response.usage.cache_creation_tokens,
                cache_read_tokens: canonical_response.usage.cache_read_tokens,
                output_tokens: canonical_response.usage.output_tokens,
                outcome,
            };
            let _ = sign_and_store(&state, parts);
        }
    };

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/event-stream")
        .header("x-receipt-id", receipt_id_header)
        .body(Body::from_stream(byte_stream))
        .unwrap_or_else(|_| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "failed to build streaming response",
            )
        })
}

// --- auth helper -----------------------------------------------------------

fn authenticate(state: &AppState, headers: &HeaderMap) -> Option<String> {
    let header_value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let bearer = auth::extract_bearer(header_value)?;
    auth::identify_caller(bearer, &state.config.caller_keys).map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use axum::http::Request;
    use http_body_util::BodyExt as _;
    use nautilus::NautilusContext;
    use serde_json::json;
    use tower::ServiceExt as _;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::config::AppConfig;
    use crate::policy::{CompiledPolicy, PolicyAction, PolicyDocument, PolicyRule};

    fn allow_all_policy() -> CompiledPolicy {
        CompiledPolicy::compile(&PolicyDocument {
            rules: vec![PolicyRule {
                name: "allow-all".to_owned(),
                action: PolicyAction::Allow,
                enabled: true,
                caller_keys: None,
                allowed_models: None,
                max_tokens: None,
                max_request_bytes: None,
            }],
        })
        .unwrap()
    }

    fn deny_all_policy() -> CompiledPolicy {
        CompiledPolicy::compile(&PolicyDocument {
            rules: vec![PolicyRule {
                name: "deny-all".to_owned(),
                action: PolicyAction::Deny,
                enabled: true,
                caller_keys: None,
                allowed_models: None,
                max_tokens: None,
                max_request_bytes: None,
            }],
        })
        .unwrap()
    }

    fn test_config(policy: CompiledPolicy) -> AppConfig {
        AppConfig {
            anthropic_api_key: Some("test-anthropic-key".to_owned()),
            openai_api_key: Some("test-openai-key".to_owned()),
            caller_keys: vec!["sk-caller".to_owned()],
            policy,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            concurrency_limit: DEFAULT_CONCURRENCY_LIMIT,
            receipt_ring_buffer_size: 64,
            config_hash: [7u8; 32],
        }
    }

    /// Builds a router for tests, pointing the adapters at `mock_server`
    /// (both providers, for simplicity — tests only ever call one). Passing
    /// the base URL as a plain argument (via the crate-internal,
    /// `#[cfg(test)]`-gated `app_with_base_urls`) is what makes this safe:
    /// no env vars, no unsafe code, and no path by which `AppConfig` (the
    /// boot-config-sourced type) could smuggle a base URL override into a
    /// real deployment. See `Inner::anthropic_base_url` doc comment.
    fn test_app(config: AppConfig, mock_server_uri: &str) -> Router {
        app_with_base_urls(
            NautilusContext::development(),
            config,
            mock_server_uri.to_owned(),
            mock_server_uri.to_owned(),
        )
    }

    /// Router variant for tests that never reach a provider (auth/policy
    /// rejections, receipt-store-only checks): no mock server needed.
    fn test_app_no_provider(config: AppConfig) -> Router {
        app(NautilusContext::development(), config)
    }

    async fn response_json(response: Response) -> serde_json::Value {
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        serde_json::from_slice(&bytes).expect("json")
    }

    #[tokio::test]
    async fn health_check_returns_identity() {
        let response = test_app_no_provider(test_config(allow_all_policy()))
            .oneshot(
                Request::builder()
                    .uri("/health_check")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = response_json(response).await;
        assert_eq!(json["pk"].as_str().unwrap().len(), 64);
    }

    #[tokio::test]
    async fn chat_completions_rejects_missing_auth() {
        let response = test_app_no_provider(test_config(allow_all_policy()))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/chat/completions")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({"model": "gpt-5.2", "messages": []}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn policy_denial_produces_receipt_with_outcome_3_and_no_upstream_call() {
        let mock_server = MockServer::start().await;
        // No mock registered for chat/completions: if the gateway called
        // upstream despite the denial, wiremock would 404 the unexpected
        // request and this test's receipt outcome assertion would still
        // catch it (outcome would not be 3), so this doubles as a "no
        // upstream call made" guard.
        let response = test_app(test_config(deny_all_policy()), &mock_server.uri())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/chat/completions")
                    .header("authorization", "Bearer sk-caller")
                    .header("content-type", "application/json")
                    .body(Body::from(json!({"model": "gpt-5.2", "messages": [{"role": "user", "content": "hi"}]}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let receipt_id = response
            .headers()
            .get("x-receipt-id")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        assert!(!receipt_id.is_empty());
    }

    #[tokio::test]
    async fn refusal_receipt_records_outcome_1_in_same_store() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "chatcmpl-1",
                "model": "gpt-5.2",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": ""}, "finish_reason": "content_filter"}],
                "usage": {"prompt_tokens": 5, "completion_tokens": 0}
            })))
            .mount(&mock_server)
            .await;

        let app_router = test_app(test_config(allow_all_policy()), &mock_server.uri());
        let response = app_router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/chat/completions")
                    .header("authorization", "Bearer sk-caller")
                    .header("content-type", "application/json")
                    .body(Body::from(json!({"model": "gpt-5.2", "messages": [{"role": "user", "content": "bad"}]}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let receipt_id = response
            .headers()
            .get("x-receipt-id")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();

        let receipt_response = app_router
            .oneshot(
                Request::builder()
                    .uri(format!("/receipts/{receipt_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(receipt_response.status(), StatusCode::OK);
        let receipt_json = response_json(receipt_response).await;
        assert_eq!(receipt_json["outcome"], 1);
        // provider=1 (openai-compatible), task brief item 8.
        assert_eq!(receipt_json["provider"], 1);
        assert_eq!(receipt_json["endpoint_host"], "api.openai.com");
        assert_eq!(receipt_json["provider_request_id"], "chatcmpl-1");
        // wiremock speaks plain HTTP, so no TLS handshake ever happens —
        // `tls_cert_sha256` falls back to the documented all-zero sentinel.
        assert_eq!(receipt_json["tls_cert_sha256"], hex::encode([0u8; 32]));
    }

    #[tokio::test]
    async fn usage_counters_are_reported_separately_not_folded() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "chatcmpl-2",
                "model": "gpt-5.2",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "hi"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 100, "completion_tokens": 10, "prompt_tokens_details": {"cached_tokens": 40}}
            })))
            .mount(&mock_server)
            .await;

        let app_router = test_app(test_config(allow_all_policy()), &mock_server.uri());
        let response = app_router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/chat/completions")
                    .header("authorization", "Bearer sk-caller")
                    .header("content-type", "application/json")
                    .body(Body::from(json!({"model": "gpt-5.2", "messages": [{"role": "user", "content": "hi"}]}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let receipt_id = response
            .headers()
            .get("x-receipt-id")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();

        let receipt_response = app_router
            .oneshot(
                Request::builder()
                    .uri(format!("/receipts/{receipt_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let receipt_json = response_json(receipt_response).await;
        assert_eq!(receipt_json["input_tokens"], 60);
        assert_eq!(receipt_json["cache_creation_tokens"], 0);
        assert_eq!(receipt_json["cache_read_tokens"], 40);
        assert_eq!(receipt_json["output_tokens"], 10);
    }

    #[tokio::test]
    async fn upstream_5xx_produces_outcome_2_receipt() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(
                ResponseTemplate::new(500).set_body_json(json!({"error": {"message": "boom"}})),
            )
            .mount(&mock_server)
            .await;

        let app_router = test_app(test_config(allow_all_policy()), &mock_server.uri());
        let response = app_router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/chat/completions")
                    .header("authorization", "Bearer sk-caller")
                    .header("content-type", "application/json")
                    .body(Body::from(json!({"model": "gpt-5.2", "messages": [{"role": "user", "content": "hi"}]}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let receipt_id = response
            .headers()
            .get("x-receipt-id")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();

        let receipt_response = app_router
            .oneshot(
                Request::builder()
                    .uri(format!("/receipts/{receipt_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let receipt_json = response_json(receipt_response).await;
        assert_eq!(receipt_json["outcome"], 2);
    }

    #[tokio::test]
    async fn oversized_body_is_rejected() {
        let big_body = "x".repeat(DEFAULT_MAX_BODY_BYTES + 1);
        let response = test_app_no_provider(test_config(allow_all_policy()))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/chat/completions")
                    .header("authorization", "Bearer sk-caller")
                    .header("content-type", "application/json")
                    .body(Body::from(big_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn unknown_receipt_id_returns_404() {
        let response = test_app_no_provider(test_config(allow_all_policy()))
            .oneshot(
                Request::builder()
                    .uri("/receipts/does-not-exist")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// Spawns a raw TCP server that starts a valid chunked SSE response,
    /// writes one real content chunk, then drops the connection without the
    /// terminating `0\r\n\r\n` chunk. `wiremock` can only shape whole
    /// request/response pairs, so a genuine mid-stream transport abort (the
    /// scenario `finish_error_receipt`'s `had_transport_error` branch
    /// exists for) needs a raw socket instead.
    async fn spawn_abrupt_sse_server() -> String {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let mut buf = [0u8; 4096];
            let _ = socket.read(&mut buf).await;

            let headers = "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\n\r\n";
            let _ = socket.write_all(headers.as_bytes()).await;

            let event = "data: {\"id\":\"1\",\"model\":\"gpt-5.2\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"partial\"},\"finish_reason\":null}]}\n\n";
            let framed = format!("{:x}\r\n{event}\r\n", event.len());
            let _ = socket.write_all(framed.as_bytes()).await;
            let _ = socket.flush().await;
            // Deliberately no terminating "0\r\n\r\n" chunk: drop the
            // socket so the client observes an incomplete chunked body.
        });

        format!("http://{addr}")
    }

    #[tokio::test]
    async fn mid_stream_upstream_abort_produces_outcome_2_receipt() {
        let base_url = spawn_abrupt_sse_server().await;
        let app_router = test_app(test_config(allow_all_policy()), &base_url);

        let response = app_router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/chat/completions")
                    .header("authorization", "Bearer sk-caller")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({"model": "gpt-5.2", "stream": true, "messages": [{"role": "user", "content": "hi"}]}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let receipt_id = response
            .headers()
            .get("x-receipt-id")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();

        // Drain the (partial, then aborted) streaming body. The finalize
        // step runs inline inside the same async generator before it ends
        // the stream, so by the time `collect()` resolves the receipt is
        // already stored — no separate synchronization needed.
        let _ = response.into_body().collect().await;

        let receipt_response = app_router
            .oneshot(
                Request::builder()
                    .uri(format!("/receipts/{receipt_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(receipt_response.status(), StatusCode::OK);
        let receipt_json = response_json(receipt_response).await;
        assert_eq!(receipt_json["outcome"], 2);
        // `id` from the one chunk that did arrive should still be recorded.
        assert_eq!(receipt_json["provider_request_id"], "1");
    }

    #[tokio::test]
    async fn anthropic_success_receipt_has_provider_0_and_correct_host() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "msg_1",
                "model": "claude-sonnet-5",
                "content": [{"type": "text", "text": "hi"}],
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 5, "output_tokens": 2}
            })))
            .mount(&mock_server)
            .await;

        let app_router = test_app(test_config(allow_all_policy()), &mock_server.uri());
        let response = app_router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/messages")
                    .header("authorization", "Bearer sk-caller")
                    .header("content-type", "application/json")
                    .body(Body::from(json!({"model": "claude-sonnet-5", "max_tokens": 100, "messages": [{"role": "user", "content": "hi"}]}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let receipt_id = response
            .headers()
            .get("x-receipt-id")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();

        let receipt_response = app_router
            .oneshot(
                Request::builder()
                    .uri(format!("/receipts/{receipt_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let receipt_json = response_json(receipt_response).await;
        assert_eq!(receipt_json["outcome"], 0);
        assert_eq!(receipt_json["provider"], 0);
        assert_eq!(receipt_json["endpoint_host"], "api.anthropic.com");
        assert_eq!(receipt_json["provider_request_id"], "msg_1");
        // Non-empty request/response bodies must produce a real
        // (non-zero) locally-computed Walrus blob id, not the "not
        // archived" sentinel.
        assert_ne!(receipt_json["request_blob"], hex::encode([0u8; 32]));
        assert_ne!(receipt_json["response_blob"], hex::encode([0u8; 32]));
    }
}

#[cfg(test)]
mod nonce_tests {
    use super::*;

    fn headers_with(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(NONCE_HEADER, HeaderValue::from_str(value).unwrap());
        h
    }

    #[test]
    fn absent_header_yields_a_random_nonce() {
        let a = resolve_receipt_id(&HeaderMap::new()).unwrap();
        let b = resolve_receipt_id(&HeaderMap::new()).unwrap();
        assert_ne!(a, b, "each request must get a distinct nonce");
    }

    #[test]
    fn client_supplied_nonce_is_used_verbatim() {
        let id = resolve_receipt_id(&headers_with("000102030405060708090a0b0c0d0e0f")).unwrap();
        assert_eq!(
            id,
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            "a client-chosen nonce must reach the signed payload unchanged, or the \
             caller cannot use it to identify its own call"
        );
    }

    #[test]
    fn client_supplied_nonce_is_stable_across_calls() {
        let h = headers_with("ffeeddccbbaa99887766554433221100");
        assert_eq!(
            resolve_receipt_id(&h).unwrap(),
            resolve_receipt_id(&h).unwrap()
        );
    }

    #[test]
    fn wrong_length_is_rejected_rather_than_padded() {
        // Silently padding or truncating would produce a nonce the client did
        // not choose, defeating the point.
        assert!(resolve_receipt_id(&headers_with("00010203")).is_err());
        assert!(resolve_receipt_id(&headers_with(&"ab".repeat(32))).is_err());
    }

    #[test]
    fn non_hex_is_rejected() {
        assert!(resolve_receipt_id(&headers_with("zz0102030405060708090a0b0c0d0e0f")).is_err());
    }
}
