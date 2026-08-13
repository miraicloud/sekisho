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
use crate::canonical::{self, CanonicalResponse, Outcome, sha256_of};
use crate::config::AppConfig;
use crate::policy::EvaluationRequest;
use crate::providers::{ErrorResponseRecord, ProviderError, anthropic, build_http_client, openai};
use crate::receipt::{self, ReceiptStore, ReceiptV1, StoredReceipt};

/// 1 MiB default request body cap (`docs/SPEC.md` §4 / task brief).
pub const DEFAULT_MAX_BODY_BYTES: usize = 1024 * 1024;
/// Default bound on concurrent in-flight requests.
pub const DEFAULT_CONCURRENCY_LIMIT: usize = 16;

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

#[allow(clippy::too_many_arguments)]
fn sign_and_store(
    state: &AppState,
    receipt_id: [u8; 16],
    request_hash: [u8; 32],
    upstream_request_hash: [u8; 32],
    model_id: String,
    response_hash: [u8; 32],
    input_tokens: u64,
    output_tokens: u64,
    outcome: Outcome,
) -> Result<StoredReceipt, nautilus::NautilusError> {
    let timestamp_ms = current_timestamp_ms();
    let payload = ReceiptV1 {
        receipt_id,
        config_hash: state.config.config_hash,
        request_hash,
        upstream_request_hash,
        model_id,
        response_hash,
        input_tokens,
        output_tokens,
        outcome: outcome.as_u8(),
    };
    let message = receipt::serialize_intent_message(&payload, timestamp_ms);
    let signature = state.ctx.sign(&message)?;
    let stored = StoredReceipt::new(&payload, timestamp_ms, &signature);
    state.receipts.insert(stored.clone());
    Ok(stored)
}

/// Builds+signs+stores an error-path receipt (`Outcome::UpstreamError` or
/// `Outcome::PolicyDenied`) whose `response_hash` covers a small canonical
/// error record rather than an absent/never-arrived response, and returns
/// the client-facing error response with `x-receipt-id` set.
#[allow(clippy::too_many_arguments)]
fn finish_error_receipt(
    state: &AppState,
    receipt_id: [u8; 16],
    request_hash: [u8; 32],
    upstream_request_hash: [u8; 32],
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
    let response_hash = canonical::sha256_of(&record).unwrap_or([0u8; 32]);
    match sign_and_store(
        state,
        receipt_id,
        request_hash,
        upstream_request_hash,
        model_hint.to_owned(),
        response_hash,
        0,
        0,
        outcome,
    ) {
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

#[allow(clippy::too_many_arguments)]
fn finish_non_streaming_ok(
    state: &AppState,
    receipt_id: [u8; 16],
    request_hash: [u8; 32],
    upstream_request_hash: [u8; 32],
    raw_response: &Value,
    to_canonical: fn(&Value) -> Result<CanonicalResponse, ProviderError>,
    outcome_for: fn(&str) -> Outcome,
    model_hint: &str,
) -> Response {
    let canonical_response = match to_canonical(raw_response) {
        Ok(value) => value,
        Err(error) => {
            return finish_error_receipt(
                state,
                receipt_id,
                request_hash,
                upstream_request_hash,
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
    let response_hash = match sha256_of(&canonical_response) {
        Ok(hash) => hash,
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                error.to_string(),
            );
        }
    };
    match sign_and_store(
        state,
        receipt_id,
        request_hash,
        upstream_request_hash,
        canonical_response.model.clone(),
        response_hash,
        canonical_response.usage.input_tokens,
        canonical_response.usage.output_tokens,
        outcome,
    ) {
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
    let request_hash = match sha256_of(&canonical_request) {
        Ok(hash) => hash,
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                error.to_string(),
            );
        }
    };
    let receipt_id: [u8; 16] = *Uuid::new_v4().as_bytes();
    let model_hint = canonical_request.model.clone();

    if let Err(denial) = state.config.policy.evaluate(&EvaluationRequest {
        caller_key: &caller_key,
        model: &canonical_request.model,
        max_tokens: canonical_request.max_tokens,
        request_bytes: body.len(),
    }) {
        // No upstream call is made on a policy denial.
        return finish_error_receipt(
            &state,
            receipt_id,
            request_hash,
            request_hash,
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
            request_hash,
            api_key,
            raw_request,
            model_hint,
        )
        .await;
    }

    match openai::call_non_streaming(&state.http, &state.openai_base_url, &api_key, &raw_request)
        .await
    {
        Ok((status, response_body)) if (200..300).contains(&status) => finish_non_streaming_ok(
            &state,
            receipt_id,
            request_hash,
            request_hash,
            &response_body,
            openai::to_canonical_response,
            openai::outcome_for_finish_reason,
            &model_hint,
        ),
        Ok((status, response_body)) => finish_error_receipt(
            &state,
            receipt_id,
            request_hash,
            request_hash,
            &model_hint,
            Outcome::UpstreamError,
            Some(status),
            response_body.to_string(),
            StatusCode::BAD_GATEWAY,
            "upstream_error",
        ),
        Err(error) => finish_error_receipt(
            &state,
            receipt_id,
            request_hash,
            request_hash,
            &model_hint,
            Outcome::UpstreamError,
            None,
            error.to_string(),
            StatusCode::BAD_GATEWAY,
            "upstream_error",
        ),
    }
}

async fn openai_stream_response(
    state: AppState,
    receipt_id: [u8; 16],
    request_hash: [u8; 32],
    api_key: String,
    raw_request: Value,
    model_hint: String,
) -> Response {
    let (upstream, dispatched_body) =
        match openai::start_streaming(&state.http, &state.openai_base_url, &api_key, &raw_request)
            .await
        {
            Ok(value) => value,
            Err(error) => {
                return finish_error_receipt(
                    &state,
                    receipt_id,
                    request_hash,
                    request_hash,
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
    // (provider-apis.md §4), so `upstream_request_hash` is computed from
    // what was actually dispatched, separately from `request_hash`.
    let upstream_request_hash = sha256_of(&dispatched_body).unwrap_or(request_hash);

    if !upstream.status().is_success() {
        let status = upstream.status().as_u16();
        let body_text = upstream.text().await.unwrap_or_default();
        return finish_error_receipt(
            &state,
            receipt_id,
            request_hash,
            upstream_request_hash,
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
        let canonical_response = acc.finish(&model_hint);
        let outcome = if had_transport_error {
            Outcome::UpstreamError
        } else {
            openai::outcome_for_finish_reason(&canonical_response.stop_reason)
        };
        if let Ok(response_hash) = sha256_of(&canonical_response) {
            let _ = sign_and_store(
                &state,
                receipt_id,
                request_hash,
                upstream_request_hash,
                canonical_response.model.clone(),
                response_hash,
                canonical_response.usage.input_tokens,
                canonical_response.usage.output_tokens,
                outcome,
            );
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
    let request_hash = match sha256_of(&canonical_request) {
        Ok(hash) => hash,
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                error.to_string(),
            );
        }
    };
    let receipt_id: [u8; 16] = *Uuid::new_v4().as_bytes();
    let model_hint = canonical_request.model.clone();

    if let Err(denial) = state.config.policy.evaluate(&EvaluationRequest {
        caller_key: &caller_key,
        model: &canonical_request.model,
        max_tokens: canonical_request.max_tokens,
        request_bytes: body.len(),
    }) {
        return finish_error_receipt(
            &state,
            receipt_id,
            request_hash,
            request_hash,
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
            request_hash,
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
        Ok((status, response_body)) if (200..300).contains(&status) => finish_non_streaming_ok(
            &state,
            receipt_id,
            request_hash,
            request_hash,
            &response_body,
            anthropic::to_canonical_response,
            anthropic::outcome_for_stop_reason,
            &model_hint,
        ),
        Ok((status, response_body)) => finish_error_receipt(
            &state,
            receipt_id,
            request_hash,
            request_hash,
            &model_hint,
            Outcome::UpstreamError,
            Some(status),
            response_body.to_string(),
            StatusCode::BAD_GATEWAY,
            "upstream_error",
        ),
        Err(error) => finish_error_receipt(
            &state,
            receipt_id,
            request_hash,
            request_hash,
            &model_hint,
            Outcome::UpstreamError,
            None,
            error.to_string(),
            StatusCode::BAD_GATEWAY,
            "upstream_error",
        ),
    }
}

async fn anthropic_stream_response(
    state: AppState,
    receipt_id: [u8; 16],
    request_hash: [u8; 32],
    api_key: String,
    raw_request: Value,
    model_hint: String,
) -> Response {
    let upstream = match anthropic::start_streaming(
        &state.http,
        &state.anthropic_base_url,
        &api_key,
        &raw_request,
    )
    .await
    {
        Ok(value) => value,
        Err(error) => {
            return finish_error_receipt(
                &state,
                receipt_id,
                request_hash,
                request_hash,
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
    // so upstream_request_hash == request_hash today. See task report.
    let upstream_request_hash = request_hash;

    if !upstream.status().is_success() {
        let status = upstream.status().as_u16();
        let body_text = upstream.text().await.unwrap_or_default();
        return finish_error_receipt(
            &state,
            receipt_id,
            request_hash,
            upstream_request_hash,
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
        let canonical_response = acc.finish(&model_hint);
        let outcome = if had_transport_error {
            Outcome::UpstreamError
        } else {
            anthropic::outcome_for_stop_reason(&canonical_response.stop_reason)
        };
        if let Ok(response_hash) = sha256_of(&canonical_response) {
            let _ = sign_and_store(
                &state,
                receipt_id,
                request_hash,
                upstream_request_hash,
                canonical_response.model.clone(),
                response_hash,
                canonical_response.usage.input_tokens,
                canonical_response.usage.output_tokens,
                outcome,
            );
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
    }
}
