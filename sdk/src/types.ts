// ─── OpenAI-compatible chat completions (POST /v1/chat/completions) ────────────
//
// Deliberately minimal (not a full OpenAI type mirror): sekisho passes these
// through to the upstream provider mostly as-is, so the SDK models the
// envelope shape it needs to route/stream/hash, and leaves provider-specific
// fields as an open record via index signatures.

export type ChatMessage = {
  role: 'system' | 'user' | 'assistant' | 'tool'
  content: string | ChatContentPart[] | null
  name?: string
  tool_call_id?: string
  tool_calls?: unknown[]
  [key: string]: unknown
}

export type ChatContentPart = {
  type: string
  [key: string]: unknown
}

export type ChatCompletionRequest = {
  model: string
  messages: ChatMessage[]
  stream?: boolean
  max_tokens?: number
  temperature?: number
  [key: string]: unknown
}

export type ChatCompletionChoice = {
  index: number
  message?: ChatMessage
  delta?: Partial<ChatMessage>
  finish_reason?: string | null
  [key: string]: unknown
}

export type ChatCompletionUsage = {
  prompt_tokens: number
  completion_tokens: number
  total_tokens: number
  [key: string]: unknown
}

export type ChatCompletionResponse = {
  id: string
  object: string
  created: number
  model: string
  choices: ChatCompletionChoice[]
  usage?: ChatCompletionUsage
  [key: string]: unknown
}

/** A single SSE-delivered chunk from a streaming `/v1/chat/completions` call. */
export type ChatCompletionChunk = {
  id: string
  object: string
  created: number
  model: string
  choices: ChatCompletionChoice[]
  usage?: ChatCompletionUsage
  [key: string]: unknown
}

// ─── Anthropic-native messages passthrough (POST /v1/messages) ─────────────────

export type MessagesContentBlock = {
  type: string
  [key: string]: unknown
}

export type MessagesMessage = {
  role: 'user' | 'assistant'
  content: string | MessagesContentBlock[]
  [key: string]: unknown
}

export type MessagesRequest = {
  model: string
  messages: MessagesMessage[]
  max_tokens: number
  stream?: boolean
  system?: string | MessagesContentBlock[]
  [key: string]: unknown
}

export type MessagesUsage = {
  input_tokens: number
  output_tokens: number
  [key: string]: unknown
}

export type MessagesResponse = {
  id: string
  type: 'message'
  role: 'assistant'
  model: string
  content: MessagesContentBlock[]
  stop_reason?: string | null
  usage?: MessagesUsage
  [key: string]: unknown
}

/** A single SSE-delivered event from a streaming `/v1/messages` call. */
export type MessagesStreamEvent = {
  type: string
  [key: string]: unknown
}

// ─── Gateway response envelope ──────────────────────────────────────────────

/**
 * Every gateway call surfaces the `x-receipt-id` response header alongside the
 * parsed body, so callers can immediately look up (or later verify) the
 * receipt for that exchange.
 */
export type SekishoResponse<T> = {
  data: T
  receiptId: string | null
}

// ─── Receipts endpoint (GET /receipts/:id) ──────────────────────────────────

/**
 * JSON wire shape returned by `GET /receipts/:id`, mirroring `Receipt`
 * (SPEC.md section 3) field-for-field. Byte fields are hex strings; `*_blob`
 * fields are `u256` Walrus blob ids as decimal strings; `timestamp_ms` and
 * `*_tokens` fields are `u64` as decimal strings (never JSON numbers — they
 * can exceed `Number.MAX_SAFE_INTEGER`).
 */
export type ReceiptRecord = {
  receipt_id: string
  timestamp_ms: string
  config_hash: string
  provider: number
  endpoint_host: string
  tls_cert_sha256: string
  request_blob: string
  upstream_request_blob: string
  upstream_headers_hash: string
  model_id: string
  provider_request_id: string
  response_blob: string
  provider_meta_hash: string
  input_tokens: string
  cache_creation_tokens: string
  cache_read_tokens: string
  output_tokens: string
  outcome: number
  /** Ed25519 signature over the BCS-encoded `IntentMessage<Receipt>`, hex-encoded. */
  signature: string
  [key: string]: unknown
}

// ─── Attestation endpoint (GET /attestation) ────────────────────────────────

export type AttestationResponse = {
  /** Base64-encoded CBOR/COSE_Sign1 Nitro attestation document. */
  document: string
  /** Ed25519 public key extracted from the attestation document, hex-encoded. */
  public_key?: string
  [key: string]: unknown
}

// ─── Error envelope ──────────────────────────────────────────────────────────

export type SekishoErrorResponse = {
  error: string
  [key: string]: unknown
}
