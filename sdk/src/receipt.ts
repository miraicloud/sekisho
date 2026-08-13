import { bcs } from '@mysten/sui/bcs'
import { fromHex, toHex } from '@mysten/sui/utils'
import { ed25519 } from '@noble/curves/ed25519.js'

/** `sekisho::receipt::RECEIPT_INTENT_V1` — the domain-separation byte for `ReceiptV1`. */
export const RECEIPT_INTENT_V1 = 0

/** `sekisho::receipt::ReceiptV1.outcome` values (SPEC.md section 3). */
export const ReceiptOutcome = {
  Ok: 0,
  Refusal: 1,
  UpstreamError: 2,
  PolicyDenied: 3,
} as const

export type ReceiptOutcome = (typeof ReceiptOutcome)[keyof typeof ReceiptOutcome]

/**
 * `sekisho::receipt::ReceiptV1` payload (SPEC.md section 3). Byte fields are
 * hex strings; token counts are `bigint` because they are provider-reported
 * `u64`s that can exceed `Number.MAX_SAFE_INTEGER` (JSON numbers cannot
 * round-trip `u64` in IEEE-754 parsers such as JavaScript's — the same
 * reason the wire format in {@link ReceiptRecord} uses decimal strings).
 */
export type ReceiptV1 = {
  /** 16-byte UUID assigned by the enclave, hex-encoded. */
  receiptId: string
  /** 32-byte SHA-256 of the active policy/config JSON, hex-encoded. */
  configHash: string
  /** 32-byte SHA-256 of the canonicalized client request, hex-encoded. */
  requestHash: string
  /** 32-byte SHA-256 of what was actually sent upstream, hex-encoded. */
  upstreamRequestHash: string
  /** Provider-reported served model, read back off the response. */
  modelId: string
  /** 32-byte SHA-256 of the canonicalized assembled response, hex-encoded. */
  responseHash: string
  inputTokens: bigint
  outputTokens: bigint
  outcome: ReceiptOutcome
}

/**
 * BCS schema for `IntentMessage<ReceiptV1>` (SPEC.md section 3 + envelope).
 * BCS structs are a flat concatenation of their fields with no per-struct
 * framing, so a single flattened struct — `intent`/`timestamp_ms` followed by
 * the `ReceiptV1` fields in spec order — is byte-identical to the nested
 * `IntentMessage<ReceiptV1>{ intent, timestamp_ms, payload: ReceiptV1 }` the
 * Move/Rust sides construct. Verified byte-for-byte against both vectors in
 * `docs/receipt-v1-vectors.json` (see `test/receipt.test.ts`).
 */
const IntentMessageReceiptV1 = bcs.struct('IntentMessageReceiptV1', {
  intent: bcs.u8(),
  timestampMs: bcs.u64(),
  receiptId: bcs.byteVector(),
  configHash: bcs.byteVector(),
  requestHash: bcs.byteVector(),
  upstreamRequestHash: bcs.byteVector(),
  modelId: bcs.string(),
  responseHash: bcs.byteVector(),
  inputTokens: bcs.u64(),
  outputTokens: bcs.u64(),
  outcome: bcs.u8(),
})

/**
 * BCS-serialize `IntentMessage<ReceiptV1>`: `intent(u8) || timestamp_ms(u64 LE)
 * || ReceiptV1 fields in spec order`, with ULEB128 length prefixes on the
 * `vector<u8>`/`String` fields — exactly what the enclave signs and
 * `sekisho::receipt::verify` re-derives and checks on-chain.
 */
export function serializeReceiptV1(receipt: ReceiptV1, timestampMs: bigint | number): Uint8Array {
  return IntentMessageReceiptV1.serialize({
    intent: RECEIPT_INTENT_V1,
    timestampMs,
    receiptId: fromHex(receipt.receiptId),
    configHash: fromHex(receipt.configHash),
    requestHash: fromHex(receipt.requestHash),
    upstreamRequestHash: fromHex(receipt.upstreamRequestHash),
    modelId: receipt.modelId,
    responseHash: fromHex(receipt.responseHash),
    inputTokens: receipt.inputTokens,
    outputTokens: receipt.outputTokens,
    outcome: receipt.outcome,
  }).toBytes()
}

/**
 * Verify an enclave-signed `ReceiptV1` against a registered `Gateway` public
 * key. Recomputes the BCS `IntentMessage<ReceiptV1>` bytes and checks the
 * Ed25519 signature — the same check `sekisho::receipt::verify` performs
 * on-chain via `sui::ed25519`, done client-side so callers can validate a
 * receipt before ever submitting a transaction.
 *
 * @param receipt ReceiptV1 payload as returned by the gateway.
 * @param timestampMs Envelope timestamp (`IntentMessage.timestamp_ms`), matching what was signed.
 * @param signatureHex Ed25519 signature over the BCS message, hex-encoded.
 * @param enclavePubkey The `Gateway.pk` bytes (or hex string) registered on-chain for this enclave.
 */
export function verifyReceipt(
  receipt: ReceiptV1,
  timestampMs: bigint | number,
  signatureHex: string,
  enclavePubkey: Uint8Array | string,
): boolean {
  const message = serializeReceiptV1(receipt, timestampMs)
  const signature = fromHex(signatureHex)
  const publicKey = typeof enclavePubkey === 'string' ? fromHex(enclavePubkey) : enclavePubkey
  return ed25519.verify(signature, message, publicKey)
}

// ─── Canonical hashing (mirrors the enclave's request/response hashing) ────────

/**
 * Recursively sort object keys so `JSON.stringify` produces a canonical
 * encoding independent of key insertion order — mirrors the enclave's
 * canonical-JSON hashing so clients can independently recompute
 * `request_hash`/`response_hash`/`config_hash`.
 */
function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(canonicalize)
  }
  if (value !== null && typeof value === 'object') {
    const sorted: Record<string, unknown> = {}
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      sorted[key] = canonicalize((value as Record<string, unknown>)[key])
    }
    return sorted
  }
  return value
}

/** Canonical (sorted-key) JSON encoding of `value`. */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalize(value))
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  // Cast needed because TS's typed-array generics (`Uint8Array<ArrayBufferLike>`
  // vs. WebCrypto's `BufferSource` expecting `Uint8Array<ArrayBuffer>`) don't
  // line up across lib versions; `bytes` is always a plain heap-backed
  // Uint8Array at runtime (never a SharedArrayBuffer view), so this is safe.
  const digest = await crypto.subtle.digest('SHA-256', bytes as unknown as ArrayBuffer)
  return toHex(new Uint8Array(digest))
}

/**
 * SHA-256 of the canonicalized (sorted-key) JSON encoding of a request body —
 * mirrors the enclave's `request_hash`/`upstream_request_hash` computation so
 * a client can independently verify what was hashed into a `ReceiptV1`.
 */
export async function hashRequest(request: unknown): Promise<string> {
  return sha256Hex(new TextEncoder().encode(canonicalJson(request)))
}

/**
 * SHA-256 of the canonicalized (sorted-key) JSON encoding of an assembled
 * response body — mirrors the enclave's `response_hash` computation. For
 * streamed responses, pass the fully-accumulated response structure (never
 * raw SSE bytes), matching SPEC.md section 3.
 */
export async function hashResponse(response: unknown): Promise<string> {
  return sha256Hex(new TextEncoder().encode(canonicalJson(response)))
}
