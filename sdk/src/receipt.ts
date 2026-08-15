import { bcs } from '@mysten/sui/bcs'
import { fromHex, toHex } from '@mysten/sui/utils'
import { ed25519 } from '@noble/curves/ed25519.js'

/** `sekisho::receipt::RECEIPT_INTENT` — the domain-separation byte for `Receipt`. */
export const RECEIPT_INTENT = 0

/** `sekisho::receipt::Receipt.outcome` values (SPEC.md section 3). */
export const ReceiptOutcome = {
  Ok: 0,
  Refusal: 1,
  UpstreamError: 2,
  PolicyDenied: 3,
} as const

export type ReceiptOutcome = (typeof ReceiptOutcome)[keyof typeof ReceiptOutcome]

/**
 * `sekisho::receipt::Receipt` payload (SPEC.md section 3 — field order there is
 * normative and matched exactly below). Byte fields are hex strings. Token
 * counts and the `*Blob` fields are `bigint`: token counts are provider-reported
 * `u64`s and the blob fields are `u256` Walrus blob ids, both of which can
 * exceed `Number.MAX_SAFE_INTEGER` (JSON numbers cannot round-trip `u64`/`u256`
 * in IEEE-754 parsers such as JavaScript's — the same reason the wire format in
 * {@link ReceiptRecord} uses decimal strings).
 */
export type Receipt = {
  /** 16-byte UUID assigned by the enclave, hex-encoded. */
  receiptId: string
  /** 32-byte SHA-256 of the canonical policy JSON (policy only, never secrets), hex-encoded. */
  configHash: string
  /** 0 = anthropic, 1 = openai-compatible. */
  provider: number
  /** TLS hostname actually validated during the upstream handshake. */
  endpointHost: string
  /** 32-byte SHA-256 of the upstream server's leaf certificate (DER), hex-encoded. */
  tlsCertSha256: string
  /** `u256` Walrus blob id of the canonical client request (`0` = computed but not archived). */
  requestBlob: bigint
  /** `u256` Walrus blob id of the canonical upstream request (captures gateway transforms). */
  upstreamRequestBlob: bigint
  /** 32-byte SHA-256 of canonical upstream request headers, hex-encoded. */
  upstreamHeadersHash: string
  /** Served model, read off the response — never the request. */
  modelId: string
  /** Provider's own request id (Anthropic `id` / `request-id`); empty when absent. */
  providerRequestId: string
  /** `u256` Walrus blob id of the canonical assembled response. */
  responseBlob: bigint
  /** 32-byte SHA-256 of a canonical provider-specific metadata blob, hex-encoded. */
  providerMetaHash: string
  inputTokens: bigint
  cacheCreationTokens: bigint
  cacheReadTokens: bigint
  outputTokens: bigint
  outcome: ReceiptOutcome
}

/**
 * BCS schema for `IntentMessage<Receipt>` (SPEC.md section 3 + envelope). BCS
 * structs are a flat concatenation of their fields with no per-struct framing,
 * so a single flattened struct — `intent`/`timestamp_ms` followed by the
 * `Receipt` fields in spec order — is byte-identical to the nested
 * `IntentMessage<Receipt>{ intent, timestamp_ms, payload: Receipt }` the
 * Move/Rust sides construct. Verified byte-for-byte against both vectors in
 * `docs/receipt-vectors.json` (see `test/receipt.test.ts`), and matches the
 * schema shape independently cross-checked in `scripts/verify_vectors.ts`.
 */
const IntentMessageReceipt = bcs.struct('IntentMessageReceipt', {
  intent: bcs.u8(),
  timestampMs: bcs.u64(),
  receiptId: bcs.byteVector(),
  configHash: bcs.byteVector(),
  provider: bcs.u8(),
  endpointHost: bcs.string(),
  tlsCertSha256: bcs.byteVector(),
  requestBlob: bcs.u256(),
  upstreamRequestBlob: bcs.u256(),
  upstreamHeadersHash: bcs.byteVector(),
  modelId: bcs.string(),
  providerRequestId: bcs.string(),
  responseBlob: bcs.u256(),
  providerMetaHash: bcs.byteVector(),
  inputTokens: bcs.u64(),
  cacheCreationTokens: bcs.u64(),
  cacheReadTokens: bcs.u64(),
  outputTokens: bcs.u64(),
  outcome: bcs.u8(),
})

/**
 * BCS-serialize `IntentMessage<Receipt>`: `intent(u8) || timestamp_ms(u64 LE)
 * || Receipt fields in spec order`, with ULEB128 length prefixes on the
 * `vector<u8>`/`String` fields — exactly what the enclave signs and
 * `sekisho::receipt::verify` re-derives and checks on-chain.
 */
export function serializeReceipt(receipt: Receipt, timestampMs: bigint | number): Uint8Array {
  return IntentMessageReceipt.serialize({
    intent: RECEIPT_INTENT,
    timestampMs,
    receiptId: fromHex(receipt.receiptId),
    configHash: fromHex(receipt.configHash),
    provider: receipt.provider,
    endpointHost: receipt.endpointHost,
    tlsCertSha256: fromHex(receipt.tlsCertSha256),
    requestBlob: receipt.requestBlob,
    upstreamRequestBlob: receipt.upstreamRequestBlob,
    upstreamHeadersHash: fromHex(receipt.upstreamHeadersHash),
    modelId: receipt.modelId,
    providerRequestId: receipt.providerRequestId,
    responseBlob: receipt.responseBlob,
    providerMetaHash: fromHex(receipt.providerMetaHash),
    inputTokens: receipt.inputTokens,
    cacheCreationTokens: receipt.cacheCreationTokens,
    cacheReadTokens: receipt.cacheReadTokens,
    outputTokens: receipt.outputTokens,
    outcome: receipt.outcome,
  }).toBytes()
}

/**
 * Verify an enclave-signed `Receipt` against a registered `Gateway` public
 * key. Recomputes the BCS `IntentMessage<Receipt>` bytes and checks the
 * Ed25519 signature — the same check `sekisho::receipt::verify` performs
 * on-chain via `sui::ed25519`, done client-side so callers can validate a
 * receipt before ever submitting a transaction.
 *
 * @param receipt Receipt payload as returned by the gateway.
 * @param timestampMs Envelope timestamp (`IntentMessage.timestamp_ms`), matching what was signed.
 * @param signatureHex Ed25519 signature over the BCS message, hex-encoded.
 * @param enclavePubkey The `Gateway.pk` bytes (or hex string) registered on-chain for this enclave.
 */
export function verifyReceipt(
  receipt: Receipt,
  timestampMs: bigint | number,
  signatureHex: string,
  enclavePubkey: Uint8Array | string,
): boolean {
  const message = serializeReceipt(receipt, timestampMs)
  const signature = fromHex(signatureHex)
  const publicKey = typeof enclavePubkey === 'string' ? fromHex(enclavePubkey) : enclavePubkey
  return ed25519.verify(signature, message, publicKey)
}

// ─── Canonical hashing (mirrors the enclave's request/response hashing) ────────

/**
 * Recursively sort object keys so `JSON.stringify` produces a canonical
 * encoding independent of key insertion order — mirrors the enclave's
 * canonical-JSON hashing so clients can independently recompute
 * hashes of their own content (see {@link hashJson}'s caveat about receipt hashes).
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
 * SHA-256 over the canonicalized (sorted-key) JSON encoding of a value.
 *
 * **This does NOT reproduce any of a receipt's hash fields** (e.g.
 * `configHash`, `upstreamHeadersHash`, `providerMetaHash`). The gateway hashes
 * its own normalized internal representation — messages flattened into
 * canonical blocks, unmodelled content replaced by digests, provider
 * transforms applied — not the JSON body you sent. Two further mismatches make
 * raw-body hashing unreliable in principle: JavaScript cannot distinguish
 * `1` from `1.0` (Rust emits `1.0`, `JSON.stringify` emits `1`), and JS sorts
 * keys by UTF-16 code unit while Rust sorts by UTF-8 byte, which differ for
 * astral-plane keys.
 *
 * What a client should rely on instead is `verifyReceipt`: the enclave's
 * signature covers every field of the receipt, so a valid signature proves the
 * gateway committed to those exact values. Recomputing hash fields locally is
 * not supported in v1 (see docs/SPEC.md §6a).
 *
 * The helper remains useful for hashing your own content — e.g. committing to
 * a prompt before sending it, or comparing two payloads.
 */
export async function hashJson(value: unknown): Promise<string> {
  return sha256Hex(new TextEncoder().encode(canonicalJson(value)))
}

/** @deprecated Misleading name — see {@link hashJson}. Does not reproduce any receipt hash field. */
export const hashRequest = hashJson

/** @deprecated Misleading name — see {@link hashJson}. Does not reproduce any receipt hash field. */
export const hashResponse = hashJson
