import { describe, expect, test } from 'bun:test'
import { toHex } from '@mysten/sui/utils'
import { ed25519 } from '@noble/curves/ed25519.js'
import {
  canonicalJson,
  hashRequest,
  hashResponse,
  type Receipt,
  ReceiptOutcome,
  serializeReceipt,
  verifyReceipt,
} from '../src/receipt'

// ─── docs/receipt-vectors.json parity ───────────────────────────────────────
//
// Loaded directly from disk (not copy-pasted) so this test always checks the
// SDK against the same file Move/Rust are contract-tested against, and stays
// in sync automatically if the vectors ever change.

const VECTORS_PATH = new URL('../../docs/receipt-vectors.json', import.meta.url)

type Vector = {
  name: string
  fields: {
    intent: number
    timestamp_ms: string
    receipt_id: string
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
  }
  byte_length: number
  expected_bcs_hex: string
}

async function loadVectors(): Promise<Vector[]> {
  const file = Bun.file(VECTORS_PATH)
  const json = (await file.json()) as { vectors: Vector[] }
  return json.vectors
}

function toReceipt(fields: Vector['fields']): Receipt {
  return {
    receiptId: fields.receipt_id,
    configHash: fields.config_hash,
    provider: fields.provider,
    endpointHost: fields.endpoint_host,
    tlsCertSha256: fields.tls_cert_sha256,
    requestBlob: BigInt(fields.request_blob),
    upstreamRequestBlob: BigInt(fields.upstream_request_blob),
    upstreamHeadersHash: fields.upstream_headers_hash,
    modelId: fields.model_id,
    providerRequestId: fields.provider_request_id,
    responseBlob: BigInt(fields.response_blob),
    providerMetaHash: fields.provider_meta_hash,
    inputTokens: BigInt(fields.input_tokens),
    cacheCreationTokens: BigInt(fields.cache_creation_tokens),
    cacheReadTokens: BigInt(fields.cache_read_tokens),
    outputTokens: BigInt(fields.output_tokens),
    outcome: fields.outcome as ReceiptOutcome,
  }
}

describe('serializeReceipt — docs/receipt-vectors.json parity', () => {
  test('reproduces both vectors byte-for-byte', async () => {
    const vectors = await loadVectors()
    expect(vectors.length).toBeGreaterThanOrEqual(2)

    for (const vector of vectors) {
      const receipt = toReceipt(vector.fields)
      const bytes = serializeReceipt(receipt, BigInt(vector.fields.timestamp_ms))

      expect(bytes.length).toBe(vector.byte_length)
      expect(toHex(bytes)).toBe(vector.expected_bcs_hex)
    }
  })

  test('nominal-anthropic-success vector (361 bytes)', async () => {
    const vectors = await loadVectors()
    const vector = vectors.find((v) => v.name === 'nominal-anthropic-success')
    expect(vector).toBeDefined()
    expect(vector!.byte_length).toBe(361)
    const receipt = toReceipt(vector!.fields)
    const bytes = serializeReceipt(receipt, BigInt(vector!.fields.timestamp_ms))
    expect(bytes.length).toBe(361)
    expect(toHex(bytes)).toBe(vector!.expected_bcs_hex)
  })

  test('refusal-unarchived-max-tokens vector (506 bytes, u64::MAX tokens, unarchived u256 blobs)', async () => {
    const vectors = await loadVectors()
    const vector = vectors.find((v) => v.name === 'refusal-unarchived-max-tokens')
    expect(vector).toBeDefined()
    expect(vector!.byte_length).toBe(506)
    const receipt = toReceipt(vector!.fields)
    expect(receipt.inputTokens).toBe(18446744073709551615n)
    expect(receipt.cacheCreationTokens).toBe(18446744073709551615n)
    expect(receipt.requestBlob).toBe(0n)
    expect(receipt.upstreamRequestBlob).toBe(0n)
    expect(receipt.responseBlob).toBe(0n)
    const bytes = serializeReceipt(receipt, BigInt(vector!.fields.timestamp_ms))
    expect(bytes.length).toBe(506)
    expect(toHex(bytes)).toBe(vector!.expected_bcs_hex)
  })
})

// ─── verifyReceipt — Ed25519 round trip ──────────────────────────────────────

describe('verifyReceipt', () => {
  const receipt: Receipt = {
    receiptId: '000102030405060708090a0b0c0d0e0f',
    configHash: 'aa'.repeat(32),
    provider: 0,
    endpointHost: 'api.anthropic.com',
    tlsCertSha256: 'bb'.repeat(32),
    requestBlob: 12345n,
    upstreamRequestBlob: 67890n,
    upstreamHeadersHash: 'cc'.repeat(32),
    modelId: 'claude-sonnet-5',
    providerRequestId: 'msg_011Ce3rq3tLXgrQNPLAYKda8',
    responseBlob: 24680n,
    providerMetaHash: 'dd'.repeat(32),
    inputTokens: 1000n,
    cacheCreationTokens: 0n,
    cacheReadTokens: 0n,
    outputTokens: 250n,
    outcome: ReceiptOutcome.Ok,
  }
  const timestampMs = 1234567890123n

  test('accepts a signature produced by the matching key', () => {
    const { secretKey, publicKey } = ed25519.keygen()
    const message = serializeReceipt(receipt, timestampMs)
    const signature = ed25519.sign(message, secretKey)

    const ok = verifyReceipt(receipt, timestampMs, toHex(signature), publicKey)
    expect(ok).toBe(true)
  })

  test('accepts a hex-encoded public key', () => {
    const { secretKey, publicKey } = ed25519.keygen()
    const message = serializeReceipt(receipt, timestampMs)
    const signature = ed25519.sign(message, secretKey)

    const ok = verifyReceipt(receipt, timestampMs, toHex(signature), toHex(publicKey))
    expect(ok).toBe(true)
  })

  test('rejects a signature from a different key', () => {
    const { secretKey: signingKey } = ed25519.keygen()
    const { publicKey: otherPublicKey } = ed25519.keygen()
    const message = serializeReceipt(receipt, timestampMs)
    const signature = ed25519.sign(message, signingKey)

    const ok = verifyReceipt(receipt, timestampMs, toHex(signature), otherPublicKey)
    expect(ok).toBe(false)
  })

  test('rejects a tampered receipt field', () => {
    const { secretKey, publicKey } = ed25519.keygen()
    const message = serializeReceipt(receipt, timestampMs)
    const signature = ed25519.sign(message, secretKey)

    const tampered: Receipt = { ...receipt, outputTokens: 999n }
    const ok = verifyReceipt(tampered, timestampMs, toHex(signature), publicKey)
    expect(ok).toBe(false)
  })

  test('rejects a tampered u256 blob field', () => {
    const { secretKey, publicKey } = ed25519.keygen()
    const message = serializeReceipt(receipt, timestampMs)
    const signature = ed25519.sign(message, secretKey)

    const tampered: Receipt = { ...receipt, requestBlob: receipt.requestBlob + 1n }
    const ok = verifyReceipt(tampered, timestampMs, toHex(signature), publicKey)
    expect(ok).toBe(false)
  })

  test('rejects a tampered timestamp (domain-separated by the envelope)', () => {
    const { secretKey, publicKey } = ed25519.keygen()
    const message = serializeReceipt(receipt, timestampMs)
    const signature = ed25519.sign(message, secretKey)

    const ok = verifyReceipt(receipt, timestampMs + 1n, toHex(signature), publicKey)
    expect(ok).toBe(false)
  })
})

// ─── canonicalJson / hashRequest / hashResponse ─────────────────────────────

describe('canonicalJson', () => {
  test('sorts object keys recursively', () => {
    const a = canonicalJson({ b: 1, a: { d: 2, c: 3 } })
    const b = canonicalJson({ a: { c: 3, d: 2 }, b: 1 })
    expect(a).toBe(b)
    expect(a).toBe('{"a":{"c":3,"d":2},"b":1}')
  })

  test('preserves array order (arrays are not sorted)', () => {
    expect(canonicalJson([3, 1, 2])).toBe('[3,1,2]')
  })
})

describe('hashRequest / hashResponse', () => {
  test('hashRequest is stable under key reordering', async () => {
    const h1 = await hashRequest({ model: 'x', messages: [{ role: 'user', content: 'hi' }] })
    const h2 = await hashRequest({ messages: [{ content: 'hi', role: 'user' }], model: 'x' })
    expect(h1).toBe(h2)
    expect(h1).toMatch(/^[0-9a-f]{64}$/)
  })

  test('hashResponse is stable under key reordering', async () => {
    const h1 = await hashResponse({ id: '1', choices: [{ index: 0 }] })
    const h2 = await hashResponse({ choices: [{ index: 0 }], id: '1' })
    expect(h1).toBe(h2)
  })

  test('hashRequest changes when content changes', async () => {
    const h1 = await hashRequest({ a: 1 })
    const h2 = await hashRequest({ a: 2 })
    expect(h1).not.toBe(h2)
  })

  // Pins a documented limitation rather than a desirable property: JS cannot
  // tell 1 from 1.0, so canonical JSON here emits `1` where serde_json emits
  // `1.0`. This is one of the reasons hashing a raw request body cannot
  // reproduce any receipt hash field — clients must rely on verifyReceipt
  // instead (see hashJson's docs and docs/SPEC.md section 6a).
  test('canonicalJson cannot distinguish 1 from 1.0 (Rust emits 1.0)', () => {
    expect(canonicalJson({ temperature: 1.0 })).toBe('{"temperature":1}')
    expect(canonicalJson({ temperature: 1 })).toBe(canonicalJson({ temperature: 1.0 }))
  })

  test('hashRequest and hashResponse are independent SHA-256 (known test vector)', async () => {
    // SHA-256("null") == 74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b
    const h = await hashRequest(null)
    expect(h).toBe('74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b')
  })
})
