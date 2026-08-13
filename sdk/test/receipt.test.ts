import { describe, expect, test } from 'bun:test'
import { toHex } from '@mysten/sui/utils'
import { ed25519 } from '@noble/curves/ed25519.js'
import {
  canonicalJson,
  hashRequest,
  hashResponse,
  ReceiptOutcome,
  serializeReceiptV1,
  verifyReceipt,
  type ReceiptV1,
} from '../src/receipt'

// ─── docs/receipt-v1-vectors.json parity ────────────────────────────────────
//
// Loaded directly from disk (not copy-pasted) so this test always checks the
// SDK against the same file Move/Rust are contract-tested against.

const VECTORS_PATH = new URL('../../docs/receipt-v1-vectors.json', import.meta.url)

type Vector = {
  name: string
  fields: {
    intent: number
    timestamp_ms: string
    receipt_id: string
    config_hash: string
    request_hash: string
    upstream_request_hash: string
    model_id: string
    response_hash: string
    input_tokens: string
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

function toReceipt(fields: Vector['fields']): ReceiptV1 {
  return {
    receiptId: fields.receipt_id,
    configHash: fields.config_hash,
    requestHash: fields.request_hash,
    upstreamRequestHash: fields.upstream_request_hash,
    modelId: fields.model_id,
    responseHash: fields.response_hash,
    inputTokens: BigInt(fields.input_tokens),
    outputTokens: BigInt(fields.output_tokens),
    outcome: fields.outcome as ReceiptOutcome,
  }
}

describe('serializeReceiptV1 — docs/receipt-v1-vectors.json parity', () => {
  test('reproduces both vectors byte-for-byte', async () => {
    const vectors = await loadVectors()
    expect(vectors.length).toBeGreaterThanOrEqual(2)

    for (const vector of vectors) {
      const receipt = toReceipt(vector.fields)
      const bytes = serializeReceiptV1(receipt, BigInt(vector.fields.timestamp_ms))

      expect(bytes.length).toBe(vector.byte_length)
      expect(toHex(bytes)).toBe(vector.expected_bcs_hex)
    }
  })

  test('nominal-success vector', async () => {
    const vectors = await loadVectors()
    const vector = vectors.find((v) => v.name === 'nominal-success')
    expect(vector).toBeDefined()
    const receipt = toReceipt(vector!.fields)
    const bytes = serializeReceiptV1(receipt, BigInt(vector!.fields.timestamp_ms))
    expect(toHex(bytes)).toBe(vector!.expected_bcs_hex)
  })

  test('refusal-long-model-max-tokens vector (u64::MAX input_tokens, 2-byte ULEB model_id)', async () => {
    const vectors = await loadVectors()
    const vector = vectors.find((v) => v.name === 'refusal-long-model-max-tokens')
    expect(vector).toBeDefined()
    const receipt = toReceipt(vector!.fields)
    expect(receipt.inputTokens).toBe(18446744073709551615n)
    const bytes = serializeReceiptV1(receipt, BigInt(vector!.fields.timestamp_ms))
    expect(toHex(bytes)).toBe(vector!.expected_bcs_hex)
  })
})

// ─── verifyReceipt — Ed25519 round trip ──────────────────────────────────────

describe('verifyReceipt', () => {
  const receipt: ReceiptV1 = {
    receiptId: '000102030405060708090a0b0c0d0e0f',
    configHash: 'aa'.repeat(32),
    requestHash: 'bb'.repeat(32),
    upstreamRequestHash: 'cc'.repeat(32),
    modelId: 'claude-sonnet-5',
    responseHash: 'dd'.repeat(32),
    inputTokens: 1000n,
    outputTokens: 250n,
    outcome: ReceiptOutcome.Ok,
  }
  const timestampMs = 1234567890123n

  test('accepts a signature produced by the matching key', () => {
    const { secretKey, publicKey } = ed25519.keygen()
    const message = serializeReceiptV1(receipt, timestampMs)
    const signature = ed25519.sign(message, secretKey)

    const ok = verifyReceipt(receipt, timestampMs, toHex(signature), publicKey)
    expect(ok).toBe(true)
  })

  test('accepts a hex-encoded public key', () => {
    const { secretKey, publicKey } = ed25519.keygen()
    const message = serializeReceiptV1(receipt, timestampMs)
    const signature = ed25519.sign(message, secretKey)

    const ok = verifyReceipt(receipt, timestampMs, toHex(signature), toHex(publicKey))
    expect(ok).toBe(true)
  })

  test('rejects a signature from a different key', () => {
    const { secretKey: signingKey } = ed25519.keygen()
    const { publicKey: otherPublicKey } = ed25519.keygen()
    const message = serializeReceiptV1(receipt, timestampMs)
    const signature = ed25519.sign(message, signingKey)

    const ok = verifyReceipt(receipt, timestampMs, toHex(signature), otherPublicKey)
    expect(ok).toBe(false)
  })

  test('rejects a tampered receipt field', () => {
    const { secretKey, publicKey } = ed25519.keygen()
    const message = serializeReceiptV1(receipt, timestampMs)
    const signature = ed25519.sign(message, secretKey)

    const tampered: ReceiptV1 = { ...receipt, outputTokens: 999n }
    const ok = verifyReceipt(tampered, timestampMs, toHex(signature), publicKey)
    expect(ok).toBe(false)
  })

  test('rejects a tampered timestamp (domain-separated by the envelope)', () => {
    const { secretKey, publicKey } = ed25519.keygen()
    const message = serializeReceiptV1(receipt, timestampMs)
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

  test('hashRequest and hashResponse are independent SHA-256 (known test vector)', async () => {
    // SHA-256("null") == 74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b
    const h = await hashRequest(null)
    expect(h).toBe('74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b')
  })
})
