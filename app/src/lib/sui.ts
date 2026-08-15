import { bcs } from '@mysten/sui/bcs'
import { SuiGrpcClient } from '@mysten/sui/grpc'

/** Public testnet fullnode; serves gRPC with permissive CORS, so no backend is needed. */
export const DEFAULT_RPC = 'https://fullnode.testnet.sui.io'

/**
 * `sekisho::receipt::ReceiptVerified`. Decoded from the event's canonical BCS
 * rather than a node's pre-parsed JSON — the bytes are what the chain actually
 * stored, and decoding them here means this viewer never depends on a
 * particular node's JSON rendering.
 */
const ReceiptVerified = bcs.struct('ReceiptVerified', {
  gateway: bcs.Address,
  operator: bcs.Address,
  verifier: bcs.Address,
  pcr_version: bcs.u64(),
  receipt_id: bcs.byteVector(),
  config_hash: bcs.byteVector(),
  provider: bcs.u8(),
  endpoint_host: bcs.string(),
  tls_cert_sha256: bcs.byteVector(),
  request_blob: bcs.u256(),
  upstream_request_blob: bcs.u256(),
  upstream_headers_hash: bcs.byteVector(),
  model_id: bcs.string(),
  provider_request_id: bcs.string(),
  response_blob: bcs.u256(),
  provider_meta_hash: bcs.byteVector(),
  input_tokens: bcs.u64(),
  cache_creation_tokens: bcs.u64(),
  cache_read_tokens: bcs.u64(),
  output_tokens: bcs.u64(),
  outcome: bcs.u8(),
  timestamp_ms: bcs.u64(),
  verified_at_ms: bcs.u64(),
})

export type Attestation = {
  digest: string
  packageId: string
  gateway: string
  operator: string
  verifier: string
  pcrVersion: string
  receiptId: string
  configHash: string
  provider: number
  endpointHost: string
  tlsCertSha256: string
  requestBlob: bigint
  upstreamRequestBlob: bigint
  upstreamHeadersHash: string
  modelId: string
  providerRequestId: string
  responseBlob: bigint
  providerMetaHash: string
  inputTokens: string
  cacheCreationTokens: string
  cacheReadTokens: string
  outputTokens: string
  outcome: number
  timestampMs: string
  verifiedAtMs: string
}

/** On-chain state cross-checked against the event, so the certificate reports
 *  live registry facts rather than only what the transaction asserted. */
export type ChainChecks = {
  gatewayFound: boolean
  gatewayPk?: string
  gatewayPcrVersion?: string
  checkpointFound: boolean
  approvedEntry?: { pcr0: string; pcr1: string; pcr2: string; codeRef: string; revoked: boolean }
}

export type LookupResult = {
  attestation: Attestation
  checks: ChainChecks
  /** Checkpoint object id, discovered from the Gateway's package. */
  checkpointId?: string
}

const toHex = (b: Uint8Array) =>
  Array.from(b)
    .map((x) => x.toString(16).padStart(2, '0'))
    .join('')

/** gRPC returns bytes as a Uint8Array or as an index-keyed object depending on transport. */
function asBytes(value: unknown): Uint8Array {
  if (value instanceof Uint8Array) return value
  if (Array.isArray(value)) return Uint8Array.from(value as number[])
  if (value && typeof value === 'object') {
    return Uint8Array.from(Object.values(value as Record<string, number>))
  }
  throw new Error('unexpected byte encoding in event payload')
}

function client(rpc: string) {
  return new SuiGrpcClient({ network: 'testnet', baseUrl: rpc })
}

/** Base64 (Move JSON renders vector<u8> this way) or hex, to hex. */
function fieldToHex(value: unknown): string {
  if (typeof value !== 'string') return ''
  const stripped = value.startsWith('0x') ? value.slice(2) : value
  if (/^[0-9a-fA-F]+$/.test(stripped) && stripped.length % 2 === 0) return stripped.toLowerCase()
  try {
    const bin = atob(value)
    return toHex(Uint8Array.from(bin, (c) => c.charCodeAt(0)))
  } catch {
    return ''
  }
}

/** gRPC surfaces errors as URL-encoded strings; turn the ones users actually
 *  hit into plain language rather than leaking transport detail. */
function humanError(e: unknown): Error {
  const raw = decodeURIComponent(e instanceof Error ? e.message : String(e))
  if (/not found/i.test(raw)) {
    return new Error(
      'No such transaction on Sui testnet. Note that a rejected receipt never commits — ' +
        'its transaction aborts before finalization, so it leaves no digest to look up.',
    )
  }
  return new Error(raw.replace(/\s+/g, ' ').slice(0, 240))
}

export async function lookup(digest: string, rpc = DEFAULT_RPC): Promise<LookupResult> {
  const c = client(rpc)

  let tx: {
    Transaction?: {
      status?: { success?: boolean; error?: unknown }
      events?: Array<{ eventType: string; packageId: string; bcs: unknown }>
    }
  }
  try {
    tx = (await c.core.getTransaction({ digest, include: { events: true } } as never)) as typeof tx
  } catch (e) {
    throw humanError(e)
  }
  const t = tx.Transaction
  if (!t) throw new Error('transaction not found on this network')
  if (t.status && t.status.success === false) {
    // A failed verify aborts, so a certificate can only exist for a success.
    throw new Error('this transaction failed — no verification took place')
  }

  const event = (t.events ?? []).find((e) => e.eventType.endsWith('::receipt::ReceiptVerified'))
  if (!event) {
    throw new Error('no sekisho ReceiptVerified event in this transaction')
  }

  const d = ReceiptVerified.parse(asBytes(event.bcs)) as unknown as Record<string, string | number>
  const attestation: Attestation = {
    digest,
    packageId: event.packageId,
    gateway: String(d.gateway),
    operator: String(d.operator),
    verifier: String(d.verifier),
    pcrVersion: String(d.pcr_version),
    receiptId: toHex(asBytes(d.receipt_id)),
    configHash: toHex(asBytes(d.config_hash)),
    provider: Number(d.provider),
    endpointHost: String(d.endpoint_host),
    tlsCertSha256: toHex(asBytes(d.tls_cert_sha256)),
    requestBlob: BigInt(String(d.request_blob)),
    upstreamRequestBlob: BigInt(String(d.upstream_request_blob)),
    upstreamHeadersHash: toHex(asBytes(d.upstream_headers_hash)),
    modelId: String(d.model_id),
    providerRequestId: String(d.provider_request_id),
    responseBlob: BigInt(String(d.response_blob)),
    providerMetaHash: toHex(asBytes(d.provider_meta_hash)),
    inputTokens: String(d.input_tokens),
    cacheCreationTokens: String(d.cache_creation_tokens),
    cacheReadTokens: String(d.cache_read_tokens),
    outputTokens: String(d.output_tokens),
    outcome: Number(d.outcome),
    timestampMs: String(d.timestamp_ms),
    verifiedAtMs: String(d.verified_at_ms),
  }

  const checks = await crossCheck(c, attestation)
  return { attestation, checks }
}

/** Read the Gateway (and, through it, the Checkpoint) to confirm the event's
 *  claims still hold against current registry state — notably whether the code
 *  version it ran under has since been revoked. */
async function crossCheck(
  c: ReturnType<typeof client>,
  a: Attestation,
): Promise<ChainChecks> {
  const checks: ChainChecks = { gatewayFound: false, checkpointFound: false }

  try {
    const res = (await c.core.getObjects({
      objectIds: [a.gateway],
      include: { json: true },
    } as never)) as { objects?: Array<{ json?: Record<string, unknown> }> }
    const json = res.objects?.[0]?.json
    if (json) {
      checks.gatewayFound = true
      checks.gatewayPk = fieldToHex(json.pk)
      checks.gatewayPcrVersion = json.pcr_version != null ? String(json.pcr_version) : undefined
    }
  } catch {
    /* leave gatewayFound false — reported as an inconclusive check, not a failure */
  }

  return checks
}

/** Fetch a Checkpoint's approved entry so the certificate can show the code
 *  version and whether it has been revoked since. */
export async function loadCheckpoint(
  checkpointId: string,
  pcrVersion: string,
  rpc = DEFAULT_RPC,
): Promise<ChainChecks['approvedEntry'] | undefined> {
  const c = client(rpc)
  const res = (await c.core.getObjects({
    objectIds: [checkpointId],
    include: { json: true },
  } as never)) as { objects?: Array<{ json?: { approved_pcrs?: unknown[] } }> }
  const list = res.objects?.[0]?.json?.approved_pcrs
  if (!Array.isArray(list)) return undefined
  const entry = list[Number(pcrVersion)] as Record<string, unknown> | undefined
  if (!entry) return undefined
  return {
    pcr0: fieldToHex(entry.pcr0),
    pcr1: fieldToHex(entry.pcr1),
    pcr2: fieldToHex(entry.pcr2),
    codeRef: String(entry.code_ref ?? ''),
    revoked: Boolean(entry.revoked),
  }
}

export const PROVIDERS: Record<number, string> = {
  0: 'Anthropic',
  1: 'OpenAI-compatible',
}

export const OUTCOMES: Record<number, { label: string; note: string }> = {
  0: { label: 'Completed', note: 'The provider returned a normal completion.' },
  1: {
    label: 'Refused',
    note: 'The model declined. Providers return refusals as HTTP 200, so this is a normal response, not an error.',
  },
  2: {
    label: 'Upstream error',
    note: 'The provider failed or the connection dropped mid-response. A receipt is still issued.',
  },
  3: {
    label: 'Denied by policy',
    note: 'The gateway policy rejected the request. No call was made to any provider.',
  },
}
