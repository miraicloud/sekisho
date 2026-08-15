/**
 * End-to-end demo: boot a local gateway, get a signed receipt, verify it with
 * the SDK, and build the on-chain verification PTB.
 *
 * Runs fully offline. It exercises the policy-denial path, which produces a
 * signed receipt WITHOUT contacting any model provider — so the whole
 * enclave -> receipt -> SDK -> PTB loop is provable with no API key and no
 * network. (Provider base URLs are compile-time constants, so a local mock
 * provider is deliberately impossible to substitute.)
 *
 * The gateway runs in development mode here: with no /dev/nsm device it uses
 * an in-memory Ed25519 key instead of an NSM-attested one. Signature checking
 * is identical; only the key's provenance differs.
 *
 *   bun scripts/e2e_demo.ts
 */
import { spawn } from 'node:child_process'
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { setTimeout as sleep } from 'node:timers/promises'
import {
  ReceiptOutcome,
  parseBlobId,
  serializeReceipt,
  verifyReceipt,
  type Receipt,
} from '../sdk/src/receipt'
import { buildVerifyTransaction } from '../sdk/src/extension'

const REPO = new URL('..', import.meta.url).pathname
const CALLER_KEY = 'demo-caller-key'
const PORT = 38311

const config = {
  anthropic_api_key: 'unused-no-upstream-call-is-made',
  caller_keys: [CALLER_KEY],
  policy: {
    rules: [
      {
        name: 'allow-claude-only',
        action: 'allow',
        allowed_models: ['claude-*'],
      },
    ],
  },
}

let failures = 0
const check = (ok: boolean, label: string, detail = '') => {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${detail ? ` — ${detail}` : ''}`)
  if (!ok) failures++
}

const dir = mkdtempSync(join(tmpdir(), 'sekisho-e2e-'))
const configPath = join(dir, 'config.json')
writeFileSync(configPath, JSON.stringify(config))

console.log('building gateway (cargo build)...')
const build = spawn('cargo', ['build', '--quiet'], { cwd: join(REPO, 'enclave'), stdio: 'inherit' })
await new Promise((res) => build.on('exit', res))

const server = spawn(join(REPO, 'enclave/target/debug/sekisho-enclave'), [], {
  env: { ...process.env, SEKISHO_CONFIG: configPath, HOST: '127.0.0.1', PORT: String(PORT) },
  stdio: ['ignore', 'pipe', 'pipe'],
})
server.stdout.on('data', (b) => process.stdout.write(`  [gateway] ${b}`))
server.stderr.on('data', (b) => process.stderr.write(`  [gateway] ${b}`))

const base = `http://127.0.0.1:${PORT}`
try {
  // Wait for the listener.
  let up = false
  for (let i = 0; i < 50 && !up; i++) {
    try {
      const r = await fetch(`${base}/health_check`)
      up = r.ok
    } catch {
      await sleep(100)
    }
  }
  check(up, 'gateway is listening', base)
  if (!up) throw new Error('gateway never came up')

  // 1. The enclave's public key, as a client would fetch it before trusting anything.
  const attestation = (await (await fetch(`${base}/attestation`)).json()) as Record<string, unknown>
  const pubkeyHex = String(attestation.public_key ?? attestation.publicKey ?? '')
  check(/^[0-9a-f]{64}$/.test(pubkeyHex), 'attestation exposes an Ed25519 public key', pubkeyHex)

  // 2. A request the policy forbids: signed receipt, no upstream call.
  const res = await fetch(`${base}/v1/messages`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${CALLER_KEY}` },
    body: JSON.stringify({
      model: 'gpt-4o-not-allowed-by-policy',
      max_tokens: 16,
      messages: [{ role: 'user', content: 'hello' }],
    }),
  })
  const receiptId = res.headers.get('x-receipt-id')
  check(!!receiptId, 'denied request still returns x-receipt-id', receiptId ?? '(missing)')

  // 3. Fetch the receipt the gateway recorded.
  const record = (await (
    await fetch(`${base}/receipts/${receiptId}`, { headers: { authorization: `Bearer ${CALLER_KEY}` } })
  ).json()) as any
  const r = record.receipt ?? record
  check(
    Number(r.outcome) === ReceiptOutcome.PolicyDenied,
    'receipt outcome is 3 (policy_denied)',
    `outcome=${r.outcome}`,
  )

  // The gateway's outcome is an untyped number off the wire; narrow it to the
  // union rather than casting, so an unrecognized code fails loudly here
  // instead of silently producing a receipt that won't verify.
  const outcomes = Object.values(ReceiptOutcome) as number[]
  const rawOutcome = Number(r.outcome)
  if (!outcomes.includes(rawOutcome)) throw new Error(`unknown receipt outcome ${rawOutcome}`)
  const outcome = rawOutcome as ReceiptOutcome

  const receipt: Receipt = {
    receiptId: r.receipt_id,
    configHash: r.config_hash,
    provider: Number(r.provider),
    endpointHost: r.endpoint_host,
    tlsCertSha256: r.tls_cert_sha256,
    requestBlob: parseBlobId(r.request_blob),
    upstreamRequestBlob: parseBlobId(r.upstream_request_blob),
    upstreamHeadersHash: r.upstream_headers_hash,
    modelId: r.model_id,
    providerRequestId: r.provider_request_id,
    responseBlob: parseBlobId(r.response_blob),
    providerMetaHash: r.provider_meta_hash,
    inputTokens: BigInt(r.input_tokens),
    cacheCreationTokens: BigInt(r.cache_creation_tokens),
    cacheReadTokens: BigInt(r.cache_read_tokens),
    outputTokens: BigInt(r.output_tokens),
    outcome,
  }
  const timestampMs = BigInt(record.timestamp_ms ?? record.timestampMs ?? r.timestamp_ms)
  const signatureHex = String(record.signature ?? record.signature_hex)

  // 4. The point of the whole project: verify the enclave's signature client-side.
  const bytes = serializeReceipt(receipt, timestampMs)
  check(bytes.length > 0, 'SDK serializes the receipt to BCS', `${bytes.length} bytes`)

  const valid = verifyReceipt(receipt, timestampMs, signatureHex, pubkeyHex)
  check(valid, 'SDK verifies the enclave signature over the receipt')

  const tampered: Receipt = { ...receipt, outcome: ReceiptOutcome.Ok }
  const stillValid = verifyReceipt(tampered, timestampMs, signatureHex, pubkeyHex)
  check(!stillValid, 'tampering with the receipt invalidates the signature')

  // 5. The PTB a consuming contract would submit.
  const tx = buildVerifyTransaction({
    packageId: '0x2'.padEnd(66, '0'),
    gatewayId: '0x3'.padEnd(66, '0'),
    checkpointId: '0x4'.padEnd(66, '0'),
    timestampMs,
    receipt,
    signatureHex,
  })
  const cmds = (tx.getData() as any).commands.filter((c: any) => c.$kind === 'MoveCall')
  check(
    cmds.length === 2 && cmds[1].MoveCall.function === 'verify',
    'PTB chains new_receipt -> receipt::verify',
    `${cmds.length} move calls`,
  )
} finally {
  server.kill('SIGTERM')
  rmSync(dir, { recursive: true, force: true })
}

console.log(failures === 0 ? '\nEND-TO-END OK' : `\n${failures} CHECK(S) FAILED`)
process.exit(failures === 0 ? 0 : 1)
