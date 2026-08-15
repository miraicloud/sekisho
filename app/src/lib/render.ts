import type { Attestation, ChainChecks } from './sui'
import { OUTCOMES, PROVIDERS } from './sui'

/** One rendered terminal line. `tone` drives colour only. */
export type Line = {
  text: string
  tone?: 'dim' | 'ok' | 'warn' | 'bad' | 'label' | 'value'
}

const short = (s: string, head = 10, tail = 6) =>
  s.length > head + tail + 3 ? `${s.slice(0, head)}…${s.slice(-tail)}` : s

const when = (ms: string) => `${new Date(Number(ms)).toISOString().slice(0, 19).replace('T', ' ')}Z`

/** Walrus u256 blob id (little-endian) as the base64url form explorers use. */
function blobIdBase64(value: bigint): string {
  const bytes = new Uint8Array(32)
  let v = value
  for (let i = 0; i < 32; i++) {
    bytes[i] = Number(v & 0xffn)
    v >>= 8n
  }
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/** `key   value` with the key padded to a fixed gutter. */
const kv = (k: string, v: string): Line => ({ text: `  ${k.padEnd(16)}${v}`, tone: 'value' })

export function renderCertificate(a: Attestation, checks: ChainChecks): Line[] {
  const outcome = OUTCOMES[a.outcome] ?? { label: `unknown (${a.outcome})`, note: '' }
  const archived = a.responseBlob !== 0n
  const skew = (Number(a.verifiedAtMs) - Number(a.timestampMs)) / 1000
  const out: Line[] = []

  out.push({ text: '' })
  out.push({ text: '  CERTIFICATE OF ATTESTED INFERENCE', tone: 'label' })
  out.push({ text: `  ${'─'.repeat(60)}`, tone: 'dim' })
  out.push({ text: '' })

  out.push(kv('model', a.modelId))
  out.push(kv('provider', `${PROVIDERS[a.provider] ?? `#${a.provider}`} · ${a.endpointHost}`))
  out.push(kv('outcome', outcome.label))
  out.push(
    kv(
      'tokens',
      `${a.inputTokens} in · ${a.outputTokens} out · cache ${a.cacheCreationTokens}/${a.cacheReadTokens}`,
    ),
  )
  out.push(kv('provider ref', a.providerRequestId || '—'))
  if (outcome.note) {
    out.push({ text: '' })
    out.push({ text: `  ${outcome.note}`, tone: 'dim' })
  }

  out.push({ text: '' })
  out.push({ text: '  CHAIN OF EVIDENCE', tone: 'label' })
  out.push({ text: '' })

  const claim = (
    mark: string,
    tone: Line['tone'],
    text: string,
    evidence: string[],
  ) => {
    out.push({ text: `  [${mark}] ${text}`, tone })
    for (const e of evidence) out.push({ text: `         ${e}`, tone: 'dim' })
    out.push({ text: '' })
  }

  claim('PASS', 'ok', 'signature checked against the registered enclave key', [
    'move aborts on a bad signature — this transaction could not have succeeded otherwise',
    `gateway ${short(a.gateway, 12, 8)}${checks.gatewayPk ? `  key ${short(checks.gatewayPk, 10, 6)}` : ''}`,
  ])

  if (checks.approvedEntry?.revoked) {
    claim('WARN', 'bad', 'code version has been REVOKED since this ran', [
      `version #${a.pcrVersion}  ref ${checks.approvedEntry.codeRef}`,
    ])
  } else if (checks.approvedEntry) {
    claim('PASS', 'ok', 'enclave ran approved, PCR-measured code', [
      `version #${a.pcrVersion}  ref ${checks.approvedEntry.codeRef}`,
      `PCR0 ${checks.approvedEntry.pcr0}`,
    ])
  } else {
    claim('SKIP', 'warn', 'code approval not confirmed (checkpoint unreadable)', [
      `version #${a.pcrVersion}`,
    ])
  }

  claim('PASS', 'ok', `TLS handshake completed with ${a.endpointHost}`, [
    `leaf certificate sha256 ${a.tlsCertSha256}`,
  ])

  if (archived) {
    claim('PASS', 'ok', 'request and response committed by Walrus blob id', [
      `request  ${blobIdBase64(a.requestBlob)}`,
      `response ${blobIdBase64(a.responseBlob)}`,
    ])
  } else {
    claim('SKIP', 'warn', 'no blob commitment for this exchange', [
      'a policy denial makes no upstream call',
    ])
  }

  claim('PASS', 'ok', 'policy and upstream headers committed', [
    `policy ${short(a.configHash, 12, 8)}  headers ${short(a.upstreamHeadersHash, 12, 8)}  meta ${short(a.providerMetaHash, 12, 8)}`,
  ])

  claim('PASS', 'ok', 'signed by the enclave, verified at consensus time', [
    `enclave   ${when(a.timestampMs)}`,
    `consensus ${when(a.verifiedAtMs)}  (skew ${skew.toFixed(1)}s)`,
    'the enclave clock derives from its host and is advisory',
  ])

  out.push({ text: '  LIMITS', tone: 'bad' })
  out.push({ text: '' })
  out.push({
    text: '  ! does NOT prove the provider ran the model it named. Providers do not',
    tone: 'bad',
  })
  out.push({
    text: `    sign responses, so custody ends at ${a.endpointHost}'s TLS termination.`,
    tone: 'bad',
  })
  out.push({ text: '    Faithful relay is proven; honest inference is not.', tone: 'bad' })
  out.push({ text: '' })
  out.push({
    text: `  ! receipts are replayable — dedupe by receipt id ${short(a.receiptId, 10, 6)}`,
    tone: 'bad',
  })
  out.push({
    text: '  ! only successful verifications emit events; an abort rolls its event back',
    tone: 'bad',
  })
  out.push({ text: '' })
  out.push({ text: `  package  ${a.packageId}`, tone: 'dim' })
  out.push({ text: `  operator ${a.operator}`, tone: 'dim' })
  out.push({ text: '' })

  return out
}
