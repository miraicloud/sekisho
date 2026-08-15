import type { Attestation, ChainChecks } from '../lib/sui'
import { OUTCOMES, PROVIDERS } from '../lib/sui'

const short = (s: string, head = 10, tail = 6) =>
  s.length > head + tail + 3 ? `${s.slice(0, head)}…${s.slice(-tail)}` : s

const when = (ms: string) => new Date(Number(ms)).toISOString().replace('T', ' ').slice(0, 19)

/** Walrus ids are u256; the explorer wants the base64url form. */
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

function Field({ k, v, big }: { k: string; v: string; big?: boolean }) {
  return (
    <div className="field">
      <span className="k">{k}</span>
      <div className={big ? 'v big' : 'v'}>{v}</div>
    </div>
  )
}

export function Certificate({
  a,
  checks,
}: {
  a: Attestation
  checks: ChainChecks
}) {
  const outcome = OUTCOMES[a.outcome] ?? { label: `Unknown (${a.outcome})`, note: '' }
  const stampClass =
    a.outcome === 0 ? '' : a.outcome === 3 ? 'denied' : a.outcome === 1 ? 'refused' : 'refused'

  const archived = a.responseBlob !== 0n
  const skew = Number(a.verifiedAtMs) - Number(a.timestampMs)

  return (
    <article className="certificate">
      <div className="cert-head">
        <div>
          <h2 className="cert-title">Certificate of Attested Inference</h2>
          <p className="cert-sub">Sui testnet · transaction {short(a.digest, 12, 8)}</p>
        </div>
        <div className={`stamp ${stampClass}`}>
          Signature
          <strong>Verified</strong>
          on-chain
        </div>
      </div>

      <section>
        <div className="sec-label">The exchange</div>
        <div className="grid">
          <Field k="Model served" v={a.modelId} big />
          <Field k="Provider" v={PROVIDERS[a.provider] ?? `#${a.provider}`} />
          <Field k="Endpoint" v={a.endpointHost} />
          <Field k="Outcome" v={outcome.label} />
          <Field k="Input tokens" v={a.inputTokens} />
          <Field k="Output tokens" v={a.outputTokens} />
          <Field k="Cache write / read" v={`${a.cacheCreationTokens} / ${a.cacheReadTokens}`} />
          <Field k="Provider request id" v={a.providerRequestId || '—'} />
        </div>
        {outcome.note && <p className="skew">{outcome.note}</p>}
      </section>

      <section>
        <div className="sec-label">Chain of evidence</div>
        <ol className="chain">
          <li>
            <div>
              <p className="claim">
                The signature over this receipt was checked on-chain against the enclave key
                registered for this gateway.
                <span className="mark ok">Proven</span>
              </p>
              <p className="ev">
                Move aborts on a bad signature, so this transaction could not have succeeded
                otherwise. Gateway {short(a.gateway, 12, 8)}
                {checks.gatewayPk ? ` · key ${short(checks.gatewayPk, 10, 6)}` : ''}
              </p>
            </div>
          </li>

          <li>
            <div>
              <p className="claim">
                The enclave was running approved, PCR-measured code.
                {checks.approvedEntry?.revoked ? (
                  <span className="mark bad">Revoked since</span>
                ) : checks.approvedEntry ? (
                  <span className="mark ok">Approved</span>
                ) : (
                  <span className="mark warn">Not checked</span>
                )}
              </p>
              <p className="ev">
                Code version #{a.pcrVersion}
                {checks.approvedEntry ? ` · ref ${checks.approvedEntry.codeRef}` : ''}
                {checks.approvedEntry ? ` · PCR0 ${short(checks.approvedEntry.pcr0, 12, 8)}` : ''}
                {!checks.approvedEntry &&
                  ' — supply the Checkpoint object id to confirm this version is still approved.'}
              </p>
            </div>
          </li>

          <li>
            <div>
              <p className="claim">
                The enclave completed a TLS handshake with a server presenting this certificate for{' '}
                {a.endpointHost}.<span className="mark ok">Proven</span>
              </p>
              <p className="ev">Leaf certificate SHA-256 {a.tlsCertSha256}</p>
            </div>
          </li>

          <li>
            <div>
              <p className="claim">
                The request and response are committed to by content-addressed Walrus blob ids.
                {archived ? (
                  <span className="mark ok">Committed</span>
                ) : (
                  <span className="mark warn">Not archived</span>
                )}
              </p>
              <p className="ev">
                request {archived ? blobIdBase64(a.requestBlob) : '—'}
                <br />
                response {archived ? blobIdBase64(a.responseBlob) : '—'}
                {!archived &&
                  ' — the gateway computed no blob commitment for this exchange (a policy denial makes no upstream call).'}
              </p>
            </div>
          </li>

          <li>
            <div>
              <p className="claim">
                The policy in force, and the headers actually sent upstream, are committed to.
                <span className="mark ok">Committed</span>
              </p>
              <p className="ev">
                policy {short(a.configHash, 12, 8)} · upstream headers{' '}
                {short(a.upstreamHeadersHash, 12, 8)} · provider metadata{' '}
                {short(a.providerMetaHash, 12, 8)}
              </p>
            </div>
          </li>

          <li>
            <div>
              <p className="claim">
                Signed by the enclave, then verified at consensus time.
                <span className="mark ok">Timestamped</span>
              </p>
              <p className="ev">
                enclave {when(a.timestampMs)}Z · consensus {when(a.verifiedAtMs)}Z · skew{' '}
                {(skew / 1000).toFixed(1)}s
                <br />
                The enclave clock derives from its host and is advisory; consensus time is the
                trustworthy one.
              </p>
            </div>
          </li>
        </ol>
      </section>

      <div className="limits">
        <h3>Limits of this certificate</h3>
        <p>
          This does <strong>not</strong> prove the provider ran the model it named. Providers do not
          sign their responses, so the chain of custody ends at {a.endpointHost}'s TLS termination.
          What is proven is faithful <em>relay</em> by auditable code — not honest <em>inference</em>.
        </p>
        <p>
          Receipts are replayable by design: the same receipt can be verified more than once, and
          each verification emits its own event. Consumers must dedupe by receipt id{' '}
          <span style={{ fontFamily: 'var(--mono)' }}>{short(a.receiptId, 10, 6)}</span>.
        </p>
        <p>
          Only successful verifications appear on-chain. A rejected receipt aborts its transaction,
          and an abort rolls back its events — so the absence of a certificate is not evidence that
          nothing was attempted.
        </p>
      </div>

      <div className="foot">
        package {a.packageId}
        <br />
        operator {a.operator} · submitted by {a.verifier}
        <br />
        Rebuild the enclave from the referenced source and compare PCRs to check this yourself:{' '}
        <code>bun scripts/verify_deployment.ts &lt;url&gt; --ref &lt;git-ref&gt;</code>
      </div>
    </article>
  )
}
