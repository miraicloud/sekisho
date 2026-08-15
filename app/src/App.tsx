import { useCallback, useEffect, useState } from 'react'
import { Certificate } from './components/Certificate'
import { loadCheckpoint, lookup, type LookupResult } from './lib/sui'

/** A known-good digest so the page is useful the moment it loads. */
const EXAMPLE = 'CEPZgWZ6R9ZyuvSbwepDEytfvfv6C4aZKLXzxCTcQs3d'
/** Optional: lets the certificate report whether the code version is still approved. */
const CHECKPOINT = '0x14e1a8cb5aeb0b52f04ed1d05d0e8f44e75644a644acc70be1613c3fb5075553'

export default function App() {
  const [digest, setDigest] = useState('')
  const [result, setResult] = useState<LookupResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const run = useCallback(async (d: string) => {
    const trimmed = d.trim()
    if (!trimmed) return
    setBusy(true)
    setError(null)
    setResult(null)
    try {
      const res = await lookup(trimmed)
      // Best-effort: a revoked code version is the one fact the event alone
      // cannot tell you, so it is worth a second read.
      try {
        const entry = await loadCheckpoint(CHECKPOINT, res.attestation.pcrVersion)
        if (entry) res.checks.approvedEntry = entry
      } catch {
        /* leave unchecked rather than claiming approval */
      }
      setResult(res)
      window.location.hash = trimmed
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }, [])

  // Deep link: /#<digest> so a certificate can be shared as a URL.
  useEffect(() => {
    const fromHash = window.location.hash.replace(/^#/, '')
    if (fromHash) {
      setDigest(fromHash)
      void run(fromHash)
    }
  }, [run])

  return (
    <div className="shell">
      <header className="masthead">
        <div className="bureau">Sekisho · attested inference registry</div>
        <h1>Present your papers.</h1>
        <p>
          Look up a Sui transaction that verified a sekisho receipt. A block explorer will tell you
          a Move call succeeded; this tells you what that success actually proves about an LLM
          exchange — and, just as importantly, what it does not.
        </p>
      </header>

      <form
        className="lookup"
        onSubmit={(e) => {
          e.preventDefault()
          void run(digest)
        }}
      >
        <input
          value={digest}
          onChange={(e) => setDigest(e.target.value)}
          placeholder="Transaction digest"
          spellCheck={false}
          aria-label="Transaction digest"
        />
        <button type="submit" disabled={busy || !digest.trim()}>
          {busy ? 'Inspecting…' : 'Inspect'}
        </button>
      </form>

      <p className="hint">
        No transaction to hand?{' '}
        <button
          type="button"
          onClick={() => {
            setDigest(EXAMPLE)
            void run(EXAMPLE)
          }}
        >
          Inspect a real attested Claude call
        </button>
      </p>

      {error && <div className="notice">{error}</div>}

      {result && <Certificate a={result.attestation} checks={result.checks} />}
    </div>
  )
}
