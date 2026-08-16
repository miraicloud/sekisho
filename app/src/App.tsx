import { useCallback, useEffect, useRef, useState } from 'react'
import { renderCertificate, type Line } from './lib/render'
import { loadCheckpoint, lookup } from './lib/sui'

const EXAMPLE = 'CEPZgWZ6R9ZyuvSbwepDEytfvfv6C4aZKLXzxCTcQs3d'
const CHECKPOINT = '0x14e1a8cb5aeb0b52f04ed1d05d0e8f44e75644a644acc70be1613c3fb5075553'

/** A certificate is addressed as `/cert/<digest>`. */
function digestFromLocation(): string | null {
  return window.location.pathname.match(/^\/cert\/([A-Za-z0-9]+)\/?$/)?.[1] ?? null
}

const BANNER: Line[] = [
  { text: 'sekisho — attested inference registry', tone: 'label' },
  { text: 'sui testnet · read-only · no backend', tone: 'dim' },
  { text: '' },
  {
    text: 'A block explorer tells you a Move call succeeded. This tells you what that',
    tone: 'dim',
  },
  { text: 'success proves about an LLM exchange — and what it does not.', tone: 'dim' },
  { text: '' },
  { text: "type 'help' for commands, or 'example' to inspect a real attested Claude call", tone: 'dim' },
  { text: '' },
]

const HELP: Line[] = [
  { text: '' },
  { text: '  verify <digest>   inspect a transaction that verified a receipt', tone: 'value' },
  { text: '  example           inspect a known attested Claude call', tone: 'value' },
  { text: '  clear             clear the scrollback', tone: 'value' },
  { text: '  help              this list', tone: 'value' },
  { text: '' },
]

export default function App() {
  const [lines, setLines] = useState<Line[]>(BANNER)
  const [input, setInput] = useState('')
  const [busy, setBusy] = useState(false)
  const [history, setHistory] = useState<string[]>([])
  const [histIndex, setHistIndex] = useState<number | null>(null)
  const endRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  const push = useCallback((...l: Line[]) => setLines((prev) => [...prev, ...l]), [])

  useEffect(() => {
    endRef.current?.scrollIntoView({ block: 'end' })
  }, [lines])

  const verify = useCallback(
    async (digest: string) => {
      setBusy(true)
      const started = performance.now()
      try {
        const res = await lookup(digest, undefined, (label) =>
          push({ text: `  · ${label}`, tone: 'dim' }),
        )
        try {
          push({ text: '  · reading checkpoint', tone: 'dim' })
          const entry = await loadCheckpoint(CHECKPOINT, res.attestation.pcrVersion)
          if (entry) res.checks.approvedEntry = entry
        } catch {
          /* reported as SKIP in the certificate rather than claimed as approval */
        }
        push(...renderCertificate(res.attestation, res.checks))
        push({
          text: `  verified in ${Math.round(performance.now() - started)}ms`,
          tone: 'dim',
        })
        push({ text: '' })
        window.history.pushState({}, '', `/cert/${digest}`)
      } catch (e) {
        push({ text: '' })
        push({ text: `  error: ${e instanceof Error ? e.message : String(e)}`, tone: 'bad' })
        push({ text: '' })
      } finally {
        setBusy(false)
      }
    },
    [push],
  )

  const run = useCallback(
    async (raw: string) => {
      const cmd = raw.trim()
      if (!cmd) return
      push({ text: `$ ${cmd}` })
      setHistory((h) => [...h, cmd])
      setHistIndex(null)

      const [verb, ...rest] = cmd.split(/\s+/)
      switch (verb) {
        case 'help':
          push(...HELP)
          break
        case 'clear':
          setLines([])
          break
        case 'example':
          await verify(EXAMPLE)
          break
        case 'verify':
          if (!rest[0]) {
            push({ text: '  usage: verify <transaction-digest>', tone: 'warn' }, { text: '' })
          } else {
            await verify(rest[0])
          }
          break
        default:
          // A bare digest is the overwhelmingly common input; accept it.
          if (/^[A-Za-z0-9]{40,50}$/.test(verb)) {
            await verify(verb)
          } else {
            push(
              { text: `  ${verb}: not a command. try 'help'.`, tone: 'warn' },
              { text: '' },
            )
          }
      }
    },
    [push, verify],
  )

  // Deep link on load, and follow browser history.
  useEffect(() => {
    const initial = digestFromLocation()
    if (initial) void run(`verify ${initial}`)

    const onPop = () => {
      const d = digestFromLocation()
      if (d) void run(`verify ${d}`)
    }
    window.addEventListener('popstate', onPop)
    return () => window.removeEventListener('popstate', onPop)
    // run once on mount
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // Typing anywhere focuses the prompt, the way a terminal behaves.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.metaKey || e.ctrlKey || e.altKey) return
      if (document.activeElement !== inputRef.current) inputRef.current?.focus()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  return (
    <div className="term" onClick={() => inputRef.current?.focus()}>
      <div className="scroll">
        {lines.map((l, i) => (
          <div key={i} className={`line ${l.tone ?? ''}`}>
            {l.text || ' '}
          </div>
        ))}

        <form
          className="prompt"
          onSubmit={(e) => {
            e.preventDefault()
            if (busy) return
            const v = input
            setInput('')
            void run(v)
          }}
        >
          <span className="sigil">$</span>
          <input
            ref={inputRef}
            value={input}
            spellCheck={false}
            autoComplete="off"
            autoFocus
            aria-label="command"
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'ArrowUp') {
                e.preventDefault()
                if (!history.length) return
                const next = histIndex === null ? history.length - 1 : Math.max(0, histIndex - 1)
                setHistIndex(next)
                setInput(history[next])
              } else if (e.key === 'ArrowDown') {
                e.preventDefault()
                if (histIndex === null) return
                const next = histIndex + 1
                if (next >= history.length) {
                  setHistIndex(null)
                  setInput('')
                } else {
                  setHistIndex(next)
                  setInput(history[next])
                }
              }
            }}
          />
          {busy && <span className="working">working…</span>}
        </form>
        <div ref={endRef} />
      </div>
    </div>
  )
}
