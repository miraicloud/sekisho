# Research briefs

Background research this project's design decisions were drawn from, kept in-repo so the
reasoning behind the spec is auditable rather than folklore.

| File | Subject |
|---|---|
| `nautilus.md` | Nautilus framework internals: attestation verification, PCR semantics, reproducible builds, vsock wiring |
| `prior-art.md` | Attested-inference prior art (Tinfoil, Phala, NEAR AI, Opacity) and receipt schema design |
| `provider-apis.md` | Anthropic / OpenAI-compatible / OpenRouter API surfaces, canonical hashing, streaming, error taxonomy |
| `UsingNautilus.md` | Upstream Nautilus operational guide (vendored copy) |

One brief is deliberately **not** committed: an internal-patterns review of sibling repos
(`an internal sibling project`, `onara`, `hayabusa`). It quotes production infrastructure — backend
URLs and Cloudflare resource ids — that those repos keep in gitignored config precisely so it
never lands in open-source code. It is gitignored here at `docs/research/local-patterns.md` and
kept on disk for local reference only.
