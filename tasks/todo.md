# Sekisho build plan

Spec: docs/SPEC.md. Phase B ran as four parallel Sonnet subagents; every result was
independently re-verified (not taken from the agent's report) before being accepted.

## Phase A — Foundations
- [x] A1. Repo init: git, Apache-2.0, README, .gitignore, bun workspace, research briefs in docs/research/
- [x] A2. Pin the Receipt v1 BCS layout as `docs/receipt-v1-vectors.json` — 2 script-generated vectors
      (191B nominal; 377B refusal + 200-char model forcing 2-byte ULEB + u64::MAX tokens)

## Phase B — Parallel builds
- [x] B1. move/ — 16/16 `sui move test`; parity literals confirmed identical to A2 vectors;
      test helpers correctly `#[test_only]`; nonce-bound registration; PCR lookup by index (fixed)
- [x] B2. enclave/ — 49/49 cargo tests, clippy `-D warnings` and fmt clean; parity constants verified
      against A2; provider URLs compile-time consts; config_hash excludes secrets
- [x] B3. sdk/ — 29/29 bun tests, clean tsc build; parity test reads A2 from disk;
      PTB helper fixed to chain `new_receipt_v1` -> `verify`
- [x] B4. build+ops — Containerfile.eif, Makefile, argonaut boot config (secrets on 7778, bridge
      config PCR-measured), register/verify scripts, CI, runbooks

## Phase C — Integration + adversarial verification
- [x] C1. Move, Rust, and TypeScript all reproduce the A2 vector bytes exactly; vectors themselves
      cross-checked against Mysten's BCS (a different implementation than the generator)
- [x] C2. Adversarial review — findings below
- [x] C3. End-to-end run green from a clean clone (`bun scripts/e2e_demo.ts`), added as a CI job
- [x] C4. README complete and its commands verified; `make check` / `sui move test` / `bun test` /
      `tsc --noEmit` all green

## Review

Defects found and fixed after the builders reported success:

| # | Where | Defect |
|---|---|---|
| 1 | vectors | `u64::MAX` stored as a JSON number rounds up in any IEEE-754 parser; now decimal strings |
| 2 | move | PCRs read by array position; Sui's PCR parsing has changed across protocol versions, so a legitimate enclave could be rejected. Now looked up by index |
| 3 | sdk | PTB helper passed the receipt as 13 flat args, but `verify` takes a struct by value and a PTB cannot build one from pure args. Would have failed on the first real onchain call |
| 4 | enclave | `receipt_id` served as a dashed UUID while every sibling field was hex — clients could not decode the signed payload uniformly |
| 5 | enclave | `/attestation` omitted the signing key, forcing clients to hand-parse CBOR to verify a receipt |
| 6 | sdk | Docstrings claimed the hash helpers reproduce `request_hash`; empirically false. Renamed to `hashJson` with accurate docs |
| 7 | enclave | **Policy bypass**: a `max_tokens` cap only checked requests that specified it; omitting the field (legal on the OpenAI surface) escaped the cap |
| 8 | enclave | Bearer scheme matched case-sensitively, against RFC 7235 |
| 9 | ops | `verify_deployment` treated a `pcr_version` mismatch as a warning; the Move package makes that index definitional, so it is now a FAIL |
| 10 | ci | Vector check had a hardcoded absolute path and lived outside any workspace — unrunnable in CI |

Design holes found in an early adversarial pass, fixed in the spec before they were built:

- **Registration hijack**: attestation documents are public, so an unbound document was a bearer
  token — anyone could register another operator's enclave and destroy the gateway. Registration
  is now bound to the sender via the attestation nonce.
- **Provider redirection**: config-supplied base URLs would have let an operator point "anthropic"
  at their own server while still emitting receipts that verify onchain, voiding the entire
  premise. URLs are now compile-time constants covered by PCR2.
- **Allowlist injection**: reusing argonaut's VSOCK:7777 for secrets would have let an untrusted
  host inject the outbound allowlist; secrets moved to 7778, bridge config stays PCR-measured.

## Not done (deliberate)

- No real EIF build or Nitro run — needs `linux/amd64` and Nitro hardware. The Containerfile passes
  `docker build --check`; the reproducibility CI job is `continue-on-error` until proven.
- No onchain deployment, so `register_enclave.ts` and `verify_deployment.ts`'s chain reads are
  untested against a live Checkpoint.
- No live provider call (would need a real API key); provider adapters are covered by mocked tests.
- Not audited. The upstream Nautilus template is itself pre-audit.
