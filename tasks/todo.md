# Sekisho build plan

Spec: docs/SPEC.md. Build phases run as Sonnet subagents; Fable verifies adversarially after each
merge. Phase B tasks are parallel after A lands.

## Phase A — Foundations (sequential, blocks everything)
- [x] A1. Repo init: git, Apache-2.0 LICENSE, README skeleton (hayabusa README structure), .gitignore, bun workspace, copy research briefs to docs/research/
- [x] A2. Pin the Receipt v1 BCS layout as a shared test-vector file (docs/receipt-v1-vectors.json): exact bytes for one canonical receipt, used by Move, Rust, and TS parity tests — 2 vectors (191B nominal; 377B refusal + 200-char model forcing 2-byte ULEB + u64::MAX tokens), script-generated

## Phase B — Parallel builds (Sonnet, one agent each)
- [x] B1. move/: checkpoint + receipt modules — 16/16 `sui move test` pass (verified independently), parity literals confirmed identical to A2 vectors, test helpers correctly `#[test_only]`, PCR lookup by index (fixed from positional), nonce-bound registration implemented
- [ ] B2. enclave/: axum server, canonical internal schema + hashing, anthropic + openai adapters (streaming accumulation), policy engine, bearer auth, receipt ring buffer, intent serialization matching A2 vectors, cargo test green incl. Rust-side parity test
- [x] B3. sdk/: 28/28 bun tests + clean tsc build (verified independently); parity test reads A2 vectors from disk (no hardcoded bytes); PTB helper FIXED to chain new_receipt_v1 -> verify (Move takes ReceiptV1 by value; PTBs can't build structs from pure args)
- [ ] B4. build+ops: Containerfile.eif, Makefile, argonaut boot-config wiring, register_enclave.ts, verify_deployment.ts, CI workflows, .claude/skills runbooks

## Phase C — Integration + adversarial verification (Fable)
- [ ] C1. Cross-check: Move/Rust/TS all reproduce A2 vector bytes exactly
- [ ] C2. Adversarial review: registration permissionlessness abuse, replay, hash canonicalization gaps, streaming edge cases (mid-stream abort, refusal receipts), policy bypass, secret handling
- [ ] C3. End-to-end dev-mode run: local enclave (no NSM) → real provider call → receipt → SDK verify
- [ ] C4. README + docs complete, `make check` green everywhere

## Review notes
(filled in as phases complete)
