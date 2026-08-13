# Sekisho — Attested AI Gateway for Sui Nautilus

Sekisho is an open-source AI gateway that runs inside an AWS Nitro Enclave (via Nautilus),
relays requests to LLM providers, and signs an inference **Receipt** verifiable onchain by any
Sui Move contract.

Spec version: 1 (2026-08-13). Research briefs backing every decision here live in the session
scratchpad (`research/{nautilus,local-patterns,provider-apis,prior-art}.md`) and should be copied
into `docs/research/` on repo init.

---

## 1. What it proves

A Receipt attests: *"An enclave running exactly this open-source code (PCR-verified), under exactly
this policy config (config-hashed), forwarded exactly this request (hashed) to exactly this model,
and returned exactly this response (hashed), at this time."*

Trust model: AWS Nitro attestation → registered onchain once (expensive `sui::nitro_attestation`
verify at registration) → per-receipt cheap Ed25519 verify. Upstream model content remains trusted
to the provider (attested *relay*, not attested *inference*). This is the Nautilus verify-once /
sign-cheap split; Phala/NEAR AI validate the same shape.

## 2. Repo layout

```
sekisho/
├── move/               # Move package `sekisho` (registry + receipt verification)
├── enclave/            # Rust axum gateway (Nautilus enclave app)
├── sdk/                 # @miraicloud/sekisho TypeScript SDK
├── scripts/             # bun scripts: register_enclave.ts, verify_deployment.ts
├── docs/                # SPEC.md, research/, runbooks
├── .claude/skills/      # operational runbooks (register-enclave, rotate-keys)
└── .github/workflows/   # CI (deliberate break from house no-CI norm)
```

License Apache-2.0, Copyright 2026 (miraicloud). Move edition 2024. Bun for all TS tooling.

## 3. Move package (`move/`)

Depends on `kagi` concepts but implements its own registry because kagi's `enclave::new` is
cap-gated and sekisho needs **permissionless operator registration**:

- `sekisho::checkpoint` — shared `Checkpoint` object (the trust root, published once by
  miraicloud):
  - `approved_pcrs: vector<PcrSet>` — PCR0/1/2 triples for approved code versions, each with
    `code_ref: String` (git tag) and `revoked: bool`. Gated by `CheckpointCap` (add, revoke —
    NEAR AI-style onchain build revocation).
  - `register(checkpoint, document: NitroAttestationDocument, ctx)` — **no cap required**: any
    enclave whose attestation PCRs match a non-revoked `PcrSet` registers; shares a
    `Gateway { id, pk: vector<u8>, pcr_version: u64, operator: address, registered_at_ms }`.
    Attestation parsed/verified in the same PTB via `0x2::nitro_attestation::load_nitro_attestation`.
  - Reboot ⇒ new ephemeral key ⇒ re-register (documented runbook; old Gateway destroyable by
    operator).
- `sekisho::receipt` — receipt verification:
  - `ReceiptV1` payload struct (below), `RECEIPT_INTENT_V1: u8 = 0`.
  - `verify(gateway: &Gateway, checkpoint: &Checkpoint, timestamp_ms, payload, sig)` — aborts
    unless sig valid (Ed25519 over BCS `IntentMessage`) AND the gateway's PCR version is not
    revoked. Returns a hot-potato-free witness struct callers can consume.
  - Inline `#[test]`s including **`test_bcs_parity` with exact byte offsets** (house pattern from
    an internal sibling project — non-negotiable guard against Rust/Move drift).

### ReceiptV1 (BCS, field order is normative)

| field | type | notes |
|---|---|---|
| `receipt_id` | `vector<u8>` (16) | UUID assigned by enclave |
| `config_hash` | `vector<u8>` (32) | SHA-256 of active policy/config JSON (canonical) |
| `request_hash` | `vector<u8>` (32) | SHA-256 of canonicalized client request |
| `upstream_request_hash` | `vector<u8>` (32) | hash of what was actually sent upstream (captures gateway transforms — Phala lesson) |
| `model_id` | `String` | provider-reported served model (read back off response, not the request — OpenRouter lesson) |
| `response_hash` | `vector<u8>` (32) | SHA-256 of canonicalized assembled response (streamed deltas accumulated first — never raw SSE bytes) |
| `input_tokens` / `output_tokens` | `u64` | provider-reported usage |
| `outcome` | `u8` | 0=ok, 1=refusal (HTTP 200 refusals still get receipts), 2=upstream_error, 3=policy_denied |

Envelope: `IntentMessage<ReceiptV1> { intent: 0, timestamp_ms, payload }`, Ed25519-signed.
Schema evolution = new intent byte + new struct (`ReceiptV2`), never mutation.

## 4. Enclave (`enclave/`)

Single Rust binary crate, edition 2024, modeled on `an internal sibling project/enclave`:
axum 0.8, tokio; `nautilus`/`nautilus-nsm` pinned by git rev to `unconfirmedlabs/nautilus-rust`;
`/dev/nsm` boot switch (NsmAttestor vs `NautilusContext::development()`); `unsafe_code = "forbid"`;
concurrency bounded by semaphore.

**Client API surface** (per provider-apis brief): OpenAI-compatible
`POST /v1/chat/completions` (primary) + native Anthropic passthrough `POST /v1/messages`
(avoids lossy translation of thinking blocks / cache_control). Both canonicalize into ONE
internal request/response schema before hashing, so the same logical request yields the same
`request_hash` regardless of entry surface. Plus `GET /attestation`, `GET /health_check`,
`GET /receipts/:id` (x-receipt-id header on every response; in-memory ring buffer store, no disk).

**Provider adapters**: anthropic, openai-compatible (covers OpenRouter/DeepSeek/self-hosted).
Streaming: accumulate SSE deltas into the assembled-response structure, hash that; mid-stream
refusals/errors still produce receipts with the right `outcome`.

**Policy engine**: onara's compiled-matcher design (JSON policies → Zod-equivalent
serde validation at boot → precompiled matchers, deny-first then allow-first-match). Rules v1:
allowed models/providers per caller key, max tokens, request-size caps. The canonical JSON config
is SHA-256'd → `config_hash` in every Receipt.

**Caller auth** (gap onara doesn't cover): bearer API keys, delivered at boot, constant-time
compared. v1 keeps it simple; capability-object auth is a later extension.

**Secrets/config**: NOT baked into the EIF (would break third-party reproducibility and put keys
in the measured image). Delivered by **argonaut's one-shot boot config over VSOCK:7777**
(provider API keys, caller keys, policy JSON). Key rotation ⇒ enclave restart ⇒ re-register
(cheap, scripted). Seal two-phase key load is a documented future option, not v1.
Outbound HTTPS restricted to provider domains via allowlist forwarder (in-image, so allowlist
changes are PCR-visible — that's a feature).

## 5. Reproducible build + verification

`Containerfile.eif` + Makefile copied from the the sibling project pattern (StageX digest-pinned,
static musl, `SOURCE_DATE_EPOCH=0`, `--reproducible` cpio, `rewrite-timestamp=true`,
`eif_build` → `out/nitro.eif` + `out/nitro.pcrs`). **No build args carrying secrets.**

Verbs (Makefile + bun scripts, CLI-crate later if warranted):
`make eif` / `make run-eif` / `make check`; `bun scripts/register_enclave.ts` (PTB:
`load_nitro_attestation` → `checkpoint::register`); `bun scripts/verify_deployment.ts <url>`
— fetches `/attestation`, checks PCRs against a git tag's published `nitro.pcrs` and the onchain
Checkpoint. That script is the product's whole pitch executable in one command.

CI (GitHub Actions): rust fmt/clippy/test, `sui move test`, TS tests, and a
**reproducibility job** that builds the EIF twice and diffs `nitro.pcrs` (argonaut has precedent
for CI here).

## 6. SDK (`sdk/`)

`@miraicloud/sekisho`, `type: module`, plain tsc dual-tsconfig build, `@mysten/sui` as
peerDependency, `$extend`-pattern registration like `@unconfirmed/onara`. Features: call gateway
(both surfaces), client-side Receipt verification (recompute hashes + Ed25519 check against onchain
Gateway pk), PTB builder for submitting a Receipt to a consuming contract. bun:test, offline.

## 7. Explicit non-goals (v1)

In-enclave model inference (CPU-only Nitro; router pattern only) · zkTLS · Marlin Oyster (AWS
first; Oyster once Seal/Oyster matures) · persistent receipt storage (client/Walrus-side concern)
· payments/metering onchain (later; onara composes) · prompt privacy from the provider (out of
scope by definition of relay).

## 8. Known risks

Nautilus template churn (pin template-derived files to a noted upstream commit) · PCR parsing
changed across Sui protocol versions ~74→113 (test against current mainnet) · replay: Receipt has
no consumer-side nonce — consuming contracts must dedupe by `receipt_id` (documented, and
`receipt::verify` exposes `receipt_id` for that purpose) · enclave reboot = new key (runbook).
