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
    Attestation parsed/verified in the same PTB via `0x2::nitro_attestation::load_nitro_attestation`
    (an `entry fun` — Move cannot call it; the document arrives by value from a prior PTB command).
  - **Registration binding (required)**: attestation documents are served publicly at
    `GET /attestation`, so a bare document is a bearer token — anyone could register someone
    else's enclave, claim `operator`, then `destroy_gateway` it (denial of service), or spam
    duplicate Gateways. So `register` asserts `document.nonce()` equals the BCS bytes of
    `ctx.sender()`: the operator requests an attestation bound to their own address
    (`POST /attestation` with a nonce) and registration from any other sender aborts
    (`ENonceNotSender`). `registered_at_ms` comes from `document.timestamp()`, never from a
    caller argument.
  - Reboot ⇒ new ephemeral key ⇒ re-register (documented runbook; old Gateway destroyable by
    operator).
- `sekisho::receipt` — receipt verification:
  - `Receipt` payload struct (below), `RECEIPT_INTENT: u8 = 0`.
  - `verify(gateway: &Gateway, checkpoint: &Checkpoint, timestamp_ms, payload, sig)` — aborts
    unless sig valid (Ed25519 over BCS `IntentMessage`) AND the gateway's PCR version is not
    revoked. Returns a hot-potato-free witness struct callers can consume.
  - Inline `#[test]`s including **`test_bcs_parity` with exact byte offsets** (house pattern from
    an internal sibling project — non-negotiable guard against Rust/Move drift).

### Receipt (BCS, field order is normative)

| field | type | notes |
|---|---|---|
| `receipt_id` | `vector<u8>` (16) | **uniqueness nonce, not the receipt's identity** — see below. Client-settable via `x-sekisho-nonce`; otherwise a random v4 UUID |
| `config_hash` | `vector<u8>` (32) | SHA-256 of canonical policy JSON — policy only, never secrets |
| `provider` | `u8` | 0 = anthropic, 1 = openai-compatible |
| `endpoint_host` | `String` | TLS hostname actually validated during the upstream handshake |
| `tls_cert_sha256` | `vector<u8>` (32) | SHA-256 of the upstream server's leaf certificate (DER). Binds the counterparty cryptographically rather than by assertion |
| `request_blob` | `u256` | Walrus blob ID of the canonical client request |
| `upstream_request_blob` | `u256` | Walrus blob ID of the canonical upstream request (captures gateway transforms) |
| `upstream_headers_hash` | `vector<u8>` (32) | SHA-256 of canonical upstream request headers — proves ZDR/no-training headers were actually set |
| `model_id` | `String` | served model, read off the response, never the request |
| `provider_request_id` | `String` | provider's own id (Anthropic `id` / `request-id`); empty when absent |
| `response_blob` | `u256` | Walrus blob ID of the canonical assembled response (streamed deltas accumulated first — never raw SSE bytes) |
| `provider_meta_hash` | `vector<u8>` (32) | SHA-256 of a canonical provider-specific blob (`stop_reason`, `service_tier`, `inference_geo`, …) |
| `input_tokens` / `cache_creation_tokens` / `cache_read_tokens` / `output_tokens` | `u64` | provider-reported usage, kept separate so billing detail survives |
| `outcome` | `u8` | 0=ok, 1=refusal (HTTP 200 refusals still get receipts), 2=upstream_error, 3=policy_denied |

Envelope: `IntentMessage<Receipt> { intent: RECEIPT_INTENT (0), timestamp_ms, payload }`,
BCS-serialized and Ed25519-signed. The intent byte is a domain separator — it stops a receipt
signature being replayable as another message type — and doubles as the version escape hatch if an
incompatible schema is ever needed after launch. There is no `V1`/`V2` in any type name; the
schema simply changes until there are users.

**Blob IDs are the content commitments.** A Walrus blob ID is derived from the content (encoding
tag + unencoded length + Merkle root over the slivers), so it commits to the bytes exactly as a
hash would, while additionally addressing them. It is computed locally with `walrus-core`, so
`0` means "computed but not archived" — a receipt never depends on a storage write succeeding.
Blobs only, never quilts: a quilt patch is identified by its quilt and offsets rather than by its
content, so it would not be a commitment.

**`receipt_id` is a nonce, and the signature is the identity.** The signature is unique per
signed payload, unforgeable, and bound to a registered enclave key; `receipt_id` is a 16-byte
value the enclave (or the client) chooses. Do not index or dedupe on `receipt_id` alone —
registration is permissionless, so a hostile operator can replay another gateway's value, and it
carries no cross-gateway uniqueness guarantee.

What the nonce is actually for: without it, two byte-identical exchanges — same prompt, same
response, same usage, same millisecond — serialize to identical signed payloads and therefore
collapse into a single receipt, silently undercounting paid calls. A client may set it via the
`x-sekisho-nonce` header (32 hex characters). Because it is covered by the signature, a
client-chosen nonce also proves *which* of the caller's own calls a receipt belongs to, and
supplies the idempotency key neither Anthropic nor OpenAI offers. Malformed values are rejected
rather than padded, since a silently altered nonce would defeat the purpose.

**Trust boundary.** A receipt proves what request left the enclave, which TLS peer answered, and
what came back. It cannot prove the provider ran the model it named — providers do not sign
responses, so the chain of custody ends at their TLS termination. Anything stronger needs
provider-signed responses or zkTLS.

## 4. Enclave (`enclave/`)

Single Rust binary crate, edition 2024, modeled on an internal sibling Nautilus project:
axum 0.8, tokio; `nautilus`/`nautilus-nsm` pinned by git rev to `unconfirmedlabs/nautilus-rust`;
`/dev/nsm` boot switch (NsmAttestor vs `NautilusContext::development()`); `unsafe_code = "forbid"`;
concurrency bounded by semaphore.

**Client API surface** (per provider-apis brief): OpenAI-compatible
`POST /v1/chat/completions` (primary) + native Anthropic passthrough `POST /v1/messages`
(avoids lossy translation of thinking blocks / cache_control). Both canonicalize into ONE
internal request/response schema before hashing, so the same logical request yields the same
`request_hash` regardless of entry surface. Plus `GET /attestation` (no nonce — for third-party
verification), `POST /attestation` (body `{ nonce: hex }`, passed through to the NSM attestation
request — required by the sender-bound registration flow in §3), `GET /health_check`,
`GET /receipts/:id` (x-receipt-id header on every response; in-memory ring buffer store, no disk).

**Provider adapters**: anthropic, openai-compatible (covers OpenRouter/DeepSeek/self-hosted).
Streaming: accumulate SSE deltas into the assembled-response structure, hash that; mid-stream
refusals/errors still produce receipts with the right `outcome`.

**Provider endpoints are compile-time constants, never config** (load-bearing security property):
base URLs for each provider are `const` in the source and therefore covered by PCR0. If they came
from boot config, an operator could point the "anthropic" adapter at a server they control and
still emit receipts that verify onchain — the attested-relay claim would be worthless. Boot config
supplies *credentials only*. The outbound HTTPS allowlist is likewise in-image, so any change to
reachable hosts shows up as a PCR change.

**Policy engine**: onara's compiled-matcher design (JSON policies → Zod-equivalent
serde validation at boot → precompiled matchers, deny-first then allow-first-match). Rules v1:
allowed models/providers per caller key, max tokens, request-size caps. `config_hash` = SHA-256
of the canonical policy JSON **excluding all secrets**, so key rotation doesn't change the
attested policy identity (and no secret is ever hash-committed).

**Caller auth** (gap onara doesn't cover): bearer API keys, delivered at boot, constant-time
compared. v1 keeps it simple; capability-object auth is a later extension.

**Secrets/config**: NOT baked into the EIF (would break third-party reproducibility and put keys
in the measured image). Delivered by **argonaut's one-shot boot config over VSOCK:7777**
(provider API keys, caller keys, policy JSON). Key rotation ⇒ enclave restart ⇒ re-register
(cheap, scripted). Seal two-phase key load is a documented future option, not v1.
Outbound HTTPS restricted to provider domains via allowlist forwarder (in-image, so allowlist
changes are PCR-visible — that's a feature).

### What the PCRs actually measure (verified on hardware, 2026-08-15)

Nautilus's `eif_build` invocation passes a **single** `--ramdisk`. AWS treats the first ramdisk as
the *bootstrap* ramdisk and any later ones as *application* ramdisks, so with one ramdisk there is
no application layer to measure. Two consequences, both confirmed against real builds of three
different projects (sekisho, an internal sibling project, and nautilus-rust):

- **PCR0 == PCR1.** With a single ramdisk the whole-image and kernel+bootstrap measurements
  coincide. Not a bug; expected for this build layout.
- **PCR2 is a constant** — byte-identical across all three unrelated applications
  (`21b9efbc…fc500a`). It carries no information about the code being run.

So **PCR0 is the measurement that binds the application**: it covers the kernel, the cmdline, and
the ramdisk containing the enclave binary, `run.sh`, and `bridge-config.json`. Anywhere this spec
says a baked-in artifact is "PCR-measured", the binding is PCR0.

This does not weaken registration: `checkpoint::register` requires all three PCRs to match an
approved entry, and PCR0 alone is sufficient to pin the exact image. It does mean an approved-PCR
entry must never be reviewed on PCR2 alone, and that a future switch to a multi-ramdisk layout
would change PCR0/1 semantics and require re-approval.

## 5. Reproducible build + verification

`Containerfile.eif` + Makefile copied from an internal sibling project's pattern (StageX digest-pinned,
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

## 6a. Guidance for consuming contracts

A verified receipt proves *a registered enclave relayed this exact request and returned this exact
response*. It does not prove more than that, so consumers must handle four things themselves:

1. **Replay** — `verify` is pure; the same receipt verifies forever. Dedupe before acting on one,
   keyed on the **signature** (unique per signed payload and unforgeable), or failing that on the
   pair `(gateway, receipt_id)`. Never on `receipt_id` alone: it is an enclave- or client-chosen
   nonce with no cross-gateway uniqueness, and permissionless registration means another operator
   can emit the same value.
2. **Request uniqueness** — two callers sending byte-identical requests produce identical
   `request_hash`. If your contract needs "*this* user asked", have the client include a nonce or
   their address in the request body so the hash is unique to them, then recompute and compare.
3. **Timestamps** — `timestamp_ms` is the enclave's clock, which derives from its host and is not
   consensus time. Treat it as advisory: gate freshness against Sui's `Clock` at submission
   (e.g. reject receipts older than N minutes) rather than trusting the value itself.
4. **Content trust** — the provider is still trusted for what the model actually said. The receipt
   attests faithful relay, not truthful inference.
5. **Hashes are commitments, not client-recomputable (v1)** — the gateway hashes its *normalized
   internal* representation of a request/response, not the JSON body on the wire, so hashing a raw
   body locally will not reproduce `request_hash`. What a client verifies is the **signature**,
   which covers every receipt field and proves the enclave committed to those hashes; combined with
   PCR-verified code, that is the guarantee. Making hashes independently recomputable would require
   the enclave to publish its canonical form (a candidate for v2, with privacy and memory costs).
   The SDK's `hashJson` is a general-purpose helper and is documented not to reproduce receipt
   hashes.

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
