# Sekisho

Attested AI gateway for [Sui Nautilus](https://docs.sui.io/guides/developer/nautilus). Sekisho
runs inside an AWS Nitro Enclave, relays requests to LLM providers, and signs an inference
**Receipt** that any Sui Move contract can verify. (The name comes from the Edo-period checkpoint
stations that inspected travelers' papers.)

It answers a question a smart contract otherwise cannot ask: *did this AI output really come from
the model it claims, through code I can audit?*

## How it works

```
client ──► enclave gateway (attested code, PCR-measured) ──► LLM provider
                │
                └─► signed Receipt: hashes of {policy config, client request,
                    upstream request, model, response} + usage + outcome
                         │
                         └─► verified onchain against the Checkpoint registry (Sui)
```

- **Verify once, sign cheap.** The AWS Nitro attestation is verified onchain a single time at
  registration (`sui::nitro_attestation`, ~2.5M gas units); every receipt after that is one
  Ed25519 check.
- **Permissionless operators.** Anyone running the exact published code — matching PCR0/1/2 — can
  register their own gateway. Governance approves and revokes *code versions*, not operators, so
  receipts from every deployment verify against one shared registry.
- **Reproducible builds.** Deterministic StageX EIF builds mean a third party can rebuild from a
  git tag and confirm the PCRs match what a live enclave attests and what the chain approved.
- **No secrets in the image.** Provider credentials arrive at boot over VSOCK
  ([argonaut](https://github.com/unconfirmedlabs/argonaut)); provider URLs are compile-time
  constants, so no configuration can redirect the gateway to an impostor endpoint.

## What a Receipt proves — and what it doesn't

> An enclave running exactly this open-source code, under exactly this policy, forwarded exactly
> this request to exactly this model and returned exactly this response, at this time.

It does **not** prove the model answered truthfully — the provider is still trusted for content.
Sekisho attests faithful *relay*, not truthful *inference*. Consuming contracts must also dedupe
by `receipt_id` (receipts are replayable by design) and treat the enclave timestamp as advisory.
See [`docs/SPEC.md`](docs/SPEC.md) §6a before integrating.

## Quick start

Run the whole loop locally — no AWS, no API key, no network:

```bash
bun scripts/e2e_demo.ts
```

It boots the gateway in development mode, sends a request the policy forbids (which produces a
signed receipt without contacting any provider), verifies the enclave's signature with the SDK,
confirms tampering breaks it, and builds the on-chain verification PTB.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/v1/chat/completions` | OpenAI-compatible surface (also covers OpenRouter, DeepSeek, self-hosted) |
| `POST` | `/v1/messages` | Anthropic-native passthrough — avoids lossy translation of thinking blocks and `cache_control` |
| `GET` | `/attestation` | Attestation document + signing public key, for third-party verification |
| `POST` | `/attestation` | Nonce-bound attestation, required for onchain registration |
| `GET` | `/receipts/:id` | The receipt for a request (`x-receipt-id` header on every response) |
| `GET` | `/health_check` | Enclave identity and liveness |

Every inference response yields a receipt — including refusals (which providers return as HTTP
200) and upstream failures, each with a distinct `outcome` code.

## Deploying

```bash
cd enclave && make eif          # reproducible EIF build -> out/nitro.pcrs
make run-eif && make expose     # boot it on a Nitro host, expose port 3000
scripts/send_boot_config.sh …   # deliver credentials + policy over VSOCK:7778
bun scripts/register_enclave.ts # attest (nonce-bound) and register onchain
```

Step-by-step runbooks, including failure modes, live in
[`.claude/skills/register-enclave.md`](.claude/skills/register-enclave.md) and
[`.claude/skills/rotate-keys.md`](.claude/skills/rotate-keys.md).

## Verifying someone else's deployment

This is the whole point, in one command:

```bash
bun scripts/verify_deployment.ts https://gateway.example.com --ref v0.1.0 \
  --checkpoint 0x… --gateway 0x… --network testnet
```

It fetches the live attestation, compares its PCRs against a local reproducible build of that git
ref, and confirms the chain has those PCRs approved, not revoked, and bound to the gateway's key.
Each check reports PASS or FAIL independently.

## Layout

| Path | Purpose |
|---|---|
| `move/` | Move package: `Checkpoint` registry + `Receipt` verification |
| `enclave/` | Rust gateway (axum), reproducible EIF build |
| `sdk/` | `@miraicloud/sekisho` — client, receipt verification, PTB helpers |
| `scripts/` | Register, verify a deployment, end-to-end demo |
| `docs/` | [Spec](docs/SPEC.md), BCS test vectors, research briefs |

## Development

```bash
cd enclave && make check   # cargo fmt --check, clippy -D warnings, cargo test
cd move    && sui move test
cd sdk     && bun test && bun run build
bun scripts/verify_vectors.ts # receipt bytes still match the pinned vectors
```

`docs/receipt-v1-vectors.json` is the contract between the three implementations: Move, Rust, and
TypeScript each serialize a receipt independently, and all three must reproduce those bytes
exactly. Change the layout and all three test suites fail together — which is the point.

## Status

Working and tested end to end, not yet deployed to a network or audited. The Nautilus enclave
template it builds on is itself explicitly pre-audit.

## License

Apache-2.0.
