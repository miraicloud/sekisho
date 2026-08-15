# Sekisho

A framework for **verifiable attestation of LLM request/response exchanges**, built on
[Sui Nautilus](https://docs.sui.io/guides/developer/nautilus). Sekisho runs inside an AWS Nitro
Enclave, relays requests to LLM providers, and signs a **Receipt** that any Sui Move contract can
verify. (The name comes from the Edo-period checkpoint stations that inspected travelers' papers.)

It answers a question a smart contract otherwise cannot ask: *what exactly was sent to a model,
what exactly came back, and was it relayed by code I can rebuild myself?*

**What a Receipt proves:** this exact request left an enclave running exactly this open-source
code, under exactly this policy, over a TLS channel to a server presenting this certificate for
this hostname — and this exact response came back.

**What it does not prove:** that the provider ran the model it named. Providers don't sign their
responses, so the chain of custody ends at their TLS termination. Sekisho attests faithful
*relay*, not honest *inference* — and says so rather than blurring the line.

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
  PCR0 is the value that binds the image; with Nautilus's single-ramdisk layout PCR1 mirrors it
  and PCR2 is a constant, so never review an approved entry on PCR2 alone — see
  [`docs/SPEC.md`](docs/SPEC.md), "What the PCRs actually measure".
- **No secrets in the image.** Provider credentials arrive at boot over VSOCK
  ([argonaut](https://github.com/unconfirmedlabs/argonaut)); provider URLs are compile-time
  constants, so no configuration can redirect the gateway to an impostor endpoint — and the set of
  reachable providers is therefore fixed at build time and measured into PCR0.
- **Content-addressed commitments.** Request and response commitments are
  [Walrus](https://walrus.xyz) blob IDs, computed locally from the canonical bytes. A blob ID both
  commits to content and addresses it, so a receipt is archival-ready whether or not anyone has
  paid to store the blob.

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

## Reading a certificate

`app/` is a static terminal: type `verify <digest>` and it decodes the `ReceiptVerified` event
from its canonical BCS, cross-checks the gateway and code version against live chain state, and
prints what the transaction actually proves as pass/fail checks — alongside an explicit statement
of what it doesn't. `example` inspects a real attested Claude call; `help` lists the rest.

```bash
cd app && bun install && bun run dev
```

It talks to a public Sui fullnode directly over gRPC, so there is no backend to run or trust.

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
| `app/` | Certificate viewer — look up a transaction, see what it proves |
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

Proven end to end on real hardware and Sui testnet: reproducible build → Nitro enclave → AWS
attestation → onchain registration → a receipt verified in a transaction (and a tampered receipt
correctly rejected). See [`docs/testnet-demo.md`](docs/testnet-demo.md) for object ids,
transaction digests, and the four bugs that run exposed.

Not audited, and not yet exercised against a live model provider. The Nautilus enclave template it
builds on is itself explicitly pre-audit.

## License

Apache-2.0.
