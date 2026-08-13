# Sekisho

Attested AI gateway for [Sui Nautilus](https://docs.sui.io/guides/developer/nautilus). Sekisho
runs inside an AWS Nitro Enclave, relays requests to LLM providers (Anthropic, OpenAI-compatible),
and signs an inference **Receipt** that any Sui Move contract can verify. (The name comes from
the Edo-period checkpoint stations that inspected travelers' papers.)

## How it works

```
client ──► enclave gateway (attested code, PCR-measured) ──► LLM provider
                │
                └─► signed Receipt: {config, request, upstream request,
                    model, response, usage, outcome} hashes
                         │
                         └─► verified onchain against the Checkpoint registry (Sui)
```

- **Verify once, sign cheap**: the AWS Nitro attestation is verified onchain a single time at
  registration (`sui::nitro_attestation`); every receipt thereafter is one Ed25519 check.
- **Permissionless operators**: anyone running the exact published code (matching PCRs) can
  register their enclave on the shared `Checkpoint` registry — no gatekeeping cap. Governance
  only approves/revokes code versions.
- **Reproducible builds**: StageX deterministic EIF builds; `verify_deployment` rebuilds from a
  git tag and diffs PCRs against a live enclave and the onchain registry.
- **No secrets in the image**: provider keys and policy arrive via one-shot VSOCK boot config
  ([argonaut](https://github.com/unconfirmedlabs/argonaut)); the policy's hash is in every receipt.

## Status

Pre-release scaffold. See `docs/SPEC.md` (design) and `tasks/todo.md` (build plan).

## Layout

| Path | Purpose |
|---|---|
| `move/` | Move package: `Checkpoint` registry + `Receipt` verification |
| `enclave/` | Rust gateway (axum, Nautilus enclave app) |
| `sdk/` | `@miraicloud/sekisho` TypeScript SDK |
| `scripts/` | register / verify deployment scripts (Bun) |
| `docs/` | Spec, BCS test vectors, research briefs |

## License

Apache-2.0.
