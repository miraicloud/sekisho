# Enclave Registration Skill

Use this skill to boot a sekisho enclave and register (or re-register) it on-chain via
`sekisho::checkpoint`. Style and troubleshooting format follow
an internal sibling project's equivalent runbook; the flow itself differs because
sekisho's registration is **permissionless** (no admin cap gates it) and **nonce-bound** (the
attestation must be fetched for the specific address that will submit it).

## Overview

Unlike a cap-gated registry, `sekisho::checkpoint::register` lets *any* address register a Gateway
as long as the enclave's attestation PCRs match a `PcrSet` that a `CheckpointCap` holder has
already approved and hasn't revoked (docs/SPEC.md sec 3). That means there are two people in this
flow who may not be the same person:

- **Governance** (holds `CheckpointCap`): approves a `PcrSet` for a given code version ahead of
  time. If you're just running the published code, you don't need this cap -- someone already
  did this step. If your PCRs aren't approved yet, registration will abort; see Troubleshooting.
- **Operator** (you, running this runbook): boots the enclave, exposes it, and registers it under
  your own address. No cap needed.

The end-to-end sequence:

1. Boot the EIF on a Nitro host.
2. Expose it (argonaut host-side bridges).
3. Push sekisho's application boot config (provider API keys, caller keys, policy) -- the gateway
   process doesn't start, and `/attestation` isn't reachable, until this lands.
4. Register: fetch a nonce-bound attestation and submit the PTB.

## Current Deployment IDs

These may change on republish. Verify via GraphQL or `sui client object <id>` if stale.

| Object | ID |
|--------|-----|
| Sekisho Package | `$SEKISHO_PACKAGE` (unset -- fill in after `move/` is published) |
| Checkpoint (shared) | `$CHECKPOINT_OBJECT` (unset -- fill in after `move/` is published) |

## Step 1: Boot the Enclave

```bash
make -C enclave eif        # builds out/nitro.eif, out/nitro.pcrs, out/argonaut-host
make -C enclave run-eif    # nitro-cli run-enclave
```

`out/nitro.pcrs` is what governance approves via `CheckpointCap`-gated `add` on the Checkpoint --
if this is a new code version, get that landed before continuing, or registration will abort.

## Step 2: Expose the Enclave

```bash
make -C enclave expose
```

This runs `scripts/expose_enclave.sh`, which starts `argonaut host <cid> enclave/eif/bridge-config.json`
in the foreground -- backgrounds itself with `&` if you want your shell back. It bridges inbound
HTTP (host `:3000` -> enclave) and outbound HTTPS for the provider allowlist baked into the image.
This step also (as a side effect of how `argonaut host` works) unblocks the enclave's own boot
sequence past its first VSOCK:7777 listen -- see `enclave/eif/run.sh` for why that's a separate,
discarded handshake from the boot config in Step 3.

## Step 3: Push Boot Config

The gateway does not start -- and `/attestation`, `/health_check` etc. are not reachable -- until
this lands:

```bash
scripts/send_boot_config.sh path/to/boot-config.json
```

Confirm it's up:

```bash
curl http://<host>:3000/health_check
```

## Step 4: Register On-Chain

```bash
SEKISHO_PACKAGE=0x... \
CHECKPOINT_OBJECT=0x... \
GATEWAY_URL=http://<host>:3000 \
bun scripts/register_enclave.ts
```

Add `--dry-run` to preview the transaction without submitting it.

This script:

1. Reads `sui client active-address` -- this is the address the attestation will be bound to,
   and the address that must submit the PTB (they must match).
2. Computes `nonce = BCS(active_address)` and requests `POST /attestation` with that nonce --
   **not** `GET /attestation`. An unbound (`GET`) attestation is a bearer token: anyone who fetches
   it could register it under their own address first. Nonce-binding closes that (docs/SPEC.md sec 3).
3. Sanity-checks the response locally (public key present, nonce echoed back correctly).
4. Submits the PTB:
   ```
   0x2::nitro_attestation::load_nitro_attestation(attestation_bytes, @0x6)
   -> sekisho::checkpoint::register(checkpoint, doc)
   ```
   `register` shares the resulting `Gateway` object itself; no separate `share` call.

On success, note the new `Gateway` object id from the transaction output -- you'll want it for
`scripts/verify_deployment.ts --gateway <id>` and for `rotate-keys.md`.

## Troubleshooting

- **`ENonceNotSender`**: the attestation's `nonce` field didn't equal `BCS(ctx.sender())` at
  execution time. Causes: you fetched the attestation with `GET` instead of `POST` (no nonce at
  all); you switched `sui client active-address` between fetching the attestation and submitting
  the PTB; you reused a stale attestation fetched for a different address. Fix: just re-run
  `bun scripts/register_enclave.ts` -- it always binds the nonce to the *current* active address
  and fetches fresh.
- **`EMissingPublicKey`** (or similar -- exact code depends on `sekisho::checkpoint`'s error
  constants): the attestation document's `public_key` field was empty. This should not happen with
  a `POST /attestation` response from a healthy gateway (the enclave always binds its own ephemeral
  key into the attestation request); if it does, check the gateway's logs -- this points at a bug
  in the enclave's attestation-request construction, not something fixable from this runbook.
- **PCR mismatch / "no approved PcrSet" abort**: your `out/nitro.pcrs` (or the running enclave's
  measured PCRs) doesn't match any non-revoked `PcrSet` on the Checkpoint. Either you're running
  unreleased/modified code that hasn't been approved, or governance revoked the version you're on.
  Compare directly: `bun scripts/verify_deployment.ts <gateway-url> --ref <ref> --checkpoint $CHECKPOINT_OBJECT`.
- **Reboot ⇒ new key ⇒ re-register**: the enclave generates a fresh ephemeral Ed25519 keypair on
  every boot (Nautilus `NautilusContext`). Any restart -- including one to rotate boot config, see
  `rotate-keys.md` -- invalidates the previous `Gateway`'s association with a *live* signer (the
  old `Gateway` object still exists on-chain but nothing will ever sign with its `pk` again). You
  must run Step 4 again after every restart, and should destroy the stale `Gateway` (see
  `rotate-keys.md`).
- **Timeout / out of gas**: `load_nitro_attestation` is an expensive native call (see
  docs/research/nautilus.md sec 3 for exact gas costs). Use `--gas-budget 100000000` or higher if
  you've customized the script.
- **Enclave not reachable**: confirm the EC2 host is up, `make -C enclave expose` is running, and
  boot config has been pushed (`curl http://<host>:3000/health_check`). If `/health_check` hangs,
  the gateway process hasn't started yet -- it's still blocked on Step 3.
