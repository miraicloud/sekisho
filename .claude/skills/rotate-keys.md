# Key Rotation Skill

Use this skill when rotating provider API keys, caller bearer keys, or policy config for a running
sekisho enclave -- or when responding to a suspected key compromise.

## Why rotation means a restart

Sekisho's boot config (provider API keys, caller bearer keys, policy JSON) is delivered exactly
once, over a one-shot VSOCK channel, at enclave boot (docs/SPEC.md sec 4; `enclave/eif/run.sh`).
There is no live "push new config" endpoint by design -- baking in a mutable config channel that
the running process re-reads would mean the `config_hash` committed into every `Receipt` no longer
pins down what the enclave was actually doing at signing time. So: **to change any secret or
policy value, you restart the enclave with a new boot config.** There is no partial-rotation path.

A restart has a side effect that matters here: the enclave's ephemeral Ed25519 signing key is
generated fresh by `NautilusContext` on every boot. A new process means a new key, which means the
previously-registered `Gateway` object no longer corresponds to anything that will ever sign a
receipt again. Rotation is therefore always: **restart → re-register → destroy the old Gateway.**

## Step 1: Stop the Old Enclave

```bash
make -C enclave stop   # nitro-cli terminate-enclave --all
```

If you're rotating in response to a *suspected compromise* rather than routine hygiene, do this
first, before anything else -- don't wait for a clean handoff.

## Step 2: Boot With New Config

```bash
make -C enclave run-eif      # same EIF, same PCRs, new process -> new ephemeral key
make -C enclave expose       # re-establish the argonaut bridges (see register-enclave.md step 2)
scripts/send_boot_config.sh path/to/new-boot-config.json
```

If you are *only* rotating secrets (not code), you do not need `make -C enclave eif` again --
the EIF and its PCRs are unchanged, so no new `PcrSet` approval is needed. If you are also shipping
a code change, treat this as a fresh deployment: rebuild, get the new PCRs approved by whoever
holds `CheckpointCap`, then continue here.

Confirm the new process is up and has a different key than before:

```bash
curl http://<host>:3000/health_check   # compare `pk` against the old Gateway's pk
```

## Step 3: Re-Register

```bash
SEKISHO_PACKAGE=0x... \
CHECKPOINT_OBJECT=0x... \
GATEWAY_URL=http://<host>:3000 \
bun scripts/register_enclave.ts
```

See `register-enclave.md` for the full flow and troubleshooting (nonce binding, `ENonceNotSender`,
etc.). Note the new `Gateway` object id from the output.

## Step 4: Destroy the Old Gateway

The old `Gateway` object is now stale: its `pk` will never sign anything again, since that ephemeral
key only ever existed in the terminated enclave process's memory. Anyone who still trusts it is
trusting a dead key, so retire it rather than leaving it shared on-chain indefinitely.

The exact entry function lives in `sekisho::checkpoint` (check `move/sources/checkpoint.move`) --
as of this writing it is expected to be gated on `gateway.operator == ctx.sender()`, i.e. only the
operator who registered a `Gateway` can destroy it. Something like:

```bash
sui client call \
  --package $SEKISHO_PACKAGE --module checkpoint --function destroy_gateway \
  --args $OLD_GATEWAY_OBJECT \
  --gas-budget 20000000
```

If no such function exists yet, treat that as a gap to raise against `move/`: a permissionless
registry that never lets stale entries be cleaned up accumulates dead `Gateway` objects forever.

## Compromise Response Checklist

If rotation is happening because a provider key or caller key leaked (not routine hygiene):

1. **Stop first** (Step 1) -- don't wait for a graceful handoff.
2. Revoke/rotate the leaked credential **at the provider** (Anthropic/OpenAI/OpenRouter dashboard)
   as well as in your new boot config -- restarting sekisho alone does not invalidate a leaked
   upstream API key.
3. If the leak might also have exposed the enclave's *code* to tampering (not just config -- e.g.
   you suspect the running EIF wasn't the one you think it was), don't just restart: verify first
   with `bun scripts/verify_deployment.ts <gateway-url> --ref <ref> --checkpoint $CHECKPOINT_OBJECT`
   before trusting anything it reports post-restart.
4. Complete Steps 2-4 above.
5. If the compromise implicates the *code version itself* (not just leaked secrets), that's a
   revocation, not a rotation: ask whoever holds `CheckpointCap` to revoke the affected `PcrSet` so
   no enclave running that code can register (or stay registered) going forward.
