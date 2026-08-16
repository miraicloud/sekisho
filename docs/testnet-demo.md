# Testnet demo — end-to-end run on real Nitro hardware

First full execution of the chain the project claims: reproducible build → real enclave →
AWS attestation → onchain registration → receipt verified in a transaction. Run 2026-08-15
against Sui testnet from an AWS Nitro host (`c6a.2xlarge`, us-west-1).

## Deployed artifacts

| What | Id |
|---|---|
| Package | `0x9faf9346322288c86409e26968fefc77bb6aef1e28075e046e227d092fe56413` |
| `Checkpoint` (shared) | `0x5482976d7cd08bd69504dee612883260450e393828e4f634a115ccb504544194` |
| `CheckpointCap` | `0xb0564c76b78cd08740eb0037e83ee752c4c0a968882bd34c4f9cfbbc65f79901` |
| `Gateway` (shared, current) | `0xd9b1557d337995c68b31e24893a047741b1feffa65d8a99b283a0b48f841f4ab` |
| `Gateway` (first registration, destroyed after key rotation) | `0x2f415a0f81bc37ee0a03debedad8ef8126f956d2a2755a6f57db4b87c56e1ec3` |
| Publisher / operator | `0xd4fdadb380cac4f7c3604caab013d5572e0a062dbb12770ca43c235c250da2b1` |

Enclave measurements (from `make eif`, and identical inside the live attestation document):

```
PCR0 a127eba6dc7a010f6cd9500b913f011655df91d99aad8060fedd8540fa673bb2171908afb797ac204c1399bc4b9fb002
PCR1 a127eba6dc7a010f6cd9500b913f011655df91d99aad8060fedd8540fa673bb2171908afb797ac204c1399bc4b9fb002
PCR2 21b9efbc184807662e966d34f390821309eeac6802309798826296bf3e8bec7c10edb30948c90ba67310f7b964fc500a
```

Enclave signing key (NSM-attested, ephemeral):
`9e80b88f7c32189ba7f7ae6b65dce16c060abbd58bd7ffa2b2f643cd8c4fe427`

## Transactions

| Step | Digest |
|---|---|
| Publish package | `5jp6gNZ6…` (approve tx below shares the Checkpoint from `init`) |
| `approve_pcrs` | `5jp6gNZ6NNmmMaYsfovxBedtxgrd5vxrGUacKRedGbwQ` |
| `register` (nonce-bound attestation) | `4TwWGAY3YEvtBZk2JiGkUyVsKLqFHBx29gKJLWbr75V8` |
| `receipt::verify` (valid receipt) | `6roKbz1ySyyyJDh4TXn7GDEyBA1nHKzG5vjMHqXXJ6To` — Success |
| `receipt::verify` (tampered receipt) | `4YMYq2P9fVKVqc4NBz1rGiicPtcGn5QdK8Z18Ri3s7tJ` — **aborted, `EInvalidSignature`** |

The negative case matters as much as the positive one: flipping a single byte of the receipt
(`outcome` 3 → 0) aborts the transaction, so the onchain check is doing real work rather than
trivially succeeding.

## Verification result

```
bun scripts/verify_deployment.ts http://<host>:3000 --ref <sha> \
  --pcrs-file out/nitro.pcrs --checkpoint 0x5482…  --gateway 0x2f41… --network testnet

8 passed, 0 failed, 0 warnings, 0 skipped
```

Covering: live attestation fetched and parsed; PCR0/1/2 equal to the reproducible build; the
triple approved and not revoked onchain; the Gateway's registered pubkey equal to the live
enclave's; and the Gateway's `pcr_version` equal to the approved entry's index.

## Bugs this run found

Everything below passed unit tests and a local end-to-end run beforehand.

1. **EIF build failed** — `Containerfile.eif` pre-created `initramfs/bin`, colliding with musl's
   `/bin` symlink under BuildKit.
2. **PCR2 measures nothing** — byte-identical across three unrelated projects. Nautilus passes a
   single `--ramdisk`, so `eif_build` records no application layer; PCR0 is what binds the image
   (and PCR1 collapses to equal it). Spec claims attributing the binding to PCR2 were wrong.
3. **CBOR decoder rejected real attestations** — no support for indefinite-length maps, which is
   what AWS actually emits. It had only been tested against a synthetic definite-length document.
4. **Onchain PCR comparison was wrong** — `sui client object --json` returns `vector<u8>` as
   base64; the script assumed hex and reported no matching approved entry for a Checkpoint whose
   entry did match.

## Reproducing

The gateway ran with a policy allowing only `claude-*`, so a request for another model is denied
before any upstream call and still yields a signed receipt — which is how the whole loop is
exercised without a provider API key.

## Live provider calls

Re-run with a real Anthropic key in the boot config. Because boot config is delivered once at
enclave start, adding the key required a fresh enclave — which produced a new ephemeral key
(`9e80b88f…` → `a1eee11d…`) and therefore a re-registration, incidentally exercising the
key-rotation runbook. The superseded Gateway was then destroyed by its operator
(`EqWFvoNYP77VeCZT34nZ7YGyxZjbhqHA2VmT92aTDmP5`).

**Non-streaming** (`claude-haiku-4-5-20251001`): relayed correctly, `outcome=0`, `model_id` read
back off the response, usage 17 in / 9 out matching the provider, request and response hashes
distinct, signature verifies against the NSM-attested key, and altering the token count breaks
verification.

**Streaming**: SSE relayed through to the client (`message_start` → `content_block_delta` × N →
`message_delta` → `message_stop`, plus `ping`), with usage 16 in / 12 out taken from
`message_delta` and matching the raw stream exactly. This was the case mocks could not reach:
real providers split deltas across frames unpredictably, and the receipt hashes the assembled
response rather than raw SSE bytes.

A receipt from the real non-streaming completion then verified onchain:
`9XgYGrxUUgvc1V3Wt3b2fYKEpwc9VVu6RbqLxwNu9H4b` — Success.

`verify_deployment` against the rotated gateway reports 7 passed, 0 failed, and one **correct**
warning: the on-chain `code_ref` is `6caed16` while HEAD has moved to a later commit, because the
running enclave was built before those fixes landed. That is drift detection working, not a bug.

## Still not covered

A second independent build to confirm PCR reproducibility, and any provider other than Anthropic.


---

# Second run — attested LLM interactions with the full `Receipt` schema

Run 2026-08-15 after replacing the receipt schema with real provider and transport attestation
(TLS certificate binding, Walrus blob-id commitments, provider request id, split cache tokens).

## Deployed artifacts

| What | Id |
|---|---|
| Package | `0x9e15c768b426762b197d07e7758430984a09a8f56b9a2e99d24bc2d9567fd102` |
| `Checkpoint` (shared) | `0x14e1a8cb5aeb0b52f04ed1d05d0e8f44e75644a644acc70be1613c3fb5075553` |
| `Gateway` (shared) | `0x2f35c6bfb8b5f70cc8be469a63ab8e5d5507f4afc2e22027ef3abc3aab5c4e25` |

New enclave measurement — PCR0 changed with the code, as it must:

```
PCR0/PCR1 907900f56e4980e0751a5101b81473b237b8fd9bc7bb784faf5968d2a1ba861f6d408ce1bf3cd0accc45f158788303cf
PCR2      21b9efbc184807662e966d34f390821309eeac6802309798826296bf3e8bec7c10edb30948c90ba67310f7b964fc500a  (constant — see SPEC)
```

## The attested interaction

A real Claude call (`claude-haiku-4-5-20251001`) relayed through the enclave, verified onchain:

| Step | Digest |
|---|---|
| `approve_pcrs` | `5xYekGoT3ywVWPuPkE74Fd9N6yZYUxeZBRwTL8wV8Wf1` |
| `register` (nonce-bound) | Gateway `0x2f35c6bf…` |
| **`receipt::verify` — attested LLM interaction** | **`CEPZgWZ6R9ZyuvSbwepDEytfvfv6C4aZKLXzxCTcQs3d`** — Success · [view certificate](https://sekisho.mirai.cloud/cert/CEPZgWZ6R9ZyuvSbwepDEytfvfv6C4aZKLXzxCTcQs3d) |
| `receipt::verify` (tampered: input_tokens 13→14) | `WX4Voxyw1uTckHdrDNSi5D8NbHruShQbzQg876Mx1cR` — aborted, `EInvalidSignature` |

What the emitted `ReceiptVerified` event carried:

```
endpoint_host        api.anthropic.com
tls_cert_sha256      a0acde9e335bbe4f8153e4cbad6327cde5b4f6d907ce88f9994673818ae53e38
provider_request_id  msg_011Ce4DE3ModGgZy11WP8kej      (matches the response body id)
model_id             claude-haiku-4-5-20251001
request_blob         6833027471931826441586748218511692499256001525747483787753242714031588024153
response_blob        58159644925337159021969868184215899560621322077677401095532197927183108892067
input/output tokens  13 / 5      cache tokens 0 / 0
outcome              0 (ok)
timestamp_ms         1786782184427   (enclave)
verified_at_ms       1786782227302   (consensus)
```

`verify_deployment` against this gateway: 7 passed, 0 failed. The single warning is correct —
the on-chain `code_ref` predates the commits made after the enclave was built.

## Bugs this run found

1. **SDK could not parse blob ids off the wire.** They are hex of 32 little-endian bytes;
   `BigInt()` throws on bare hex and reads big-endian if prefixed. Added `parseBlobId`.
2. **…whose first implementation was itself wrong.** It disambiguated hex from decimal by "looks
   numeric", but a 64-char hex id can be all decimal digits — it returned 10^62 for one. Now keyed
   on the fixed wire width or an explicit prefix.


## A note on `code_ref` after the history rewrite

This repository's history was rewritten before open-sourcing, so every commit SHA changed. The
`code_ref` values recorded on the on-chain Checkpoint during these runs (`ad0ec16`, `6caed16`)
refer to commits that no longer exist here, and `verify_deployment.ts` will therefore report a
code-ref mismatch against those historical deployments.

The Sui transaction digests and object ids above are chain data and are unaffected — the
certificates still verify. Only the git-ref correlation is broken, and only for these two
pre-publication deployments. Any future deployment records a ref from the published history.
