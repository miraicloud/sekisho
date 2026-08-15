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
| `Gateway` (shared) | `0x2f415a0f81bc37ee0a03debedad8ef8126f956d2a2755a6f57db4b87c56e1ec3` |
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

Still not covered: a live provider call (needs a key), and a second independent build to confirm
PCR reproducibility.
