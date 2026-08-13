# Prior Art Survey: Attested / Verifiable AI Inference Gateways
*Compiled August 2026, for an open-source attested AI gateway on Sui Nautilus that emits signed, onchain-verifiable inference receipts.*

---

## 0. The base layer this project builds on: Sui Nautilus

Before surveying competitors, note what Nautilus already gives you, since the new receipt format should be a superset of this, not a replacement.

Nautilus (AWS Nitro Enclaves, integrated with Sui) provides:

- **Attestation**: enclave calls `get_attestation`, returns an AWS Nitro attestation document signed by the Nitro hypervisor, containing PCR0 (enclave image measurement), PCR1 (kernel/boot), PCR2 (application), and the enclave's ephemeral public key.
- **Onchain registration**: `register_enclave` verifies the attestation document *once* onchain (expensive) and stores the enclave's public key + PCR triple in a shared `EnclaveConfig<phantom T>` object, admin-gated by a `Cap<T>` object. Subsequent request verification is cheap — just an Ed25519/signature check against the registered key, not a full attestation replay.
- **Message envelope** (from `move/enclave/sources/enclave.move` in `MystenLabs/nautilus`):

```move
public struct IntentMessage<T: drop> has copy, drop {
    intent: u8,          // domain-separation tag, disambiguates message types/versions
    timestamp_ms: u64,   // enclave-attested wall clock at signing time
    data: T,              // your generic payload struct
}
```
  The enclave BCS-serializes `IntentMessage<T>` and signs it with the enclave's Ed25519 key. Move verifies via the registered `Enclave<T>` public key.

**What Nautilus does NOT give you out of the box**: a schema for `T` (that's up to the app), request/response hashing conventions, model identity, config/policy hashing, sampling params, usage accounting, or upstream TLS evidence. That's exactly the gap this project's receipt format needs to fill — Nautilus supplies the *envelope and verification primitive*; the "inference receipt" is the payload design problem.

Sources: [Nautilus on Sui](https://www.sui.io/nautilus), [Nautilus docs](https://docs.sui.io/guides/developer/nautilus/using-nautilus), [Custom PCR Verification on Sui Mainnet](https://www.cryptowisser.com/news/custom-pcr-verification-is-now-live-on-sui-mainnet), [Marlin Oyster x Nautilus](https://blog.marlin.org/scaling-confidential-compute-on-sui-nautilus-and-marlin-oyster-integration), `github.com/MystenLabs/nautilus` (`move/enclave/sources/enclave.move`).

---

## 1. Tinfoil (tinfoil.sh)

**What is attested**: Full boot chain, not just app code. The CPU (AMD SEV-SNP / Intel TDX confidential VM) measures, in order: OVMF firmware → OS kernel + initrd (from a read-only root filesystem) → the running `tinfoil-config.yml` (hash embedded in the kernel command line, so config is attested too) → model weights, verified continuously at read-time via **dm-verity** (every disk block checked against a Merkle-tree root hash, not just at boot). GPU-side: NVIDIA Hopper/Blackwell confidential-computing mode.

**Trust model**: Hardware root of trust (CPU vendor + NVIDIA) + *reproducible builds* + a **transparency log**. At build time, Tinfoil produces a signed **Sigstore bundle** binding the open-source code to the exact expected attestation measurements, and commits it to the public Sigstore transparency log (Rekor) — so Tinfoil itself cannot swap in different code without the change being publicly visible and measurement-mismatched.

**Verification flow (client SDK)**, in order:
1. Fetch the attestation document from the enclave (contains signed runtime measurements + an enclave-generated TLS public key tied to the measured runtime).
2. Verify the certificate chain back to the CPU vendor's hardcoded root cert.
3. Fetch the Sigstore bundle for the running version; verify its signature against Sigstore's root trust anchor.
4. Compare measurement predicates (expected vs. attested) to confirm the source code matches.
5. Confirm the enclave's TLS public key matches the one embedded in the attestation document — binding TLS to the attested key, so the encrypted channel itself is provably terminated inside the measured enclave (non-exportable private key, never leaves enclave memory).

**Receipt/proof format**: No discrete "signed receipt" artifact per inference request appears to be exposed — attestation is a *connection-level* property (verify-then-connect), not a *per-response* signed object. This is the biggest structural difference from Phala/NEAR AI below.

**What to copy**: the boot-chain measurement discipline (config file hash included, not just code); dm-verity for continuously-verified model weight integrity (not just "measured once at boot"); Sigstore/Rekor for public, tamper-evident code↔measurement binding — this is a strong pattern for "config/policy hash" auditability that's independent of the chain itself.
**What to avoid/note**: connection-level attestation without a portable per-request receipt object means nothing is left over for offline/onchain audit after the TLS session closes — exactly the gap an onchain receipt is meant to fill.

Sources: [Tinfoil Technology](https://tinfoil.sh/technology), [Tinfoil docs](https://docs.tinfoil.sh/), [Attestation architecture](https://docs.tinfoil.sh/verification/attestation-architecture), [tinfoil-cli](https://github.com/tinfoilsh/tinfoil-cli), [Browser-native verification](https://tinfoil.sh/blog/2025-12-18-browser-native-verification).

---

## 2. Edgeless Systems Continuum (AI)

**What is attested**: The full confidential VM stack — Continuum OS running inside a CVM on NVIDIA H100 GPUs — via an **attestation service** that admins/users query independently of the worker nodes doing inference.

**Architecture**: Worker nodes (host models, serve inference) each run inside a CVM; a dedicated attestation service issues verifiable claims about what's running. An encryption proxy sits in front: it decrypts incoming prompts inside the sandbox, processes them, and re-encrypts responses before they leave the CVM boundary — so prompts are encrypted-in-transit end-to-end except inside the measured sandbox.

**Trust model**: Separates "prove the deployment is correct" (attestation service, checked once/periodically by admins) from "send me an encrypted prompt, trust the already-verified worker" (users). This is closer to a session/deployment-level trust model than a per-response receipt model — similar to Tinfoil in that respect.

**What to copy**: the separation of concerns between an attestation *service* (deployment-level, admin-verified) and workers that serve requests once verified — reduces per-request verification overhead. Useful if the gateway wants a cheap "is this deployment currently trustworthy" check distinct from the (cheaper, per-request) signature check.
**What to avoid**: like Tinfoil, no visible per-inference receipt artifact — not directly reusable as a receipt schema, only as an attestation-service pattern.

Sources: [Edgeless Systems + NVIDIA Continuum AI](https://blockchain.news/news/edgeless-systems-nvidia-enhance-ai-security-continuum-ai-framework), [Edgeless Systems](https://www.edgeless.systems/), [TFiR coverage](https://tfir.io/edgeless-systems-continuum-offers-confidential-ai-capabilities/).

---

## 3. Phala Network — Attested Confidential Inference (ACI) Gateway

**This is the closest prior art to what you're building** — an OpenAI-compatible gateway, TDX + H100/H200/B300 GPU TEE, that issues a **signed receipt per response** plus an onchain-anchored "no-log compose-hash," with an explicit path to bring TEE attestations onchain via zkVerify.

**What is attested**:
- Gateway workload identity + TEE quote (via `dstack`, Phala's TEE deployment framework).
- Source provenance (compose-hash — a hash of the Docker Compose / deployment manifest that produced the running workload, i.e. a "config hash" concept).
- The E2EE key bound to the workload (so client encryption targets a specific attested workload, not just "some Phala node").
- Per-request: whether the **upstream provider** (if the gateway proxies to a third-party model API) was verified and channel-bound *before* the prompt was forwarded — this is notable: Phala's gateway can sit in front of non-TEE upstreams and still attest to having checked them.

**Receipt fields** (from Phala's own description, no full JSON schema published but fields named explicitly):
- `request_hash` — hash of the client's original request
- middleware-forwarded body (i.e., what the gateway internally forwarded, possibly transformed)
- `selected route` — which model/provider handled the request
- `upstream verification result` — proof the upstream was checked
- `provider-facing request hash` — hash of what was actually sent upstream (may differ from client request after gateway transforms)
- `provider response hash`
- `final returned response hash` — hash of what the gateway returned to the client
- Gateway **signature** over the receipt

**Attestation report** (fetched separately via `GET /v1/aci/attestation`): proves gateway workload identity, TEE quote, source provenance, and the **public keyset used to sign receipts** — i.e., receipts are verified against keys whose own provenance is independently attestable, not just self-asserted.

**Verification flow**: client gets `x-receipt-id` header on each response → fetches the full receipt by ID → verifies receipt signature against the gateway's attested public key (obtained from the separate attestation endpoint) → optionally cross-checks response hash against the actual response bytes.

**Onchain path**: zkVerify partnership brings TEE attestations onchain as a "modular, cost-optimized" verification path — i.e., Phala doesn't verify full attestation docs onchain per request (too expensive), it wraps/proves them and verifies cheaply via zkVerify. This is directly analogous to the Nautilus pattern of "verify attestation once at registration, verify signature cheaply per request" — validates that as the right general shape.

**What to copy**: (1) the request→hash / response→hash / *and* provider-facing-request-hash triple, which captures gateway transformation/routing, not just raw client I/O; (2) separating the attestation report (proves the signing key's provenance) from the receipt (signed by that key, per-request) — exactly mirrors Nautilus's `register_enclave` (expensive, once) vs. per-message signature check (cheap, per-request); (3) "upstream verified" flag for gateways that proxy to non-enclave model providers.
**What to avoid**: field list isn't fully published/versioned (no explicit schema version field found), so don't copy it verbatim — treat it as directional, not a spec to vendor.

Sources: [Phala Private AI Gateway](https://phala.com/posts/private-ai-gateway-verified-private-ai-compute), [Phala Cloud confidential AI docs](https://docs.phala.com/phala-cloud/confidential-ai/overview), [zkVerify x Phala](https://zkverify.io/blog/zkverify-partners-with-phala-network-to-bring-verifiable-tee-attestations-on-chain-to-boost), [Phala confidential AI models](https://phala.com/confidential-ai-models).

---

## 4. NEAR AI Cloud — Private Inference

**What is attested**: Intel TDX + NVIDIA confidential-GPU enclave; the TEE produces a **cryptographic attestation quote binding the exact model and code that ran** (i.e., model identity is part of the attested measurement, not just a claimed string field). Prompts travel over TLS and are only decrypted inside the enclave; keys never touch NEAR AI's own infrastructure.

**Receipt mechanism**: Every response carries an `x-receipt-id` header (same convention as Phala — possibly convergent, possibly shared ACI heritage). Client fetches the "ACI receipt" by ID, verifies:
- its **signature**
- its **response hash** against a **fresh gateway attestation** (i.e., re-attest at verification time, don't just trust a cached attestation — defends against a gateway that was compromised *after* an earlier attestation)
- optionally follows `upstream.verified.session_id` for deeper audit evidence when the gateway proxied to another provider

**Notable framing**: "Trust the math, not a promise" — explicit design goal that verification is fully client-side/offline-capable via an **open verifier** tool, not a hosted "trust us" dashboard.

**Onchain angle**: mentions the ability to "revoke the build onchain to kill access globally" — i.e., a revocation registry for enclave measurements/builds lives onchain, separate from the receipts themselves. Useful pattern: onchain revocation list keyed by measurement/PCR, checked by verifiers before trusting a receipt signed under that build.

**What to copy**: (1) `x-receipt-id` header + separate receipt-fetch endpoint (clean separation between the inference response and the audit artifact, avoids bloating every response body); (2) re-attesting *at verification time* rather than trusting a stale attestation cached by the client; (3) onchain revocation of a build/measurement, independent of individual receipts, so a compromised enclave version can be globally invalidated without needing to touch already-issued receipts (the receipts stay historically valid/inspectable, but a verifier checks "was this measurement revoked after issuance" as a separate step).
**What to avoid**: (same caveat as Phala) full JSON schema for the receipt isn't publicly documented in the crawlable pages — infer the field *shape*, don't assume you're matching a real spec byte-for-byte.

Sources: [NEAR AI Private Inference](https://docs.near.ai/cloud/private-inference/), [NEAR AI Cloud](https://cloud.near.ai/), [Building Next-Gen NEAR AI Infra with TEEs](https://near.ai/blog/building-next-gen-near-ai-infrastructure-with-tees).

---

## 5. Marlin Oyster

**What is attested**: Supports AWS Nitro, Intel SGX/TDX (CPU) and NVIDIA H100 (GPU) confidential computing; verifies "whether the right enclave image is running in a genuine TEE" — i.e., PCR/measurement-style code attestation, consistent with the Nautilus/Nitro model (Marlin explicitly integrates with Sui Nautilus — see [Scaling Confidential Compute on Sui](https://blog.marlin.org/scaling-confidential-compute-on-sui-nautilus-and-marlin-oyster-integration)).

**Onchain verification**: A **Solidity library with RISC Zero support** for attestation verification (i.e., wraps the raw attestation doc in a ZK proof so onchain verification is cheap) plus a hosted "web2 portal" for manual checks. Marlin also offers wrapping attestations in a ZKP generally (~15 min proof generation) as an alternative to raw onchain attestation replay — same "verify-once, cheap-thereafter" shape as Nautilus/Phala/zkVerify.

**AI-specific claim**: "Hardware enclaves run LLM inference and sign attested outputs that smart contracts and users can trust onchain" — but no published field-level receipt schema was found; Marlin's public docs describe the *mechanism* (enclave signs output, onchain verifier checks attestation + signature) rather than a concrete receipt JSON.

**What to copy**: the direct Sui/Nautilus integration precedent is worth studying at the code level (their blog post + likely GitHub) since it's the nearest existing "TEE inference + Sui onchain verification" combination; the RISC Zero-wrapped-attestation trick for cheap onchain verification of a full attestation doc (vs. Nautilus's "verify once, then just check Ed25519 sig" — compare tradeoffs).
**What to avoid**: no public receipt schema to copy; would need to read their contracts/SDK source directly for field-level detail (not retrievable in this pass — flagged as a follow-up if precise Move/Solidity structs are wanted).

Sources: [Marlin docs](https://docs.marlin.org/oyster/introduction-to-marlin/), [Marlin x Sui Nautilus](https://blog.marlin.org/scaling-confidential-compute-on-sui-nautilus-and-marlin-oyster-integration), [Marlin AI](https://www.marlin.org/ai).

---

## 6. Other TEE-inference / crypto projects (lighter coverage)

- **Atoma Network**: Different trust model entirely — not attestation-per-se but **sampling consensus**: N randomly-selected nodes each run the same inference, submit a commitment/hash of their output; if hashes match across the sample, the result is accepted as verified; mismatches trigger dispute resolution and slashing. "Elastic verifiability" — caller chooses N (2 nodes for low-stakes, 10+ for high-stakes). No enclave-measurement receipt; the "proof" is inter-node hash agreement, economically enforced. Relevant as a *complementary* verification layer (redundancy-based) rather than a receipt schema to copy, but worth knowing as a design alternative: attested TEE receipts prove "this code ran," sampling consensus proves "multiple independent parties agree on the output," and they solve different threat models (compromised enclave vs. single point of failure). Source: [Atoma intro](https://medium.com/@atomanetwork/introducing-atoma-network-a-simplified-guide-to-verifiable-ai-inference-e9a5f56f67b3), [Atoma GitHub](https://github.com/atoma-network/atoma-node).

- **VeriLLM** (academic, arXiv:2509.24257): Cryptographic-commitment / Merkle-tree approach to publicly verifiable *decentralized* inference — commits to model weights via Merkle root, verifies computation trace layer-by-layer, anchors proofs onchain. Positioned explicitly as a **non-TEE alternative** (no hardware trust assumption) at the cost of being far more complex/expensive than TEE attestation. Useful mainly as a contrast case: confirms TEE attestation (your approach) trades cryptographic purity for practicality and is the dominant *production* pattern as of 2026, while cryptographic-proof approaches (zkML, opML, VeriLLM-style) remain largely research-stage for LLM-scale models. Source: [VeriLLM](https://arxiv.org/pdf/2509.24257).

- **Automata Network**: Provides a **standardized cross-TEE attestation verification library** — one interface to generate/verify attestation reports across Intel SGX/TDX, AMD SEV-SNP, and AWS Nitro, exposed to smart contracts. Positions itself as infrastructure *underneath* projects like yours (a "verify any TEE attestation onchain" primitive) rather than a competing gateway. Worth evaluating as a dependency instead of writing your own multi-TEE Move verifier if you ever need to support non-Nitro enclaves. Source: [Automata](https://www.ata.network/).

- **zkML / opML** (general categories, not single projects): zkML = zero-knowledge proof of correct model execution — cryptographically strongest, but computationally infeasible at LLM scale as of 2026. opML = optimistic/fraud-proof model — cheap by default, but introduces a challenge period before finality (bad fit for real-time inference receipts). Both are useful as *contrast*: they justify why TEE attestation (Nautilus's approach) is the pragmatic choice for a shipping product, while flagging that a future version of your receipt format could add an optional "challengeable" or "ZK-wrapped" tier if disputes become a problem.

---

## 7. Opacity Labs (zkTLS / MPC attestation of arbitrary API responses)

**Different problem, adjacent technique.** Opacity doesn't attest AI inference — it attests that *a given HTTP(S) response really came from a given server*, from the user's own TLS session, without needing API cooperation. Relevant here because if your gateway ever proxies to third-party model providers (OpenAI, Anthropic APIs) and wants to prove *what the upstream actually returned* (not just what your enclave claims it received), zkTLS-style notarization is the applicable technique — this is effectively "upstream TLS evidence," one of the explicit things you asked not to miss.

**Mechanism**: builds on the **TLSNotary** protocol — a Notary participates in (or MPC-witnesses) the TLS session between client and server without seeing plaintext keys, then issues a signed **attestation** = "I was in a genuine TLS session with server X; here are cryptographic commitments to what was exchanged." TLSNotary attestations have two parts: a **Header** (unique identifier, protocol version, Merkle root of the body fields — signed by the Notary) and a **Body** (the actual commitments/transcript data).

**Opacity's additions**: requires the attestation software itself to run in a TEE (so unless the TEE is compromised, the Notary can't collude with either party); adds **restaking** — notaries stake collateral and are **slashable** for misbehavior, converting "trust the operator" into "trust the incentives"; requires Web2 account linkage to reduce Sybil risk for multi-wallet collusion.

**Fields**: `message` (the notarized content), `message-hash` (compared against notary's own computed hash), `signature` — verified using an **EIP-191**-style message-hashing scheme. Full transcript-level field schema not fully published in crawlable docs; underlying TLSNotary Header/Body Merkle-root structure is the more citable primitive.

**What to copy**: if the gateway ever needs to prove "the upstream model API really returned this," a TLSNotary-style commitment (Merkle root over the TLS transcript, notarized either by the enclave itself if it terminates the upstream TLS session, or by an external zkTLS notary if it doesn't) is the right primitive to reach for — and notably, if your enclave *is* the TLS client to the upstream, you get this almost for free: the enclave already saw the plaintext, so it can just hash the raw upstream response and sign that hash as part of the receipt, no MPC/zkTLS needed. zkTLS is only necessary when you *don't* control the TLS endpoint that saw the upstream response.
**What to avoid**: the MPC/restaking/slashing machinery is solving a different problem (proving to a *third party* what a *user's own* browser session saw) — over-engineering for a gateway that already terminates TLS to the upstream inside its own attested enclave.

Sources: [Opacity Message Hash Verification](https://docs.opacity.network/docs/message-hash-verification), [Opacity Network: Trust but Verify](https://medium.com/@vinayak_35433/opacity-network-trust-but-verify-eb819ebb0b0a), [TLSNotary FAQ](https://tlsnotary.org/docs/faq/), [zkTLS ≠ trustless](https://tlsnotary.org/blog/2026/06/17/public-verifiability/).

---

## 8. Emerging receipt/attestation standards (general, not AI-specific but directly reusable)

These are the most concretely useful finds for schema design — several give **complete, quotable field lists**.

### 8a. IETF draft-chueayen-attestation-receipts-00: "Enforcement Attestation Receipts for AI Inference Decisions"
Directly on-topic (AI inference specifically) and the most complete public schema found. **Exactly 12 top-level fields, closed schema** ("Receipts MUST NOT contain additional top-level fields in this version"):

| Field | Type | Purpose |
|---|---|---|
| `v` | integer | Format version, MUST be 1 |
| `attestation_id` | string (UUIDv4) | Unique receipt identifier |
| `trace_id` | string | Issuer-assigned call identifier |
| `org_id` | string | Subject organization identifier |
| `request_hash` | string | SHA-256 hex digest (64 lowercase hex chars) of the **canonicalized** request body |
| `model` | string | Provider-qualified model identifier |
| `outcome` | string | Enforcement decision: `ALLOWED`, `BLOCKED`, `SUPPRESSED`, `PASSED` |
| `policy_applied` | array | Lexicographically sorted array of ASCII policy identifiers |
| `cost_prevented_eur` | number | Issuer's estimate of spend avoided by a BLOCKED/SUPPRESSED outcome |
| `timestamp` | string | RFC 3339 datetime with explicit timezone offset |
| `public_key` | string | base64url raw 32-byte Ed25519 public key, no padding |
| `signature` | string | base64url 64-byte Ed25519 signature, no padding; **omitted from the canonical payload it signs** |

**Canonicalization**: strip `signature` → serialize remaining fields as JSON with lexicographically sorted keys, no whitespace, UTF-8, non-ASCII emitted literally (no `\uXXXX`); integers with no decimal point, other numbers in shortest decimal form; numbers outside [1e-4, 1e21) MUST NOT be signed directly (float precision safety).

**Trust-model caveat explicitly called out**: "A verifier that checks a receipt only against the `public_key` embedded in that receipt proves internal integrity but not that the receipt came from the expected issuer" — the verifier MUST pin the issuer's key **out of band** (i.e., embedding the pubkey in the receipt is necessary but not sufficient; don't let self-declared keys be the root of trust). For your Sui design, the registered `Enclave<T>` object *is* that out-of-band pinning mechanism — worth calling out explicitly in your spec as the reason the onchain registration step matters.

Source: [draft-chueayen-attestation-receipts-00](https://www.ietf.org/archive/id/draft-chueayen-attestation-receipts-00.html)

### 8b. IETF draft-farley-acta-signed-receipts-01: "Signed Decision Receipts for Machine-to-Machine Access Control" (+ draft-marques-asqav-compliance-receipts profile)
General-purpose signed receipt envelope, multiple receipt "types" sharing common fields:

**Common fields** (all receipt types): `type` (namespaced string), `issued_at` (ISO 8601), `issuer_id`, `payload_digest` (optional, hash of data too large to embed), `hook_latency_ms`, `tool_duration_ms`, `sandbox_state`, `action_ref` (SHA-256 of canonical action representation), `verifier_sigil`, `iteration_id`.

**Signed envelope structure** (separates payload from proof, unlike 8a which is flat):
```json
{
  "payload": { ... },
  "signature": { "alg": "EdDSA", "kid": "sb:issuer:<base58-fingerprint>", "sig": "<128-char hex>" }
}
```
**Canonicalization**: JCS (RFC 8785) — deterministic JSON, sorted keys, no whitespace, signature field *removed* (not nulled) before canonicalizing.
**Key distribution**: issuers publish public keys at `/.well-known/acta-keys.json` as a JWK Set (`kty: OKP`, `crv: Ed25519`, `kid`, `x`, `use: sig`).

**What's most reusable here**: (1) the `payload` / `signature` envelope split (cleaner than flat-with-signature-field, and matches your Nautilus `IntentMessage<T>` shape almost exactly — `data: T` = `payload`, the Move signature check = `signature`); (2) `kid` as a stable key identifier separate from the raw pubkey bytes, letting you rotate enclave keys without breaking receipt-verifier code; (3) `.well-known` JWK publication as a lightweight out-of-band key-pinning mechanism, complementary to (or a fallback for) onchain registration.

Sources: [draft-farley-acta-signed-receipts-01](https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/01/), [draft-marques-asqav-compliance-receipts](https://datatracker.ietf.org/doc/draft-marques-asqav-compliance-receipts/).

### 8c. Agent Receipts (agentreceipts.ai, Otto Jongerius) — "C2PA Content Credentials for agent actions"
W3C Verifiable Credentials Data Model 2.0 envelope, type `AgentReceipt`. Top fields: `id`, `issuer`, `issuanceDate`, `version`, `credentialSubject`, `proof` (Ed25519Signature2020). Nested under `credentialSubject`: `principal` (who authorized), `action` (`type`, `risk`, `timestamp`), `outcome` (`status`, `reversible`), `chain` (`sequence`, `prev_hash` — **hash-chained receipts**, each pointing to the prior one, `null` at chain start), `intent` (`prompt`, `reasoning`), `authorization` (`scopes`, `grant`), `delegation` (parent chain reference).

**What's reusable**: the **hash-chain** pattern (`prev_hash`) — turns a series of receipts (e.g., a multi-turn conversation, or a chain of tool calls inside one inference) into a tamper-evident sequence, not just individually-verifiable islands. Worth considering if your gateway supports multi-turn sessions or agentic tool-calling where you want to prove *ordering*, not just individual-request integrity.

Source: [Agent Receipts specification](https://agentreceipts.ai/specification/overview/).

### 8d. C2PA (Coalition for Content Provenance and Authenticity) — AI/ML guidance
Not a receipt-for-inference-requests standard — it's a **content provenance** standard (proving what produced a piece of *media*, e.g. an image or generated text artifact), but the closest thing to an industry-wide convention for "AI produced this, here's the chain of custody." Manifests are cryptographically signed, containing: asset hash, digital signature, timestamp, and **ingredient declarations** (references to inputs/training data/prior versions with their own hashes — recursive provenance chain). Dedicated assertion types include an **Asset Type Assertion** (model name, ML framework, model type), an **Attestation Assertion** (trust signals about the software/device that created the asset), and a **Training and Data Mining Assertion** (whether the asset is permitted for AI training use — an opt-in/opt-out signal, not directly relevant to inference receipts but shows the pattern of "policy flags embedded in the signed manifest").

**What's reusable**: the "ingredient" concept (recursive references to upstream signed artifacts, each independently hash-verifiable) is a good model if your receipts should reference e.g. the specific model-weights artifact or a prior turn's receipt, rather than inlining everything flat.
**What to avoid**: C2PA is heavyweight and designed for asset distribution/editing chains (photos, video) — don't adopt its full manifest structure, just the ingredient-hash-reference idea.

Sources: [C2PA AI/ML spec](https://spec.c2pa.org/specifications/specifications/2.4/ai-ml/ai_ml.html), [C2PA FAQ](https://c2pa.org/faqs/).

### 8e. EQTY Lab — Verifiable Compute / Verifiable Runtime
Enterprise-oriented: generates cryptographic attestations from hashes over **code and execution state**, signed using keys on a DPU (data processing unit — hardware-rooted, distinct from CPU/GPU TEEs), compiled into "manifests" and anchored to a public ledger (Hedera). Emphasizes immutable timestamping relative to known security-breach events (i.e., receipts should let you later prove "this ran *before* vulnerability X was disclosed"). No public field-level schema found (marketing-tier docs only, white paper gated behind a form) — treat as a directional data point (enterprise DPU-rooted attestation + ledger anchoring is a real, funded pattern) rather than a schema source.

Sources: [EQTY Lab Verifiable Runtime](https://www.businesswire.com/news/home/20260318888449/en/EQTY-Lab-Announces-Verifiable-Runtime-to-Secure-AI-Agents-Across-the-NVIDIA-Enterprise-AI-Factory-and-NVIDIA-OpenShell), [EQTY Lab](https://www.eqtylab.io/).

---

## 9. Cross-cutting patterns worth noting explicitly

1. **"Verify once, sign cheaply" is universal.** Every production system (Nautilus, Phala, NEAR AI, Marlin, Tinfoil) separates an expensive one-time/periodic full-attestation verification (registering a PCR/measurement, checking a Sigstore bundle, checking a Nitro cert chain) from a cheap per-request check (Ed25519 signature against the now-trusted key). Your Move-side design should keep this split explicit: an `EnclaveConfig`/registration path (rare, expensive) and a receipt-verification path (frequent, cheap, just a signature + hash check).

2. **Two receipt shapes recur**: flat-with-signature-field (8a: `{...fields..., signature}`) vs. payload/signature envelope (8b, and Nautilus's own `IntentMessage<T>` + wrapper signature). The envelope shape is strictly better for versioning and composability (you can swap `T` without touching the signing/verification code) and is what Nautilus already gives you — lean into it rather than flattening.

3. **Out-of-band key pinning is a MUST, called out explicitly in 8a.** A receipt's embedded public key alone is not a security boundary; the verifier needs the enclave's public key from a source it independently trusts. On Sui this is naturally solved by the onchain registered `Enclave<T>` object — but your docs/spec should say this explicitly, since it's exactly the failure mode IETF flagged.

4. **Per-request receipts (Phala, NEAR AI) beat connection-level-only attestation (Tinfoil, Edgeless)** for your use case, because you specifically want *onchain-verifiable, portable* evidence per inference call — not just "the channel I'm currently on is trustworthy." Design for the receipt to outlive the TLS session.

5. **Gateway/proxy transformations need their own hash fields.** Phala's split of `request_hash` / `provider-facing request hash` / `provider response hash` / `final returned response hash` matters as soon as your gateway does *any* transformation (routing, prompt injection defense, format conversion) between what the client sent and what actually went to the model — don't just hash "the request" once, hash it at each boundary crossing if you transform it.

6. **Revocation needs to be separable from receipts.** NEAR AI's "revoke the build onchain" pattern (kill a compromised measurement globally) is distinct from invalidating individual receipts — old receipts issued under a build that's later revoked should probably remain *historically* inspectable ("this really was signed by that build, and that build was later found bad on date X") rather than becoming unverifiable. Model this as a separate onchain revocation registry keyed by PCR/measurement, checked as an extra step by verifiers, not baked into the receipt's own validity check.

7. **Upstream TLS evidence is solved for free if you control the TLS client.** You only need zkTLS/notary machinery (Opacity-style) if the enclave *doesn't* terminate the TLS connection to the upstream model provider itself. If your enclave *is* the HTTPS client calling e.g. an upstream model API, it already sees the plaintext response — just hash and sign it as part of the receipt. Reserve zkTLS for a future case where you need to attest to a *third party's* browser session, which is a different product.

---

## 10. Recommended field list for a versioned inference receipt

Envelope shape, following the Nautilus `IntentMessage<T>` pattern (payload separate from signature) and the IETF drafts' canonicalization discipline:

```
InferenceReceipt {
  // --- envelope / versioning ---
  v: u16                        // schema version, closed-set enum per version (§8a pattern)
  receipt_id: string (UUIDv4)   // unique per receipt (§8a attestation_id)
  intent: u8                    // Nautilus domain-separation tag for this message type

  // --- enclave / code identity ---
  enclave_pubkey: bytes32       // Ed25519 pubkey of the signing enclave (redundant with onchain
                                 // registered key, but keep inline for offline/portable verification —
                                 // per §8a/§9.3, MUST be cross-checked against the onchain-registered
                                 // Enclave<T> object, never trusted alone)
  pcr0 / pcr1 / pcr2: bytes     // OR a single measurement_hash if you don't need per-PCR granularity —
                                 // ties the receipt to a specific reproducible build (Nitro PCR convention)
  build_ref: string             // optional: Sigstore bundle / Rekor log entry ID or git commit,
                                 // linking measurement -> public source (Tinfoil pattern)

  // --- config / policy ---
  config_hash: bytes32          // hash of the gateway's running config/policy (rate limits, allowed
                                 // models, content filters, system prompt injection rules, etc.) —
                                 // Tinfoil measures config into the boot chain; you likely can't, so
                                 // hash+sign it explicitly instead
  policy_applied: [string]      // optional: which named policies fired (§8a policy_applied), sorted

  // --- request ---
  request_hash: bytes32         // SHA-256 of the canonicalized client-facing request
  upstream_request_hash: bytes32 // optional: hash of what was actually sent upstream, if the gateway
                                 // transforms/routes (§Phala pattern) — omit if gateway == model host

  // --- model identity ---
  model_id: string              // provider-qualified model identifier (§8a `model`)
  model_version / model_hash: string // weight/version identity if self-hosted (dm-verity root, per
                                 // Tinfoil, if you want continuous not just boot-time weight integrity)

  // --- sampling / determinism (flagged by prior art gaps — Phala/NEAR AI omit, but relevant for
  //     disputing "did you actually run what I asked") ---
  sampling_params_hash: bytes32 // hash of {temperature, top_p, max_tokens, seed, stop sequences, ...} —
                                 // include the hash (not raw params) if you want compact receipts but
                                 // still bindable/disputable evidence
  seed: u64 (optional, cleartext) // include in clear if you want reproducibility claims to be checkable

  // --- response ---
  response_hash: bytes32        // hash of what was returned to the client
  usage: { input_tokens: u32, output_tokens: u32, total_tokens: u32 }  // no prior art puts this in the
                                 // signed receipt explicitly, but it's the natural place for billing
                                 // disputes / rate-limit audits to anchor to — worth adding even though
                                 // it's a gap in what you surveyed, not a copy
  outcome: enum                 // ALLOWED / BLOCKED / ERROR / RATE_LIMITED (§8a outcome, generalized)

  // --- upstream evidence (only if gateway proxies to a non-enclave third-party API) ---
  upstream_verified: bool       // did the gateway confirm upstream TLS identity before forwarding
  upstream_tls_evidence: bytes32 (optional) // hash/commitment to upstream TLS transcript if the enclave
                                 // itself terminated that connection (free — see §9.7); only reach for
                                 // real zkTLS/notary proofs if you don't control that TLS client

  // --- timestamps ---
  timestamp_ms: u64             // Nautilus-native field name, enclave-attested wall clock at signing

  // --- chaining (optional, for multi-turn/agentic sessions) ---
  session_id: string (optional)
  prev_receipt_hash: bytes32 (optional)  // §8c hash-chain pattern, null at session start

  // --- signature (outside the canonical payload) ---
  signature: bytes64            // Ed25519 over BCS(IntentMessage{intent, timestamp_ms, data: <all fields above>})
}
```

**Canonicalization rule**: sign the BCS-serialized `IntentMessage<InferenceReceiptData>` per Nautilus convention (this is free — Move's BCS is already deterministic, unlike JSON, so you don't need JCS/RFC 8785 gymnastics the IETF drafts require for JSON receipts). If you also want an *offchain* JSON representation of the same receipt for tooling/UIs, canonicalize per JCS (RFC 8785) as draft-farley does, and treat the BCS+Move version as authoritative.

**Top 3 lessons from prior art**:
1. **Split identity-proving from event-proving, and make the split explicit onchain.** Register enclave measurement + key once (expensive, rare); sign individual receipts cheaply thereafter (Nautilus already does this — lean into it, don't reinvent). A receipt's embedded pubkey is never sufficient on its own (IETF draft-chueayen's explicit warning) — the onchain `Enclave<T>` registration is your out-of-band pin.
2. **Hash at every transformation boundary, not just once.** As soon as the gateway does routing, retries, prompt rewriting, or proxies to third-party model APIs, Phala's `request_hash` / `upstream_request_hash` / `provider_response_hash` / `final_response_hash` split becomes necessary to make disputes resolvable — a single "request hash, response hash" pair silently assumes the gateway is a pure pass-through.
3. **No surveyed production system publishes a full, versioned, field-complete receipt schema — the AI-specific IETF draft (draft-chueayen) is closest but new/thin, and Phala/NEAR AI describe fields in prose, not JSON Schema.** This is a real gap and an opportunity: being first to publish a clean, versioned, closed-field-set schema (à la draft-chueayen's discipline — explicit version field, MUST NOT contain extra fields, exact byte-lengths for keys/signatures) for TEE-signed AI inference receipts, with reference Move verification code, is a genuine contribution rather than "yet another gateway."
