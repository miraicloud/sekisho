# Nautilus Technical Brief

Researched August 2026. Primary sources: [MystenLabs/nautilus](https://github.com/MystenLabs/nautilus) (GitHub, source read directly via `gh api`), [docs.sui.io Nautilus docs](https://docs.sui.io/guides/developer/nautilus), [Sui blog](https://blog.sui.io), and the [Sui core repo](https://github.com/MystenLabs/sui) framework source for `sui::nitro_attestation` and `sui::ed25519`.

---

## 0. What Nautilus is

Nautilus is Mysten Labs' framework for **verifiable off-chain computation on Sui** using Trusted Execution Environments (TEEs) — initially AWS Nitro Enclaves, with a 2026 expansion to Marlin Oyster (a TEE marketplace that provisions and runs Nitro Enclaves on demand, paid for on Sui). It has two halves:

1. A **reproducible-build enclave server template** (Rust, Docker/StageX-based) that developers fork to run their off-chain logic.
2. A **Move package** (`enclave::enclave`) that developers deploy per-application to register the enclave's PCR measurements and ephemeral public key on-chain, and to verify signed responses cheaply thereafter.

Timeline: live on Testnet April 15, 2025 ([blog](https://www.sui.io/blog/nautilus-offchain-security-privacy-web3)); on Mainnet June 5, 2025 ([blog](https://www.sui.io/blog/nautilus-tamper-proof-oracles)). Marlin Oyster integration (Dockerized deployment, no self-managed AWS infra needed) added later in 2025/2026 ([Marlin blog](https://blog.marlin.org/scaling-confidential-compute-on-sui-nautilus-and-marlin-oyster-integration), [Marlin docs](https://docs.marlin.org/oyster/nautilus/security)). Sui framework support for `load_nitro_attestation` was enabled progressively: devnet in protocol version ~74, testnet ~shortly after, mainnet with "upgraded parsing" in later protocol versions (see §3).

---

## 1. Repo structure (`MystenLabs/nautilus`)

Confirmed by listing the live repo via `gh api repos/MystenLabs/nautilus/contents/...`:

```
nautilus/
├── Containerfile          # StageX-based deterministic/hermetic multi-stage Docker build
├── Makefile                # `make ENCLAVE_APP=<name>` -> out/nitro.eif (+ out/nitro.pcrs)
├── rust-toolchain.toml
├── deny.toml                # cargo-deny dependency/license/security scanning
├── README.md / Design.md / UsingNautilus.md  # docs (mirrored onto docs.sui.io)
├── flows.png
├── configure_enclave.sh     # provisions EC2 + Nitro Enclave allocator, sets up secrets prompt
├── register_enclave.sh      # calls get_attestation on the running enclave, submits register_enclave tx
├── expose_enclave.sh        # exposes the enclave's port 3000 to the internet via a proxy
├── reset_enclave.sh
├── update.sh / update_weather.sh
├── .cargo/, .github/
├── move/
│   ├── enclave/              # the reusable "enclave" Move package (registration + verification)
│   │   └── sources/enclave.move
│   ├── seal-policy/           # Move package for the Seal-secret-decryption access policy
│   ├── twitter-example/       # example app package
│   └── weather-example/       # example app package (the canonical oracle demo)
└── src/nautilus-server/       # the Rust enclave server template
    ├── Cargo.toml
    ├── run.sh                  # init script baked into the EIF (see §4)
    ├── traffic_forwarder.py    # host<->enclave HTTPS domain allow-listing forwarder
    └── src/
        ├── main.rs             # axum server bootstrap, generates ephemeral Ed25519 keypair
        ├── common.rs           # get_attestation / health_check handlers, signing helper
        ├── lib.rs
        └── apps/                # per-example business logic (weather/twitter/seal-example)
```

Each example under `move/<app>/` and `src/nautilus-server/src/apps/<app>/` is selected via a Cargo feature flag (`weather-example`, `twitter-example`, `seal-example`) passed as `--build-arg ENCLAVE_APP=$(ENCLAVE_APP)`.

The template is explicitly **not production-hardened**: "not feature complete, has not undergone a security audit... provided as-is for evaluation purposes only" (README.md).

---

## 2. Reproducible build pipeline / PCR0-1-2

### Build mechanics
The `Containerfile` builds entirely from **StageX** (`stagex.tools`) base images pinned by sha256 digest — described as "a full source bootstrapped, deterministic, and hermetic build toolchain." The Rust binary is compiled statically (`RUSTFLAGS="-C target-feature=+crt-static -C relocation-model=static"`, musl target, `OPENSSL_STATIC=true`) so there are no dynamic-linking non-determinism sources. The root filesystem is assembled as a `cpio` archive with `--reproducible`, sorted file order, and `touch -hcd "@0"` to zero out all timestamps (`KBUILD_BUILD_TIMESTAMP=1` too), then gzipped. `make` itself uses Docker BuildKit's `--output type=local,rewrite-timestamp=true` and `--provenance=false` to strip build-time metadata that would otherwise vary run-to-run.

The final step calls AWS's `eif_build` (also a StageX package) to produce `nitro.eif` **and** `nitro.pcrs` in the same invocation:
```
eif_build --kernel /bzImage --kernel_config /linux.config \
  --ramdisk /build_cpio/rootfs.cpio --pcrs_output /nitro.pcrs \
  --output /nitro.eif --cmdline '...nit.target=/run.sh'
```
Build entry point: `make ENCLAVE_APP=weather-example` → `out/nitro.eif` + `out/nitro.pcrs`.

### PCR semantics (per `move/enclave/sources/enclave.move` comments and AWS docs linked from Design.md)
- **PCR0** — measures the enclave image file (the EIF itself: kernel + boot ramfs + app).
- **PCR1** — measures the enclave Linux kernel and boot/kernel command line.
- **PCR2** — measures the enclave application (the ramdisk contents / your app layer specifically).

Reference: [AWS "Where to find PCR values"](https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html#where), linked directly from Design.md.

Nautilus's on-chain `EnclaveConfig<T>` only stores PCR0/1/2 (a fixed-size `Pcrs(vector<u8>, vector<u8>, vector<u8>)` triple) but the underlying `NitroAttestationDocument` type can carry all AWS PCR0-31 if a given app wants to check more.

### Third-party verification against a git tag
This is a manual, out-of-band process — there is no on-chain "source code hash" pinning beyond the PCRs themselves:
1. The developer publishes the enclave server source to a public repo at a specific commit/tag (Design.md step 2).
2. Anyone (including end users, per Design.md's "Dapp user / client actions") clones that exact commit, runs `make ENCLAVE_APP=<app>` locally on the same toolchain, and reads `out/nitro.pcrs`.
3. They compare those PCR0/1/2 values against the ones the developer registered on-chain via `enclave::update_pcrs` (queryable from the shared `EnclaveConfig<T>` object).
4. If they match bit-for-bit, the deployed enclave is provably running that exact source — because any change to code, kernel, or boot config changes PCR0-2 (this is the entire point of the reproducible build). If they don't match, the enclave should not be trusted.

Design.md is explicit that this only works when the source is public — "reproducible builds may not apply to all use cases, such as when the source code cannot be made public," in which case trust falls back to the AWS certificate chain / vendor attestation of the toolchain alone, without independent binary verification.

For local iteration, `make run-debug` produces all-zero PCRs (no real measurement) — never valid for production use; it exists purely for testing the server logic without burning real enclave cycles.

---

## 3. On-chain attestation verification (exact Move APIs)

### `sui::nitro_attestation` (Sui framework, native)
Source: `crates/sui-framework/packages/sui-framework/sources/crypto/nitro_attestation.move` in [MystenLabs/sui](https://github.com/MystenLabs/sui/blob/main/crates/sui-framework/packages/sui-framework/sources/crypto/nitro_attestation.move); docs mirror at [docs.sui.io/references/framework/sui_sui/nitro_attestation](https://docs.sui.io/references/framework/sui_sui/nitro_attestation).

```move
module sui::nitro_attestation;

public struct PCREntry has drop { index: u8, value: vector<u8> }

public struct NitroAttestationDocument has drop {
    module_id: vector<u8>,
    timestamp: u64,                 // ms since epoch
    digest: vector<u8>,
    pcrs: vector<PCREntry>,          // required PCR0-4 & 8 always present; 5-7,9-31 if nonzero
    public_key: Option<vector<u8>>,  // DER-encoded key committed to in the attestation
    user_data: Option<vector<u8>>,
    nonce: Option<vector<u8>>,
}

entry fun load_nitro_attestation(attestation: vector<u8>, clock: &Clock): NitroAttestationDocument {
    load_nitro_attestation_internal(&attestation, clock::timestamp_ms(clock))
}

// accessors: module_id(), timestamp(), digest(), pcrs(), public_key(), user_data(), nonce(),
// and on PCREntry: index(), value()

native fun load_nitro_attestation_internal(attestation: &vector<u8>, current_timestamp: u64): NitroAttestationDocument;
```
This single **entry function, `sui::nitro_attestation::load_nitro_attestation`**, is the whole verification surface: it's a native function that parses the AWS COSE-signed CBOR attestation document, walks and validates the **certificate chain rooted at AWS's Nitro root CA**, checks the timestamp against the Sui `Clock`, and only then returns a `NitroAttestationDocument` — it **aborts** (`EParseError`, `EVerifyError`, `EInvalidPCRsError`, `ENotSupportedError`) rather than returning a boolean, so a failed verification simply fails the transaction.

### `enclave::enclave` (the Nautilus application-facing Move package)
Source: `move/enclave/sources/enclave.move`, read directly from the repo:

```move
module enclave::enclave;

public struct EnclaveConfig<phantom T> has key {  // shared object
    id: UID, name: String, pcrs: Pcrs, capability_id: ID, version: u64,
}
public struct Enclave<phantom T> has key {          // shared object, the registered instance
    id: UID, pk: vector<u8>, config_version: u64, owner: address,
}
public struct Cap<phantom T> has key, store { id: UID }  // admin capability

public fun new_cap<T: drop>(_: T, ctx: &mut TxContext): Cap<T>;
public fun create_enclave_config<T: drop>(cap: &Cap<T>, name: String, pcr0/1/2: vector<u8>, ctx): EnclaveConfig<T>; // shared
public fun update_pcrs<T: drop>(config: &mut EnclaveConfig<T>, cap: &Cap<T>, pcr0/1/2: vector<u8>); // version += 1
public fun update_name<T: drop>(config: &mut EnclaveConfig<T>, cap: &Cap<T>, name: String);

public fun register_enclave<T>(enclave_config: &EnclaveConfig<T>, document: NitroAttestationDocument, ctx): /* shares Enclave<T> */;
// internally: asserts document.to_pcrs() == config.pcrs, then pk = document.public_key() (destroy_some)

public fun verify_signature<T, P: drop>(
    enclave: &Enclave<T>, intent_scope: u8, timestamp_ms: u64, payload: P, signature: &vector<u8>,
): bool;   // ed25519::ed25519_verify(signature, &enclave.pk, &bcs::to_bytes(IntentMessage{intent, timestamp_ms, payload}))
```
`register_enclave` is the exact call site of `sui::nitro_attestation` verification: it takes an already-parsed/verified `NitroAttestationDocument` (produced by a prior `sui::nitro_attestation::load_nitro_attestation` call, typically in the same PTB), checks its embedded PCR0/1/2 equal the ones stored in `EnclaveConfig<T>`, extracts the enclave's ephemeral **public key** that AWS Nitro's attestation mechanism committed to (passed as `public_key` in the NSM `Attestation` request — see §4), and shares a new `Enclave<T>` object holding that key.

**End-to-end call pattern (from `UsingNautilus.md` / `register_enclave.sh`):**
```bash
# 1. sui move build && sui client publish   (move/enclave)                → ENCLAVE_PACKAGE_ID
# 2. sui move build && sui client publish   (move/<app>)                  → APP_PACKAGE_ID, CAP_OBJECT_ID, ENCLAVE_CONFIG_OBJECT_ID
sui client call --package $ENCLAVE_PACKAGE_ID --module enclave --function update_pcrs \
  --type-args "$APP_PACKAGE_ID::$MODULE_NAME::$OTW_NAME" \
  --args $ENCLAVE_CONFIG_OBJECT_ID $CAP_OBJECT_ID 0x$PCR0 0x$PCR1 0x$PCR2
# register_enclave.sh: hits GET /get_attestation on the live enclave, then in one PTB calls
#   sui::nitro_attestation::load_nitro_attestation(attestation_bytes, clock)
#   -> enclave::enclave::register_enclave<T>(enclave_config, document)
```

### Gas cost of verifying an attestation
Exact cost parameters, read directly from `crates/sui-protocol-config/src/lib.rs` in MystenLabs/sui:
```
nitro_attestation_parse_base_cost      = 53 * 50    = 2,650   (internal gas units)
nitro_attestation_parse_cost_per_byte  = 50
nitro_attestation_verify_base_cost     = 49_632 * 50 = 2,481,600
nitro_attestation_verify_cost_per_cert = 52_369 * 50 = 2,618,450
```
These are Move-VM native-function gas costs (internal units, scaled by the reference gas price to MIST at execution) charged when `load_nitro_attestation_internal` runs — dominated by the certificate-chain verification cost (`verify_base_cost` + `verify_cost_per_cert` × chain length), not the CBOR parse. Design.md explicitly calls this out: *"Verifying an attestation document on-chain is a relatively expensive operation and should be performed only during enclave registration. After registration, use the enclave key to verify messages from the enclave more efficiently"* — i.e., pay the expensive `load_nitro_attestation` + `register_enclave` cost once per enclave version, then use the cheap `enclave::verify_signature` (a single `ed25519_verify`) for every subsequent response.

Protocol history (from the same file's version-log comments): attestation verification (`enable_nitro_attestation`) was gated behind a feature flag, enabled on Devnet around protocol version 74, then Testnet, with later versions (~105-113) adding `enable_nitro_attestation_upgraded_parsing`, `..._all_nonzero_pcrs_parsing`, and `..._always_include_required_pcrs_parsing` flags that changed how many/which PCRs get included in the parsed `NitroAttestationDocument` (initially only nonzero custom PCRs were included; later all nonzero PCRs, and required PCRs 0-4/8 are always included regardless of value). Any app that hardcoded PCR-count assumptions from the earlier parsing behavior should re-check against current mainnet protocol version.

---

## 4. Enclave server structure

### Rust crates (from `src/nautilus-server/Cargo.toml`)
- **axum 0.7** — HTTP server/router (`/`, `/get_attestation`, `/process_data`, `/health_check`)
- **tokio 1.43** (full features) — async runtime
- **fastcrypto** (MystenLabs, git dep, `aes` feature) — Ed25519 keypair generation/signing (`fastcrypto::ed25519::Ed25519KeyPair`)
- **nsm_api** (`aws/aws-nitro-enclaves-nsm-api`, git dep, package `aws-nitro-enclaves-nsm-api`) — talks to the in-enclave NSM (Nitro Security Module) kernel driver to request attestation documents
- **reqwest** — outbound HTTP (e.g., fetching weather data, checking endpoint health)
- **bcs** — canonical serialization for the signed payload (must match Move's `bcs::to_bytes`)
- **serde / serde_json / serde_yaml / serde_bytes / serde_repr**
- **tower-http** (cors)
- Feature-gated, only for the Seal example: **sui-sdk-types**, **sui-crypto** (`ed25519` feature), **seal-sdk** (MystenLabs/seal git dep)

### HTTP surface (`main.rs`)
Binds `0.0.0.0:3000` inside the enclave:
- `GET /` → `"Pong!"` liveness
- `GET /get_attestation` → calls NSM driver (`nsm_api::driver::nsm_init/nsm_process_request/nsm_exit`) with an `Attestation` request whose `public_key` field is set to the enclave's ephemeral Ed25519 public key bytes; returns the AWS-signed CBOR attestation document (hex-encoded). This is what commits the AWS attestation to the specific ephemeral key.
- `GET /health_check` → reports the enclave pubkey plus reachability of each domain in `allowed_endpoints.yaml`
- `POST /process_data` → app-specific business logic; returns a `ProcessedDataResponse` = `{ response: IntentMessage<T>, signature: hex }`

### vsock / parent-instance proxy pattern
Nitro Enclaves have **no direct network access** — only a VSOCK channel to their parent EC2 instance. Nautilus's `run.sh` (baked into the EIF as PID-1's target via `nit.target=/run.sh`, using the minimal **`nit` init system**) wires this up:
1. Configures loopback (`ip addr add 127.0.0.1/32 dev lo`) and `/etc/hosts`.
2. **Secrets injection**: blocks on `socat - VSOCK-LISTEN:7777,reuseaddr` waiting for the parent instance to push a JSON blob of key/value secrets; unpacks it and `export`s each pair as an environment variable before launching the server.
3. **Inbound traffic**: `socat VSOCK-LISTEN:3000,reuseaddr,fork TCP:localhost:3000 &` — forwards the enclave-side VSOCK port 3000 to the local `nautilus-server` process; on the parent EC2 instance, `nitro-cli`/a vsock-proxy setup (configured by `configure_enclave.sh`/`expose_enclave.sh`) forwards public traffic in.
4. **Outbound traffic**: `traffic_forwarder.py` + a parent-side `vsock-proxy` forwards enclave-originated HTTPS calls out to the internet, restricted to domains declared in `allowed_endpoints.yaml` (compiled into the image at build time — changing allowed domains requires rebuilding, which changes PCR2).
5. Finally execs `/nautilus-server`.

### Secrets/config at runtime
Two documented patterns:
- **Simple secret (weather/twitter examples)**: `configure_enclave.sh` prompts to store a value in **AWS Secrets Manager** (or reference an existing ARN); the parent instance fetches it and pushes it over the VSOCK:7777 channel described above, landing as an `API_KEY` env var read by `main.rs` (`std::env::var("API_KEY")`).
- **Seal-Nautilus pattern (seal-example, updated Jan 2026 per commit "feat: update Seal-Nautilus pattern to new key load workflow")**, documented at [docs.sui.io/sui-stack/nautilus/seal](https://docs.sui.io/sui-stack/nautilus/seal): because the enclave can't reach Seal's key-server HTTP endpoints directly, this is a two-phase, host-mediated bootstrap:
  1. **Init**: the enclave generates an ElGamal (BLS) encryption keypair in memory and produces a `FetchKeyRequest` signed by its **Seal wallet** (a separate in-memory Ed25519 keypair used purely to sign key-request certificates), which it hands to a small host-only init server.
  2. **Complete**: the host relays that request to Seal's key servers, gets back key shares encrypted to the enclave's ElGamal public key, and passes them back in; the enclave decrypts and caches the plaintext keys **in memory only** — nothing touches disk, and a restart requires re-running the whole bootstrap.
  - Encryption policy on the Seal side ties decryptability to the registered enclave's **PCR values**, so only an enclave whose measurements match the registered config can ever complete phase 2.
  - Per the docs, this pattern has been validated for self-managed AWS enclaves but **not yet tested with Marlin Oyster deployments** — a known gap.

---

## 5. Verifying signed enclave responses in Move (post-registration)

**Signature scheme: Ed25519** (not secp256k1). Confirmed in both the Rust template and the Move package:
- Rust side (`common.rs`): `fastcrypto::ed25519::Ed25519KeyPair::generate(&mut rand::thread_rng())` generated fresh at enclave boot; `to_signed_response` signs `bcs::to_bytes(IntentMessage{ intent, timestamp_ms, data })` with `kp.sign(...)`, hex-encodes the signature.
- Move side (`enclave.move`): `enclave::enclave::verify_signature<T, P>` rebuilds the identical `IntentMessage`/BCS-serialized payload and calls **`sui::ed25519::ed25519_verify(signature, &enclave.pk, &payload)`** — plain single-signature Ed25519 verification against the `pk: vector<u8>` stored on the shared `Enclave<T>` object at registration time.

This is deliberately the *cheap* path Design.md recommends using for every ordinary response, reserving the expensive `nitro_attestation` verification for the one-time (per PCR version) registration step. There's a built-in Move unit test (`test_verify_signature`) with a fixed test keypair/signature pinned to a known BCS payload, plus a Rust-side `test_serde` asserting the exact same BCS bytes are produced by both languages — guarding against payload-encoding drift between the enclave and the Move verifier.

---

## 6. Known limitations, versioning concerns, recent changes

- **Not audited / not production-hardened**: repo explicitly disclaims warranty, calls itself an "evaluation purposes only" reference template (README.md).
- **Reproducible builds require public source**: if you can't publish your enclave's source, third parties can't independently confirm PCR-vs-code correspondence; trust then rests solely on the AWS attestation chain, not on the code itself (Design.md).
- **Attestation verification cost is real**: ~2.65M-5.1M internal gas units per registration call (parse + verify), which is why the design pushes apps toward one-time registration + cheap Ed25519 verification per response rather than re-attesting per request.
- **PCR parsing behavior changed across protocol versions** (~74 → ~105-113 per `sui-protocol-config`): earlier versions only surfaced nonzero *custom* PCRs; later "upgraded parsing" flags made required PCRs 0-4/8 always present and included all nonzero custom PCRs. Code written against early-2025 behavior should be re-verified against current mainnet parsing rules.
- **Seal-Nautilus secret pattern is new and narrowly tested**: reworked "two-phase key load" as of a January 2026 commit; explicitly *not yet validated* against Marlin Oyster deployments, only self-managed AWS Nitro Enclaves.
- **Marlin Oyster support is a 2025/2026 addition**, not part of the original April/June 2025 launch — expands Nautilus from "self-managed AWS only" to a TEE marketplace model (pay-per-job in stablecoins, operators auto-provision Nitro Enclaves), per Marlin's own docs and blog. Cross-check current Marlin/Sui docs before relying on it for production, since it's the newest and least battle-tested integration path.
- **Active template churn**: recent commits (through July 2026) are still fixing basic packaging bugs in the reference template itself — e.g. `allowed_endpoints.yaml` not being shipped into the enclave image broke `health_check` until a July 25, 2026 fix (#35), and glibc prebuilt-binary support / build-target updates landed in the same window. Treat the template as actively evolving rather than a stable, frozen reference.
- **Debug builds produce all-zero PCRs** (`make run-debug`) and provide **no attestation guarantees** — must never be used to register a "production" enclave config.
- No on-chain revocation/expiry beyond PCR `version` bumps: `enclave::update_pcrs` increments `EnclaveConfig.version`; old `Enclave<T>` instances become distinguishable (`config_version < config.version`) and can be explicitly destroyed via `destroy_old_enclave`, but nothing forces callers to check this — an app must itself gate on `enclave.config_version == config.version` (or similar) if it wants to reject stale-but-still-shared enclave objects.

---

## Key sources
- [MystenLabs/nautilus](https://github.com/MystenLabs/nautilus) — repo root, README.md, Design.md, UsingNautilus.md, Containerfile, Makefile, `move/enclave/sources/enclave.move`, `src/nautilus-server/*` (all read directly from the live repo)
- [MystenLabs/sui — nitro_attestation.move](https://github.com/MystenLabs/sui/blob/main/crates/sui-framework/packages/sui-framework/sources/crypto/nitro_attestation.move) and `crates/sui-protocol-config/src/lib.rs` (gas costs, feature-flag history)
- [docs.sui.io/references/framework/sui_sui/nitro_attestation](https://docs.sui.io/references/framework/sui_sui/nitro_attestation)
- [docs.sui.io/guides/developer/nautilus](https://docs.sui.io/guides/developer/nautilus), [.../using-nautilus](https://docs.sui.io/guides/developer/nautilus/using-nautilus)
- [docs.sui.io/concepts/cryptography/nautilus](https://docs.sui.io/concepts/cryptography/nautilus), [.../nautilus-design](https://docs.sui.io/concepts/cryptography/nautilus/nautilus-design)
- [docs.sui.io/sui-stack/nautilus/seal](https://docs.sui.io/sui-stack/nautilus/seal) — Seal secret-injection pattern
- [Sui blog: Introducing Nautilus](https://www.sui.io/blog/nautilus-offchain-security-privacy-web3) (Testnet launch, April 2025)
- [Sui blog: Tamper-Proof Oracles with Nautilus on Mainnet](https://www.sui.io/blog/nautilus-tamper-proof-oracles) (Mainnet launch, June 2025)
- [Marlin blog: Scaling Confidential Compute on Sui — Nautilus + Oyster](https://blog.marlin.org/scaling-confidential-compute-on-sui-nautilus-and-marlin-oyster-integration), [Marlin docs: Nautilus security analysis](https://docs.marlin.org/oyster/nautilus/security)
