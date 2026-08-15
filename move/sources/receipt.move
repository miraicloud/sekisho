// Copyright (c) 2026 miraicloud
// SPDX-License-Identifier: Apache-2.0

/// Cheap, per-request verification of a signed inference Receipt against a
/// registered `Gateway`'s Ed25519 public key. The expensive attestation-chain
/// check happens once, in `sekisho::checkpoint::register`; every Receipt
/// thereafter is a single `sui::ed25519::ed25519_verify` call.
///
/// BCS layout (`Receipt` field order) is normative — see SPEC.md section 3 —
/// and is guarded byte-for-byte by `bcs_parity_nominal_success` /
/// `bcs_parity_refusal_unarchived_max_tokens` below against
/// `docs/receipt-vectors.json`.
module sekisho::receipt;

use std::bcs;
use std::string::String;
use sui::clock::Clock;
use sui::ed25519;
use sui::event;
use sekisho::checkpoint::{Checkpoint, Gateway};

// === Constants ===

/// Domain-separator intent byte for `Receipt`. Schema evolution is a new
/// intent byte + a new field set, never silent mutation of this one. There is
/// no `V1`/`V2` in any type name — the schema simply changes until there are
/// users (see SPEC.md section 3).
const RECEIPT_INTENT: u8 = 0;

// === Errors ===

#[error]
const EInvalidSignature: vector<u8> = b"Ed25519 signature does not match the gateway's registered public key.";
#[error]
const ERevokedGateway: vector<u8> = b"The gateway's PCR version has been revoked by the checkpoint owner.";

// === Structs ===

/// The Receipt payload an enclave signs. Field order is normative (BCS) —
/// see SPEC.md section 3 — and must never change; new fields require a new
/// intent byte.
public struct Receipt has drop {
    receipt_id: vector<u8>,
    config_hash: vector<u8>,
    provider: u8,
    endpoint_host: String,
    tls_cert_sha256: vector<u8>,
    request_blob: u256,
    upstream_request_blob: u256,
    upstream_headers_hash: vector<u8>,
    model_id: String,
    provider_request_id: String,
    response_blob: u256,
    provider_meta_hash: vector<u8>,
    input_tokens: u64,
    cache_creation_tokens: u64,
    cache_read_tokens: u64,
    output_tokens: u64,
    outcome: u8,
}

/// Envelope wrapping a payload with a domain-separating intent byte and a
/// timestamp, BCS-serialized and Ed25519-signed by the enclave. Mirrors the
/// Nautilus template's `IntentMessage<T>` (own copy, not imported, since
/// sekisho does not depend on `kagi`/`enclave`).
public struct IntentMessage<P: drop> has drop {
    intent: u8,
    timestamp_ms: u64,
    payload: P,
}

/// The result of a successful `verify`: a droppable witness exposing every
/// Receipt field, including `receipt_id` for consumer-side replay dedup
/// (Receipts carry no onchain nonce — see SPEC.md section 8 — so consuming
/// contracts must dedupe by `receipt_id` themselves).
public struct VerifiedReceipt has drop {
    receipt_id: vector<u8>,
    config_hash: vector<u8>,
    provider: u8,
    endpoint_host: String,
    tls_cert_sha256: vector<u8>,
    request_blob: u256,
    upstream_request_blob: u256,
    upstream_headers_hash: vector<u8>,
    model_id: String,
    provider_request_id: String,
    response_blob: u256,
    provider_meta_hash: vector<u8>,
    input_tokens: u64,
    cache_creation_tokens: u64,
    cache_read_tokens: u64,
    output_tokens: u64,
    outcome: u8,
}

/// Emitted by `verify` on every successful verification, so inference history
/// is queryable rather than only reconstructable by parsing transaction
/// arguments.
///
/// Two notes on what this can and cannot tell you:
///
/// - **Only successes appear.** A failed `verify` aborts, and an abort rolls
///   back events with the rest of the transaction. There is no onchain record
///   of rejected Receipts.
/// - **Duplicates are expected.** Receipts are replayable by design, so the
///   same `receipt_id` may be verified — and emitted — more than once.
///   Indexers must still dedupe by `receipt_id`.
///
/// `verified_at_ms` is consensus time from the `Clock`, carried alongside the
/// enclave's self-reported `timestamp_ms` so the skew between them is visible
/// in the event itself rather than requiring a join against transaction
/// metadata. `pcr_version` is included so history can be filtered by code
/// version — notably, to find everything verified under a build that was later
/// revoked.
public struct ReceiptVerified has copy, drop {
    gateway: ID,
    operator: address,
    verifier: address,
    pcr_version: u64,
    receipt_id: vector<u8>,
    config_hash: vector<u8>,
    provider: u8,
    endpoint_host: String,
    tls_cert_sha256: vector<u8>,
    request_blob: u256,
    upstream_request_blob: u256,
    upstream_headers_hash: vector<u8>,
    model_id: String,
    provider_request_id: String,
    response_blob: u256,
    provider_meta_hash: vector<u8>,
    input_tokens: u64,
    cache_creation_tokens: u64,
    cache_read_tokens: u64,
    output_tokens: u64,
    outcome: u8,
    /// Enclave-reported signing time. Advisory: the enclave's clock derives
    /// from its host and is not consensus time.
    timestamp_ms: u64,
    /// Consensus time at verification, from `sui::clock::Clock`.
    verified_at_ms: u64,
}

// === Constructors ===

/// Build a `Receipt` payload. Exposed for tests and for consumers that
/// need to reconstruct the exact payload an enclave should have signed
/// (e.g. to recompute an expected signature offchain).
public fun new_receipt(
    receipt_id: vector<u8>,
    config_hash: vector<u8>,
    provider: u8,
    endpoint_host: String,
    tls_cert_sha256: vector<u8>,
    request_blob: u256,
    upstream_request_blob: u256,
    upstream_headers_hash: vector<u8>,
    model_id: String,
    provider_request_id: String,
    response_blob: u256,
    provider_meta_hash: vector<u8>,
    input_tokens: u64,
    cache_creation_tokens: u64,
    cache_read_tokens: u64,
    output_tokens: u64,
    outcome: u8,
): Receipt {
    Receipt {
        receipt_id,
        config_hash,
        provider,
        endpoint_host,
        tls_cert_sha256,
        request_blob,
        upstream_request_blob,
        upstream_headers_hash,
        model_id,
        provider_request_id,
        response_blob,
        provider_meta_hash,
        input_tokens,
        cache_creation_tokens,
        cache_read_tokens,
        output_tokens,
        outcome,
    }
}

// === Verification ===

/// Verify a Receipt was signed by `gateway`'s registered key, and that the
/// gateway's PCR version has not since been revoked in `checkpoint`. Aborts
/// with `ERevokedGateway` or `EInvalidSignature` on failure; on success,
/// consumes the `Receipt` and returns a `VerifiedReceipt`.
public fun verify(
    gateway: &Gateway,
    checkpoint: &Checkpoint,
    clock: &Clock,
    timestamp_ms: u64,
    receipt: Receipt,
    sig: &vector<u8>,
    ctx: &TxContext,
): VerifiedReceipt {
    assert!(!checkpoint.is_revoked(gateway.pcr_version()), ERevokedGateway);

    let intent_message = IntentMessage {
        intent: RECEIPT_INTENT,
        timestamp_ms,
        payload: receipt,
    };
    let signed_bytes = bcs::to_bytes(&intent_message);
    assert!(ed25519::ed25519_verify(sig, gateway.pk(), &signed_bytes), EInvalidSignature);

    let IntentMessage { payload, .. } = intent_message;
    let Receipt {
        receipt_id,
        config_hash,
        provider,
        endpoint_host,
        tls_cert_sha256,
        request_blob,
        upstream_request_blob,
        upstream_headers_hash,
        model_id,
        provider_request_id,
        response_blob,
        provider_meta_hash,
        input_tokens,
        cache_creation_tokens,
        cache_read_tokens,
        output_tokens,
        outcome,
    } = payload;

    event::emit(ReceiptVerified {
        gateway: object::id(gateway),
        operator: gateway.operator(),
        verifier: ctx.sender(),
        pcr_version: gateway.pcr_version(),
        receipt_id,
        config_hash,
        provider,
        endpoint_host,
        tls_cert_sha256,
        request_blob,
        upstream_request_blob,
        upstream_headers_hash,
        model_id,
        provider_request_id,
        response_blob,
        provider_meta_hash,
        input_tokens,
        cache_creation_tokens,
        cache_read_tokens,
        output_tokens,
        outcome,
        timestamp_ms,
        verified_at_ms: clock.timestamp_ms(),
    });

    VerifiedReceipt {
        receipt_id,
        config_hash,
        provider,
        endpoint_host,
        tls_cert_sha256,
        request_blob,
        upstream_request_blob,
        upstream_headers_hash,
        model_id,
        provider_request_id,
        response_blob,
        provider_meta_hash,
        input_tokens,
        cache_creation_tokens,
        cache_read_tokens,
        output_tokens,
        outcome,
    }
}

// === Getters ===

public fun receipt_id(receipt: &VerifiedReceipt): vector<u8> {
    receipt.receipt_id
}

public fun config_hash(receipt: &VerifiedReceipt): vector<u8> {
    receipt.config_hash
}

public fun provider(receipt: &VerifiedReceipt): u8 {
    receipt.provider
}

public fun endpoint_host(receipt: &VerifiedReceipt): String {
    receipt.endpoint_host
}

public fun tls_cert_sha256(receipt: &VerifiedReceipt): vector<u8> {
    receipt.tls_cert_sha256
}

public fun request_blob(receipt: &VerifiedReceipt): u256 {
    receipt.request_blob
}

public fun upstream_request_blob(receipt: &VerifiedReceipt): u256 {
    receipt.upstream_request_blob
}

public fun upstream_headers_hash(receipt: &VerifiedReceipt): vector<u8> {
    receipt.upstream_headers_hash
}

public fun model_id(receipt: &VerifiedReceipt): String {
    receipt.model_id
}

public fun provider_request_id(receipt: &VerifiedReceipt): String {
    receipt.provider_request_id
}

public fun response_blob(receipt: &VerifiedReceipt): u256 {
    receipt.response_blob
}

public fun provider_meta_hash(receipt: &VerifiedReceipt): vector<u8> {
    receipt.provider_meta_hash
}

public fun input_tokens(receipt: &VerifiedReceipt): u64 {
    receipt.input_tokens
}

public fun cache_creation_tokens(receipt: &VerifiedReceipt): u64 {
    receipt.cache_creation_tokens
}

public fun cache_read_tokens(receipt: &VerifiedReceipt): u64 {
    receipt.cache_read_tokens
}

public fun output_tokens(receipt: &VerifiedReceipt): u64 {
    receipt.output_tokens
}

public fun outcome(receipt: &VerifiedReceipt): u8 {
    receipt.outcome
}

// === Tests ===

#[test_only]
use std::unit_test::assert_eq;
#[test_only]
use sui::test_scenario;
#[test_only]
use sekisho::checkpoint;

// --- BCS parity vectors (docs/receipt-vectors.json) ---
//
// Both vectors below are transcribed field-for-field from
// docs/receipt-vectors.json ("nominal-anthropic-success" /
// "refusal-unarchived-max-tokens"). u64/u256 fields (timestamp_ms,
// *_tokens, *_blob) are given as decimal/hex literals here regardless of how
// the JSON source encodes them, so the JSON's number-vs-string
// representation has no bearing on these tests. `*_blob` fields are u256 and
// BCS-encode as 32 bytes little-endian; the literals below are palindromic
// under byte reversal (repeated-byte patterns, or zero), which is why the
// happy-path signature test doubles as an additional sanity check — see
// `verify_succeeds_and_exposes_all_fields` below, which round-trips a real
// Ed25519 signature over these exact bytes.

#[test]
fun bcs_parity_nominal_success() {
    let payload = new_receipt(
        x"000102030405060708090a0b0c0d0e0f",
        x"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        0,
        b"api.anthropic.com".to_string(),
        x"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        0x1111111111111111111111111111111111111111111111111111111111111111,
        0x2222222222222222222222222222222222222222222222222222222222222222,
        x"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        b"claude-haiku-4-5-20251001".to_string(),
        b"msg_011Ce3rq3tLXgrQNPLAYKda8".to_string(),
        0x3333333333333333333333333333333333333333333333333333333333333333,
        x"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        17,
        0,
        0,
        9,
        0,
    );
    let intent_message = IntentMessage {
        intent: RECEIPT_INTENT,
        timestamp_ms: 1_786_767_276_534,
        payload,
    };
    let bytes = bcs::to_bytes(&intent_message);

    let expected =
        x"00f6f9a003a001000010000102030405060708090a0b0c0d0e0f20aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00116170692e616e7468726f7069632e636f6d20bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb1111111111111111111111111111111111111111111111111111111111111111222222222222222222222222222222222222222222222222222222222222222220cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc19636c617564652d6861696b752d342d352d32303235313030311c6d73675f303131436533727133744c586772514e504c41594b646138333333333333333333333333333333333333333333333333333333333333333320dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd110000000000000000000000000000000000000000000000090000000000000000";

    assert_eq!(bytes.length(), 361);
    assert_eq!(bytes, expected);
}

#[test]
fun bcs_parity_refusal_unarchived_max_tokens() {
    let payload = new_receipt(
        x"ffffffffffffffffffffffffffffffff",
        x"0101010101010101010101010101010101010101010101010101010101010101",
        1,
        b"api.openai.com".to_string(),
        x"0202020202020202020202020202020202020202020202020202020202020202",
        0,
        0,
        x"0303030303030303030303030303030303030303030303030303030303030303",
        b"mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm".to_string(),
        b"".to_string(),
        0,
        x"0404040404040404040404040404040404040404040404040404040404040404",
        18_446_744_073_709_551_615,
        18_446_744_073_709_551_615,
        0,
        0,
        1,
    );
    let intent_message = IntentMessage {
        intent: RECEIPT_INTENT,
        timestamp_ms: 1_735_689_600_000,
        payload,
    };
    let bytes = bcs::to_bytes(&intent_message);

    let expected =
        x"00007c291f9401000010ffffffffffffffffffffffffffffffff200101010101010101010101010101010101010101010101010101010101010101010e6170692e6f70656e61692e636f6d20020202020202020202020202020202020202020202020202020202020202020200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200303030303030303030303030303030303030303030303030303030303030303c8016d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d000000000000000000000000000000000000000000000000000000000000000000200404040404040404040404040404040404040404040404040404040404040404ffffffffffffffffffffffffffffffff0000000000000000000000000000000001";

    assert_eq!(bytes.length(), 506);
    assert_eq!(bytes, expected);
}

// --- verify() happy path + aborts, against a real fixed Ed25519 keypair ---
//
// Keypair, message, and signature generated with Bun's `node:crypto` Ed25519
// support (see scratchpad `gen_ed25519_vector.ts`); the message signed is
// exactly the "nominal-anthropic-success" BCS bytes above, so this doubles as
// an end-to-end signature check over the same payload the parity test guards.

#[test_only]
const TEST_GATEWAY_PK: vector<u8> = x"66dbd11baf2bb5cdf65a9b5adc2b89846adb1186cb92ea13039d4616836f26a6";
#[test_only]
const TEST_SIG: vector<u8> =
    x"f460dd00bcb22dc496ed5e42b7df7bc32e722a71debd47cceb89077aea9d8b5e83dcfbe6fb78a0cf3b909a61d487bd0c247e71d8b3615b70c618bea94cb3f002";
#[test_only]
const TEST_BAD_SIG: vector<u8> =
    x"f460dd00bcb22dc496ed5e42b7df7bc32e722a71debd47cceb89077aea9d8b5e83dcfbe6fb78a0cf3b909a61d487bd0c247e71d8b3615b70c618bea94cb3f0fa";
#[test_only]
const TEST_TIMESTAMP_MS: u64 = 1_786_767_276_534;

#[test_only]
fun nominal_receipt_for_testing(): Receipt {
    new_receipt(
        x"000102030405060708090a0b0c0d0e0f",
        x"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        0,
        b"api.anthropic.com".to_string(),
        x"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        0x1111111111111111111111111111111111111111111111111111111111111111,
        0x2222222222222222222222222222222222222222222222222222222222222222,
        x"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        b"claude-haiku-4-5-20251001".to_string(),
        b"msg_011Ce3rq3tLXgrQNPLAYKda8".to_string(),
        0x3333333333333333333333333333333333333333333333333333333333333333,
        x"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        17,
        0,
        0,
        9,
        0,
    )
}

#[test]
fun verify_succeeds_and_exposes_all_fields() {
    let admin = @0xA;
    let mut scenario = test_scenario::begin(admin);
    checkpoint::init_for_testing(scenario.ctx());

    scenario.next_tx(admin);
    let mut cp = scenario.take_shared<checkpoint::Checkpoint>();
    let cap = scenario.take_from_sender<checkpoint::CheckpointCap>();
    let pcr_version = checkpoint::approve_pcrs(&mut cp, &cap, x"aa", x"bb", x"cc", b"v1".to_string());

    let gateway = checkpoint::new_gateway_for_testing(
        TEST_GATEWAY_PK,
        pcr_version,
        admin,
        0,
        scenario.ctx(),
    );

    let clock = sui::clock::create_for_testing(scenario.ctx());
    let sig = TEST_SIG;
    let verified = verify(
        &gateway,
        &cp,
        &clock,
        TEST_TIMESTAMP_MS,
        nominal_receipt_for_testing(),
        &sig,
        scenario.ctx(),
    );

    assert_eq!(verified.receipt_id(), x"000102030405060708090a0b0c0d0e0f");
    assert_eq!(verified.config_hash(), x"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    assert_eq!(verified.provider(), 0);
    assert_eq!(verified.endpoint_host(), b"api.anthropic.com".to_string());
    assert_eq!(
        verified.tls_cert_sha256(),
        x"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    );
    assert_eq!(verified.request_blob(), 0x1111111111111111111111111111111111111111111111111111111111111111);
    assert_eq!(
        verified.upstream_request_blob(),
        0x2222222222222222222222222222222222222222222222222222222222222222,
    );
    assert_eq!(
        verified.upstream_headers_hash(),
        x"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    );
    assert_eq!(verified.model_id(), b"claude-haiku-4-5-20251001".to_string());
    assert_eq!(verified.provider_request_id(), b"msg_011Ce3rq3tLXgrQNPLAYKda8".to_string());
    assert_eq!(verified.response_blob(), 0x3333333333333333333333333333333333333333333333333333333333333333);
    assert_eq!(
        verified.provider_meta_hash(),
        x"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    );
    assert_eq!(verified.input_tokens(), 17);
    assert_eq!(verified.cache_creation_tokens(), 0);
    assert_eq!(verified.cache_read_tokens(), 0);
    assert_eq!(verified.output_tokens(), 9);
    assert_eq!(verified.outcome(), 0);

    clock.destroy_for_testing();
    checkpoint::destroy_gateway_for_testing(gateway);
    test_scenario::return_shared(cp);
    scenario.return_to_sender(cap);
    scenario.end();
}

#[test, expected_failure(abort_code = EInvalidSignature, location = sekisho::receipt)]
fun verify_aborts_on_invalid_signature() {
    let admin = @0xA;
    let mut scenario = test_scenario::begin(admin);
    checkpoint::init_for_testing(scenario.ctx());

    scenario.next_tx(admin);
    let mut cp = scenario.take_shared<checkpoint::Checkpoint>();
    let cap = scenario.take_from_sender<checkpoint::CheckpointCap>();
    let pcr_version = checkpoint::approve_pcrs(&mut cp, &cap, x"aa", x"bb", x"cc", b"v1".to_string());

    let gateway = checkpoint::new_gateway_for_testing(
        TEST_GATEWAY_PK,
        pcr_version,
        admin,
        0,
        scenario.ctx(),
    );

    let bad_sig = TEST_BAD_SIG;
    let clock = sui::clock::create_for_testing(scenario.ctx());
    let verified = verify(
        &gateway,
        &cp,
        &clock,
        TEST_TIMESTAMP_MS,
        nominal_receipt_for_testing(),
        &bad_sig,
        scenario.ctx(),
    );
    let VerifiedReceipt { .. } = verified;

    clock.destroy_for_testing();
    checkpoint::destroy_gateway_for_testing(gateway);
    test_scenario::return_shared(cp);
    scenario.return_to_sender(cap);
    scenario.end();
}

#[test, expected_failure(abort_code = ERevokedGateway, location = sekisho::receipt)]
fun verify_aborts_on_revoked_gateway() {
    let admin = @0xA;
    let mut scenario = test_scenario::begin(admin);
    checkpoint::init_for_testing(scenario.ctx());

    scenario.next_tx(admin);
    let mut cp = scenario.take_shared<checkpoint::Checkpoint>();
    let cap = scenario.take_from_sender<checkpoint::CheckpointCap>();
    let pcr_version = checkpoint::approve_pcrs(&mut cp, &cap, x"aa", x"bb", x"cc", b"v1".to_string());

    let gateway = checkpoint::new_gateway_for_testing(
        TEST_GATEWAY_PK,
        pcr_version,
        admin,
        0,
        scenario.ctx(),
    );

    checkpoint::revoke_pcrs(&mut cp, &cap, pcr_version);

    let clock = sui::clock::create_for_testing(scenario.ctx());
    let sig = TEST_SIG;
    let verified = verify(
        &gateway,
        &cp,
        &clock,
        TEST_TIMESTAMP_MS,
        nominal_receipt_for_testing(),
        &sig,
        scenario.ctx(),
    );
    let VerifiedReceipt { .. } = verified;

    clock.destroy_for_testing();
    checkpoint::destroy_gateway_for_testing(gateway);
    test_scenario::return_shared(cp);
    scenario.return_to_sender(cap);
    scenario.end();
}
