// Copyright (c) 2026 miraicloud
// SPDX-License-Identifier: Apache-2.0

/// Cheap, per-request verification of a signed inference Receipt against a
/// registered `Gateway`'s Ed25519 public key. The expensive attestation-chain
/// check happens once, in `sekisho::checkpoint::register`; every Receipt
/// thereafter is a single `sui::ed25519::ed25519_verify` call.
///
/// BCS layout (`ReceiptV1` field order) is normative — see SPEC.md section 3 —
/// and is guarded byte-for-byte by `test_bcs_parity_nominal_success` /
/// `test_bcs_parity_refusal_long_model_max_tokens` below against
/// `docs/receipt-v1-vectors.json`.
module sekisho::receipt;

use std::bcs;
use std::string::String;
use sui::clock::Clock;
use sui::ed25519;
use sui::event;
use sekisho::checkpoint::{Checkpoint, Gateway};

// === Constants ===

/// Domain-separator intent byte for `ReceiptV1`. Schema evolution is a new
/// intent byte + new payload struct (`ReceiptV2`), never mutation of this one.
const RECEIPT_INTENT_V1: u8 = 0;

// === Errors ===

#[error]
const EInvalidSignature: vector<u8> = b"Ed25519 signature does not match the gateway's registered public key.";
#[error]
const ERevokedGateway: vector<u8> = b"The gateway's PCR version has been revoked by the checkpoint owner.";

// === Structs ===

/// The Receipt payload an enclave signs. Field order is normative (BCS) —
/// see SPEC.md section 3 — and must never change; new fields require a new
/// intent byte and a new struct (`ReceiptV2`).
public struct ReceiptV1 has drop {
    receipt_id: vector<u8>,
    config_hash: vector<u8>,
    request_hash: vector<u8>,
    upstream_request_hash: vector<u8>,
    model_id: String,
    response_hash: vector<u8>,
    input_tokens: u64,
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
    request_hash: vector<u8>,
    upstream_request_hash: vector<u8>,
    model_id: String,
    response_hash: vector<u8>,
    input_tokens: u64,
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
    request_hash: vector<u8>,
    upstream_request_hash: vector<u8>,
    model_id: String,
    response_hash: vector<u8>,
    input_tokens: u64,
    output_tokens: u64,
    outcome: u8,
    /// Enclave-reported signing time. Advisory: the enclave's clock derives
    /// from its host and is not consensus time.
    timestamp_ms: u64,
    /// Consensus time at verification, from `sui::clock::Clock`.
    verified_at_ms: u64,
}

// === Constructors ===

/// Build a `ReceiptV1` payload. Exposed for tests and for consumers that
/// need to reconstruct the exact payload an enclave should have signed
/// (e.g. to recompute an expected signature offchain).
public fun new_receipt_v1(
    receipt_id: vector<u8>,
    config_hash: vector<u8>,
    request_hash: vector<u8>,
    upstream_request_hash: vector<u8>,
    model_id: String,
    response_hash: vector<u8>,
    input_tokens: u64,
    output_tokens: u64,
    outcome: u8,
): ReceiptV1 {
    ReceiptV1 {
        receipt_id,
        config_hash,
        request_hash,
        upstream_request_hash,
        model_id,
        response_hash,
        input_tokens,
        output_tokens,
        outcome,
    }
}

// === Verification ===

/// Verify a Receipt was signed by `gateway`'s registered key, and that the
/// gateway's PCR version has not since been revoked in `checkpoint`. Aborts
/// with `ERevokedGateway` or `EInvalidSignature` on failure; on success,
/// consumes the `ReceiptV1` and returns a `VerifiedReceipt`.
public fun verify(
    gateway: &Gateway,
    checkpoint: &Checkpoint,
    clock: &Clock,
    timestamp_ms: u64,
    receipt: ReceiptV1,
    sig: &vector<u8>,
    ctx: &TxContext,
): VerifiedReceipt {
    assert!(!checkpoint.is_revoked(gateway.pcr_version()), ERevokedGateway);

    let intent_message = IntentMessage {
        intent: RECEIPT_INTENT_V1,
        timestamp_ms,
        payload: receipt,
    };
    let signed_bytes = bcs::to_bytes(&intent_message);
    assert!(ed25519::ed25519_verify(sig, gateway.pk(), &signed_bytes), EInvalidSignature);

    let IntentMessage { payload, .. } = intent_message;
    let ReceiptV1 {
        receipt_id,
        config_hash,
        request_hash,
        upstream_request_hash,
        model_id,
        response_hash,
        input_tokens,
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
        request_hash,
        upstream_request_hash,
        model_id,
        response_hash,
        input_tokens,
        output_tokens,
        outcome,
        timestamp_ms,
        verified_at_ms: clock.timestamp_ms(),
    });

    VerifiedReceipt {
        receipt_id,
        config_hash,
        request_hash,
        upstream_request_hash,
        model_id,
        response_hash,
        input_tokens,
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

public fun request_hash(receipt: &VerifiedReceipt): vector<u8> {
    receipt.request_hash
}

public fun upstream_request_hash(receipt: &VerifiedReceipt): vector<u8> {
    receipt.upstream_request_hash
}

public fun model_id(receipt: &VerifiedReceipt): String {
    receipt.model_id
}

public fun response_hash(receipt: &VerifiedReceipt): vector<u8> {
    receipt.response_hash
}

public fun input_tokens(receipt: &VerifiedReceipt): u64 {
    receipt.input_tokens
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

// --- BCS parity vectors (docs/receipt-v1-vectors.json) ---
//
// Both vectors below are transcribed field-for-field from
// docs/receipt-v1-vectors.json ("nominal-success" / "refusal-long-model-max-tokens").
// u64 fields (timestamp_ms/input_tokens/output_tokens) are given as decimal
// literals here regardless of how the JSON source encodes them, so the JSON's
// number-vs-string representation has no bearing on these tests.

#[test]
fun bcs_parity_nominal_success() {
    let payload = new_receipt_v1(
        x"000102030405060708090a0b0c0d0e0f",
        x"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        x"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        x"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        b"claude-sonnet-5".to_string(),
        x"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        1_000,
        250,
        0,
    );
    let intent_message = IntentMessage {
        intent: RECEIPT_INTENT_V1,
        timestamp_ms: 1_234_567_890_123,
        payload,
    };
    let bytes = bcs::to_bytes(&intent_message);

    let expected =
        x"00cb04fb711f01000010000102030405060708090a0b0c0d0e0f20aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa20bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb20cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc0f636c617564652d736f6e6e65742d3520dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddde803000000000000fa0000000000000000";

    assert_eq!(bytes.length(), 191);
    assert_eq!(bytes, expected);
}

#[test]
fun bcs_parity_refusal_long_model_max_tokens() {
    let payload = new_receipt_v1(
        x"ffffffffffffffffffffffffffffffff",
        x"0101010101010101010101010101010101010101010101010101010101010101",
        x"0202020202020202020202020202020202020202020202020202020202020202",
        x"0303030303030303030303030303030303030303030303030303030303030303",
        b"mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm".to_string(),
        x"0404040404040404040404040404040404040404040404040404040404040404",
        18_446_744_073_709_551_615,
        0,
        1,
    );
    let intent_message = IntentMessage {
        intent: RECEIPT_INTENT_V1,
        timestamp_ms: 1_735_689_600_000,
        payload,
    };
    let bytes = bcs::to_bytes(&intent_message);

    let expected =
        x"00007c291f9401000010ffffffffffffffffffffffffffffffff200101010101010101010101010101010101010101010101010101010101010101200202020202020202020202020202020202020202020202020202020202020202200303030303030303030303030303030303030303030303030303030303030303c8016d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d200404040404040404040404040404040404040404040404040404040404040404ffffffffffffffff000000000000000001";

    assert_eq!(bytes.length(), 377);
    assert_eq!(bytes, expected);
}

// --- verify() happy path + aborts, against a real fixed Ed25519 keypair ---
//
// Keypair, message, and signature generated with Bun's `node:crypto` Ed25519
// support (see scratchpad `gen_ed25519_vector.ts`); the message signed is
// exactly the "nominal-success" BCS bytes above, so this doubles as an
// end-to-end signature check over the same payload the parity test guards.

#[test_only]
const TEST_GATEWAY_PK: vector<u8> = x"87d1373725f4f0035291eb14bdefb52c76e7a9e7463247f5382c2d7ef33ec51d";
#[test_only]
const TEST_SIG: vector<u8> =
    x"d3e621b1b29ec24fa4e3fb8ff2f0b3074e82f7acd370a7312fd38855807070cd22ac5bf5e3483e3fed8f60d94380e0847bdaa0dc9d5678ad4263b73237743c05";
#[test_only]
const TEST_BAD_SIG: vector<u8> =
    x"d3e621b1b29ec24fa4e3fb8ff2f0b3074e82f7acd370a7312fd38855807070cd22ac5bf5e3483e3fed8f60d94380e0847bdaa0dc9d5678ad4263b73237743cfa";
#[test_only]
const TEST_TIMESTAMP_MS: u64 = 1_234_567_890_123;

#[test_only]
fun nominal_receipt_for_testing(): ReceiptV1 {
    new_receipt_v1(
        x"000102030405060708090a0b0c0d0e0f",
        x"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        x"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        x"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        b"claude-sonnet-5".to_string(),
        x"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        1_000,
        250,
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
    assert_eq!(verified.request_hash(), x"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    assert_eq!(
        verified.upstream_request_hash(),
        x"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    );
    assert_eq!(verified.model_id(), b"claude-sonnet-5".to_string());
    assert_eq!(verified.response_hash(), x"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");
    assert_eq!(verified.input_tokens(), 1_000);
    assert_eq!(verified.output_tokens(), 250);
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
