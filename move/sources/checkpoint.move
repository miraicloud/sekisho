// Copyright (c) 2026 miraicloud
// SPDX-License-Identifier: Apache-2.0

/// The trust root for sekisho: a shared `Checkpoint` object holding the set of
/// approved Nitro Enclave PCR0/1/2 measurements ("code versions"), and the
/// permissionless registration of `Gateway` objects from a verified attestation
/// document.
///
/// Implements Nautilus's verify-once / sign-cheap split directly on
/// `sui::nitro_attestation` + `sui::ed25519` (no `kagi` dependency): the expensive
/// attestation-chain verification happens once per enclave boot, in `register`;
/// every subsequent Receipt is checked with a cheap Ed25519 verify in
/// `sekisho::receipt`, against the `pk` captured here.
module sekisho::checkpoint;

use std::bcs;
use std::string::String;
use sui::nitro_attestation::NitroAttestationDocument;

// === Errors ===

#[error]
const EPcrsNotApproved: vector<u8> = b"No approved PCR entry matches this attestation document's PCR0/1/2.";
#[error]
const EPcrsRevoked: vector<u8> = b"The matching PCR entry has been revoked by the checkpoint owner.";
#[error]
const EMissingPublicKey: vector<u8> = b"The attestation document did not commit to a public key.";
#[error]
const ENotGatewayOperator: vector<u8> = b"Only the operator that registered a Gateway may destroy it.";
#[error]
const EEntryIndexOutOfBounds: vector<u8> = b"No approved PCR entry exists at this version index.";
#[error]
const ENonceNotSender: vector<u8> =
    b"The attestation document's nonce does not commit to the registering sender's address.";
#[error]
const EMissingPcr: vector<u8> = b"The attestation document is missing PCR0, PCR1, or PCR2.";

// === Structs ===

/// One-time witness for the checkpoint package.
public struct CHECKPOINT has drop {}

/// A single approved code version: the exact PCR0/1/2 triple a Nitro Enclave
/// must attest, plus a human-readable reference to the source it was built
/// from. `revoked` supports NEAR AI-style onchain build revocation without
/// removing history (entries are never deleted, only flagged).
public struct PcrSet has store {
    pcr0: vector<u8>,
    pcr1: vector<u8>,
    pcr2: vector<u8>,
    code_ref: String,
    revoked: bool,
}

/// Shared trust-root object. `approved_pcrs` is append-only; an entry's index
/// in this vector is its monotonically increasing `pcr_version`.
public struct Checkpoint has key {
    id: UID,
    approved_pcrs: vector<PcrSet>,
}

/// Held by the checkpoint publisher; gates `approve_pcrs` and `revoke_pcrs`.
/// Registration itself (`register`) is deliberately NOT gated by this cap —
/// any enclave whose attestation matches an approved, non-revoked entry may
/// register itself.
public struct CheckpointCap has key, store {
    id: UID,
}

/// A registered gateway instance: an enclave that has proven (via Nitro
/// attestation, checked once at registration) that it is running an
/// approved PCR version, plus the ephemeral Ed25519 public key that
/// attestation committed to.
public struct Gateway has key {
    id: UID,
    pk: vector<u8>,
    pcr_version: u64,
    operator: address,
    registered_at_ms: u64,
}

// === Init ===

fun init(otw: CHECKPOINT, ctx: &mut TxContext) {
    let checkpoint = Checkpoint {
        id: object::new(ctx),
        approved_pcrs: vector[],
    };
    let cap = CheckpointCap {
        id: object::new(ctx),
    };

    // OTW is otherwise unused (single-instance guarantee is enforced by the
    // Sui runtime at publish time); consume it to keep the `otw` binding
    // logically tied to the checkpoint it authorizes.
    let CHECKPOINT {} = otw;

    transfer::share_object(checkpoint);
    transfer::transfer(cap, ctx.sender());
}

// === Cap-gated: approve / revoke code versions ===

/// Approve a new PCR0/1/2 triple as a valid code version. Returns the new
/// entry's `pcr_version` (its index in `approved_pcrs`).
public fun approve_pcrs(
    checkpoint: &mut Checkpoint,
    _cap: &CheckpointCap,
    pcr0: vector<u8>,
    pcr1: vector<u8>,
    pcr2: vector<u8>,
    code_ref: String,
): u64 {
    let version = checkpoint.approved_pcrs.length();
    checkpoint.approved_pcrs.push_back(PcrSet { pcr0, pcr1, pcr2, code_ref, revoked: false });
    version
}

/// Revoke a previously approved PCR version. Existing `Gateway` objects
/// registered against this version remain onchain (so operators can be
/// notified / clean them up) but `sekisho::receipt::verify` will refuse to
/// verify any Receipt from a gateway whose `pcr_version` is revoked.
public fun revoke_pcrs(checkpoint: &mut Checkpoint, _cap: &CheckpointCap, version: u64) {
    assert!(version < checkpoint.approved_pcrs.length(), EEntryIndexOutOfBounds);
    let entry = &mut checkpoint.approved_pcrs[version];
    entry.revoked = true;
}

// === Testable seam ===
//
// `sui::nitro_attestation::NitroAttestationDocument` is produced only by the
// native `load_nitro_attestation` function and cannot be forged in a unit
// test. To keep the decision logic itself testable with plain `vector<u8>`
// values, both PCR-matching (`find_matching_entry`) and the full
// nonce-then-PCR validation (`validate_and_find_version`) are factored out
// below, taking raw bytes rather than a document. `register` is then thin,
// document-consuming glue: it extracts PCR0/1/2, the nonce, and the public
// key from the (already natively-verified) document and defers every
// decision to `validate_and_find_version`.

/// Find the index of an approved entry whose PCR0/1/2 exactly match the given
/// bytes, if any — revoked or not (callers distinguish "no match" from
/// "matched but revoked" themselves, since those are different failure
/// modes with different abort codes).
fun find_matching_entry(
    checkpoint: &Checkpoint,
    pcr0: &vector<u8>,
    pcr1: &vector<u8>,
    pcr2: &vector<u8>,
): Option<u64> {
    let n = checkpoint.approved_pcrs.length();
    let mut i = 0;
    let mut found = option::none();
    while (i < n) {
        let entry = &checkpoint.approved_pcrs[i];
        if (&entry.pcr0 == pcr0 && &entry.pcr1 == pcr1 && &entry.pcr2 == pcr2) {
            found = option::some(i);
            break
        };
        i = i + 1;
    };
    found
}

/// Pure core of `register`'s decision-making, taking plain bytes so it is
/// unit-testable without a `NitroAttestationDocument`.
///
/// `nonce` is the attestation document's nonce; `expected_sender_bytes` is
/// `bcs::to_bytes(&ctx.sender())` for the address invoking `register`. This
/// binds the attestation to the registering address: attestation documents
/// are served publicly (e.g. `GET /attestation` on the enclave), so a bare
/// document is a bearer token — without this check, anyone who fetches
/// another operator's document could register themselves as `operator` on a
/// `Gateway` holding that operator's public key, then `destroy_gateway` it
/// (DoS) or spam duplicate `Gateway`s. The enclave is expected to place the
/// caller's intended Sui address in the attestation's `user_data`/`nonce`
/// slot before requesting attestation (mirrors the pattern the official
/// Nautilus template uses to bind a nonce to a specific request).
///
/// Aborts `ENonceNotSender` if the nonce doesn't match, `EPcrsNotApproved`
/// if no approved entry matches the PCRs, `EPcrsRevoked` if the matching
/// entry has been revoked. Returns the matching `pcr_version` on success.
fun validate_and_find_version(
    checkpoint: &Checkpoint,
    nonce: &vector<u8>,
    expected_sender_bytes: &vector<u8>,
    pcr0: &vector<u8>,
    pcr1: &vector<u8>,
    pcr2: &vector<u8>,
): u64 {
    assert!(nonce == expected_sender_bytes, ENonceNotSender);

    let entry_idx = find_matching_entry(checkpoint, pcr0, pcr1, pcr2);
    assert!(entry_idx.is_some(), EPcrsNotApproved);
    let pcr_version = entry_idx.destroy_some();

    let entry = &checkpoint.approved_pcrs[pcr_version];
    assert!(!entry.revoked, EPcrsRevoked);

    pcr_version
}

// === Permissionless registration ===

/// Return the value of the PCR whose `index()` is `wanted`, aborting
/// `EMissingPcr` if the document does not carry it. Looking entries up by
/// index rather than by position keeps registration correct regardless of how
/// many PCRs a given Sui protocol version includes, or in what order.
fun pcr_by_index(pcrs: &vector<sui::nitro_attestation::PCREntry>, wanted: u8): vector<u8> {
    let mut i = 0;
    while (i < pcrs.length()) {
        let entry = &pcrs[i];
        if (entry.index() == wanted) {
            return *entry.value()
        };
        i = i + 1;
    };
    abort EMissingPcr
}

/// Register a `Gateway` from a natively-verified Nitro attestation document.
/// PERMISSIONLESS: no capability is required — any enclave whose PCR0/1/2
/// match a non-revoked approved entry, and whose attestation nonce commits to
/// `ctx.sender()`, may register itself. The document's authenticity (AWS
/// certificate chain, timestamp) was already checked by
/// `sui::nitro_attestation::load_nitro_attestation` before this call, typically
/// earlier in the same PTB.
///
/// Note: PCRs are looked up by their `index()`, not by position in
/// `document.pcrs()`. Protocol versions from Sui's "upgraded parsing" onward
/// always include required PCRs 0-4 and 8, but which entries appear (and in
/// what order) has changed across protocol versions, so relying on position
/// would silently break a correct enclave.
public fun register(checkpoint: &Checkpoint, document: NitroAttestationDocument, ctx: &mut TxContext) {
    let pcrs = document.pcrs();
    let pcr0 = pcr_by_index(pcrs, 0);
    let pcr1 = pcr_by_index(pcrs, 1);
    let pcr2 = pcr_by_index(pcrs, 2);

    let nonce_opt = document.nonce();
    assert!(nonce_opt.is_some(), ENonceNotSender);
    let nonce = *nonce_opt.borrow();

    let expected_sender_bytes = bcs::to_bytes(&ctx.sender());
    let pcr_version = validate_and_find_version(
        checkpoint,
        &nonce,
        &expected_sender_bytes,
        &pcr0,
        &pcr1,
        &pcr2,
    );

    let pk_opt = document.public_key();
    assert!(pk_opt.is_some(), EMissingPublicKey);
    let pk = *pk_opt.borrow();

    // Attestation time, not a caller-supplied argument — `register` takes no
    // timestamp parameter, so there is nothing for a caller to lie about.
    let registered_at_ms = *document.timestamp();

    let gateway = Gateway {
        id: object::new(ctx),
        pk,
        pcr_version,
        operator: ctx.sender(),
        registered_at_ms,
    };

    transfer::share_object(gateway);
}

/// The registering operator may tear down their own `Gateway`, e.g. after an
/// enclave reboot rotates its ephemeral key and a fresh `Gateway` has been
/// registered to replace it.
public fun destroy_gateway(gateway: Gateway, ctx: &TxContext) {
    assert!(gateway.operator == ctx.sender(), ENotGatewayOperator);
    let Gateway { id, .. } = gateway;
    id.delete();
}

// === Getters ===

public fun is_revoked(checkpoint: &Checkpoint, version: u64): bool {
    checkpoint.approved_pcrs[version].revoked
}

public fun code_ref(checkpoint: &Checkpoint, version: u64): String {
    checkpoint.approved_pcrs[version].code_ref
}

public fun approved_pcrs_count(checkpoint: &Checkpoint): u64 {
    checkpoint.approved_pcrs.length()
}

public fun pk(gateway: &Gateway): &vector<u8> {
    &gateway.pk
}

public fun pcr_version(gateway: &Gateway): u64 {
    gateway.pcr_version
}

public fun operator(gateway: &Gateway): address {
    gateway.operator
}

public fun registered_at_ms(gateway: &Gateway): u64 {
    gateway.registered_at_ms
}

// === Tests ===

#[test_only]
use sui::test_scenario;

#[test_only]
public fun init_for_testing(ctx: &mut TxContext) {
    init(CHECKPOINT {}, ctx);
}

#[test_only]
public fun new_gateway_for_testing(
    pk: vector<u8>,
    pcr_version: u64,
    operator: address,
    registered_at_ms: u64,
    ctx: &mut TxContext,
): Gateway {
    Gateway { id: object::new(ctx), pk, pcr_version, operator, registered_at_ms }
}

#[test_only]
public fun destroy_gateway_for_testing(gateway: Gateway) {
    let Gateway { id, .. } = gateway;
    id.delete();
}

#[test]
fun init_shares_checkpoint_and_transfers_cap_to_publisher() {
    let admin = @0xA;
    let mut scenario = test_scenario::begin(admin);
    init_for_testing(scenario.ctx());

    scenario.next_tx(admin);
    assert!(scenario.has_most_recent_for_sender<CheckpointCap>());
    let checkpoint = scenario.take_shared<Checkpoint>();
    assert_eq!(checkpoint.approved_pcrs_count(), 0);

    test_scenario::return_shared(checkpoint);
    scenario.end();
}

#[test]
fun approve_then_revoke_pcrs() {
    let admin = @0xA;
    let mut scenario = test_scenario::begin(admin);
    init_for_testing(scenario.ctx());

    scenario.next_tx(admin);
    let mut checkpoint = scenario.take_shared<Checkpoint>();
    let cap = scenario.take_from_sender<CheckpointCap>();

    let version = approve_pcrs(
        &mut checkpoint,
        &cap,
        x"aa",
        x"bb",
        x"cc",
        b"v1.0.0".to_string(),
    );
    assert_eq!(version, 0);
    assert!(!checkpoint.is_revoked(version));
    assert_eq!(checkpoint.code_ref(version), b"v1.0.0".to_string());

    // Approving a second version increments the index monotonically.
    let version2 = approve_pcrs(&mut checkpoint, &cap, x"dd", x"ee", x"ff", b"v1.1.0".to_string());
    assert_eq!(version2, 1);

    revoke_pcrs(&mut checkpoint, &cap, version);
    assert!(checkpoint.is_revoked(version));
    assert!(!checkpoint.is_revoked(version2));

    test_scenario::return_shared(checkpoint);
    scenario.return_to_sender(cap);
    scenario.end();
}

#[test, expected_failure(abort_code = EEntryIndexOutOfBounds, location = sekisho::checkpoint)]
fun revoke_pcrs_out_of_bounds_aborts() {
    let admin = @0xA;
    let mut scenario = test_scenario::begin(admin);
    init_for_testing(scenario.ctx());

    scenario.next_tx(admin);
    let mut checkpoint = scenario.take_shared<Checkpoint>();
    let cap = scenario.take_from_sender<CheckpointCap>();

    revoke_pcrs(&mut checkpoint, &cap, 0);

    test_scenario::return_shared(checkpoint);
    scenario.return_to_sender(cap);
    scenario.end();
}

#[test]
fun find_matching_entry_distinguishes_no_match_from_revoked() {
    let admin = @0xA;
    let mut scenario = test_scenario::begin(admin);
    init_for_testing(scenario.ctx());

    scenario.next_tx(admin);
    let mut checkpoint = scenario.take_shared<Checkpoint>();
    let cap = scenario.take_from_sender<CheckpointCap>();

    let v0 = approve_pcrs(&mut checkpoint, &cap, x"01", x"02", x"03", b"v0".to_string());

    // Exact match on a non-revoked entry.
    let found = find_matching_entry(&checkpoint, &x"01", &x"02", &x"03");
    assert!(found.is_some());
    assert_eq!(found.destroy_some(), v0);

    // No entry has these PCRs at all.
    let not_found = find_matching_entry(&checkpoint, &x"99", &x"02", &x"03");
    assert!(not_found.is_none());

    // After revocation the entry is still *found* (register() distinguishes
    // "not approved" from "revoked" using this same seam), just flagged.
    revoke_pcrs(&mut checkpoint, &cap, v0);
    let still_found = find_matching_entry(&checkpoint, &x"01", &x"02", &x"03");
    assert!(still_found.is_some());
    assert!(checkpoint.is_revoked(still_found.destroy_some()));

    test_scenario::return_shared(checkpoint);
    scenario.return_to_sender(cap);
    scenario.end();
}

#[test]
fun validate_and_find_version_happy_path() {
    let admin = @0xA;
    let mut scenario = test_scenario::begin(admin);
    init_for_testing(scenario.ctx());

    scenario.next_tx(admin);
    let mut checkpoint = scenario.take_shared<Checkpoint>();
    let cap = scenario.take_from_sender<CheckpointCap>();

    let v0 = approve_pcrs(&mut checkpoint, &cap, x"01", x"02", x"03", b"v0".to_string());

    let sender_bytes = bcs::to_bytes(&admin);
    let pcr_version = validate_and_find_version(
        &checkpoint,
        &sender_bytes,
        &sender_bytes,
        &x"01",
        &x"02",
        &x"03",
    );
    assert_eq!(pcr_version, v0);

    test_scenario::return_shared(checkpoint);
    scenario.return_to_sender(cap);
    scenario.end();
}

#[test, expected_failure(abort_code = ENonceNotSender, location = sekisho::checkpoint)]
fun validate_and_find_version_nonce_mismatch_aborts() {
    let admin = @0xA;
    let attacker = @0xB;
    let mut scenario = test_scenario::begin(admin);
    init_for_testing(scenario.ctx());

    scenario.next_tx(admin);
    let mut checkpoint = scenario.take_shared<Checkpoint>();
    let cap = scenario.take_from_sender<CheckpointCap>();

    approve_pcrs(&mut checkpoint, &cap, x"01", x"02", x"03", b"v0".to_string());

    // Attestation nonce commits to a different address than the one calling
    // `register` — this is exactly the bearer-token replay this check
    // prevents (attacker fetches operator's public attestation document and
    // tries to register it under their own address).
    let nonce = bcs::to_bytes(&admin);
    let expected_sender_bytes = bcs::to_bytes(&attacker);
    validate_and_find_version(&checkpoint, &nonce, &expected_sender_bytes, &x"01", &x"02", &x"03");

    test_scenario::return_shared(checkpoint);
    scenario.return_to_sender(cap);
    scenario.end();
}

#[test, expected_failure(abort_code = EPcrsNotApproved, location = sekisho::checkpoint)]
fun validate_and_find_version_unapproved_pcrs_aborts() {
    let admin = @0xA;
    let mut scenario = test_scenario::begin(admin);
    init_for_testing(scenario.ctx());

    scenario.next_tx(admin);
    let mut checkpoint = scenario.take_shared<Checkpoint>();
    let cap = scenario.take_from_sender<CheckpointCap>();

    approve_pcrs(&mut checkpoint, &cap, x"01", x"02", x"03", b"v0".to_string());

    let sender_bytes = bcs::to_bytes(&admin);
    // Nonce is correctly bound, but no approved entry has these PCRs.
    validate_and_find_version(&checkpoint, &sender_bytes, &sender_bytes, &x"ff", &x"02", &x"03");

    test_scenario::return_shared(checkpoint);
    scenario.return_to_sender(cap);
    scenario.end();
}

#[test, expected_failure(abort_code = EPcrsRevoked, location = sekisho::checkpoint)]
fun validate_and_find_version_revoked_pcrs_aborts() {
    let admin = @0xA;
    let mut scenario = test_scenario::begin(admin);
    init_for_testing(scenario.ctx());

    scenario.next_tx(admin);
    let mut checkpoint = scenario.take_shared<Checkpoint>();
    let cap = scenario.take_from_sender<CheckpointCap>();

    let v0 = approve_pcrs(&mut checkpoint, &cap, x"01", x"02", x"03", b"v0".to_string());
    revoke_pcrs(&mut checkpoint, &cap, v0);

    let sender_bytes = bcs::to_bytes(&admin);
    validate_and_find_version(&checkpoint, &sender_bytes, &sender_bytes, &x"01", &x"02", &x"03");

    test_scenario::return_shared(checkpoint);
    scenario.return_to_sender(cap);
    scenario.end();
}

#[test]
fun gateway_getters_and_operator_destroy() {
    let operator = @0xB;
    let ctx = &mut tx_context::dummy();
    let gateway = new_gateway_for_testing(x"1234", 0, operator, 1_700_000_000_000, ctx);

    assert_eq!(*gateway.pk(), x"1234");
    assert_eq!(gateway.pcr_version(), 0);
    assert_eq!(gateway.operator(), operator);
    assert_eq!(gateway.registered_at_ms(), 1_700_000_000_000);

    destroy_gateway_for_testing(gateway);
}

#[test, expected_failure(abort_code = ENotGatewayOperator, location = sekisho::checkpoint)]
fun destroy_gateway_by_non_operator_aborts() {
    let operator = @0xB;
    let attacker = @0xC;
    let mut scenario = test_scenario::begin(operator);
    let gateway = new_gateway_for_testing(x"1234", 0, operator, 0, scenario.ctx());

    scenario.next_tx(attacker);
    destroy_gateway(gateway, scenario.ctx());

    scenario.end();
}

#[test]
fun destroy_gateway_by_operator_succeeds() {
    let operator = @0xB;
    let mut scenario = test_scenario::begin(operator);
    let gateway = new_gateway_for_testing(x"1234", 0, operator, 0, scenario.ctx());

    destroy_gateway(gateway, scenario.ctx());

    scenario.end();
}

#[test_only]
use std::unit_test::assert_eq;
