//! `Receipt` payload, hand-rolled BCS intent serialization (byte-identical
//! to the Move side's `bcs::to_bytes(IntentMessage<Receipt>)`), signing, and
//! the in-memory ring-buffer receipt store served at `GET /receipts/:id`.
//!
//! Serialization layout (`docs/SPEC.md` §3, `docs/receipt-vectors.json`):
//! `intent(u8) || timestamp_ms(u64 LE) || receipt_id || config_hash ||
//! provider || endpoint_host || tls_cert_sha256 || request_blob ||
//! upstream_request_blob || upstream_headers_hash || model_id ||
//! provider_request_id || response_blob || provider_meta_hash ||
//! input_tokens(u64 LE) || cache_creation_tokens(u64 LE) ||
//! cache_read_tokens(u64 LE) || output_tokens(u64 LE) || outcome(u8)`.
//!
//! Two different fixed-width encodings appear for 32-byte fields, and
//! mixing them up silently produces the wrong bytes:
//! - `vector<u8>` fields (`receipt_id`, `config_hash`, `tls_cert_sha256`,
//!   `upstream_headers_hash`, `provider_meta_hash`) are BCS sequences:
//!   ULEB128 length prefix + raw bytes.
//! - `*_blob` fields (`request_blob`, `upstream_request_blob`,
//!   `response_blob`) are Move `u256` values — a fixed-width integer, BCS-
//!   encoded as exactly 32 bytes, little-endian, with NO length prefix.
//!
//! `String` fields (`endpoint_host`, `model_id`, `provider_request_id`) are
//! BCS-encoded as ULEB128 length (of the UTF-8 byte length) + UTF-8 bytes,
//! same as a `vector<u8>` of those bytes. This mirrors
//! `an internal sibling project/enclave/src/audio/intent.rs`'s hand-rolled
//! writer style.

use std::collections::VecDeque;
use std::sync::RwLock;

use serde::{Deserialize, Serialize};

/// Domain-separator byte for `IntentMessage<Receipt>`. Matches the Move
/// `RECEIPT_INTENT` constant. There is no `V1`/`V2` in this name — per
/// `docs/SPEC.md` §3, the intent byte itself is the version escape hatch if
/// an incompatible schema is ever needed, so the schema simply changes
/// until there are users rather than growing a new type name.
pub const RECEIPT_INTENT: u8 = 0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    pub receipt_id: [u8; 16],
    pub config_hash: [u8; 32],
    /// 0 = anthropic, 1 = openai-compatible (`docs/SPEC.md` §3).
    pub provider: u8,
    pub endpoint_host: String,
    pub tls_cert_sha256: [u8; 32],
    /// Walrus blob ID of the canonical client request, as 32 raw bytes —
    /// BCS-serialized as a `u256` LE fixed-width integer, no length prefix.
    pub request_blob: [u8; 32],
    /// Walrus blob ID of the canonical upstream request (captures gateway
    /// transforms). Same encoding as `request_blob`.
    pub upstream_request_blob: [u8; 32],
    pub upstream_headers_hash: [u8; 32],
    pub model_id: String,
    pub provider_request_id: String,
    /// Walrus blob ID of the canonical assembled response. Same encoding
    /// as `request_blob`.
    pub response_blob: [u8; 32],
    pub provider_meta_hash: [u8; 32],
    pub input_tokens: u64,
    pub cache_creation_tokens: u64,
    pub cache_read_tokens: u64,
    pub output_tokens: u64,
    /// 0=ok, 1=refusal, 2=upstream_error, 3=policy_denied (`docs/SPEC.md` §3).
    pub outcome: u8,
}

/// Serializes `intent(0) || timestamp_ms LE || Receipt fields` in spec
/// order. This is the exact byte sequence that gets Ed25519-signed and that
/// the Move `receipt::verify` reconstructs via `bcs::to_bytes`.
pub fn serialize_intent_message(payload: &Receipt, timestamp_ms: u64) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(
        1 + 8   // intent + timestamp_ms
        + 1 + 16 // receipt_id
        + 1 + 32 // config_hash
        + 1      // provider
        + 1 + payload.endpoint_host.len()
        + 1 + 32 // tls_cert_sha256
        + 32     // request_blob (fixed, no prefix)
        + 32     // upstream_request_blob (fixed, no prefix)
        + 1 + 32 // upstream_headers_hash
        + 1 + payload.model_id.len()
        + 1 + payload.provider_request_id.len()
        + 32     // response_blob (fixed, no prefix)
        + 1 + 32 // provider_meta_hash
        + 8 + 8 + 8 + 8 // token counters
        + 1, // outcome
    );
    bytes.push(RECEIPT_INTENT);
    bytes.extend_from_slice(&timestamp_ms.to_le_bytes());
    write_bcs_bytes(&mut bytes, &payload.receipt_id);
    write_bcs_bytes(&mut bytes, &payload.config_hash);
    bytes.push(payload.provider);
    write_bcs_string(&mut bytes, &payload.endpoint_host);
    write_bcs_bytes(&mut bytes, &payload.tls_cert_sha256);
    write_u256_le(&mut bytes, &payload.request_blob);
    write_u256_le(&mut bytes, &payload.upstream_request_blob);
    write_bcs_bytes(&mut bytes, &payload.upstream_headers_hash);
    write_bcs_string(&mut bytes, &payload.model_id);
    write_bcs_string(&mut bytes, &payload.provider_request_id);
    write_u256_le(&mut bytes, &payload.response_blob);
    write_bcs_bytes(&mut bytes, &payload.provider_meta_hash);
    bytes.extend_from_slice(&payload.input_tokens.to_le_bytes());
    bytes.extend_from_slice(&payload.cache_creation_tokens.to_le_bytes());
    bytes.extend_from_slice(&payload.cache_read_tokens.to_le_bytes());
    bytes.extend_from_slice(&payload.output_tokens.to_le_bytes());
    bytes.push(payload.outcome);
    bytes
}

/// BCS byte-vector: ULEB128 length prefix + raw bytes.
fn write_bcs_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    write_uleb128(buf, bytes.len());
    buf.extend_from_slice(bytes);
}

/// BCS string: ULEB128 length prefix (of the UTF-8 byte length) + UTF-8 bytes.
fn write_bcs_string(buf: &mut Vec<u8>, value: &str) {
    write_uleb128(buf, value.len());
    buf.extend_from_slice(value.as_bytes());
}

/// BCS `u256`: exactly 32 bytes, little-endian, NO length prefix — a
/// fixed-width integer, not a `vector<u8>`. `bytes` is already the raw LE
/// byte representation (see `blob::compute_blob_id_bytes`), so this is a
/// direct copy, kept as a named function so every call site documents the
/// "no prefix" property instead of a bare `extend_from_slice`.
fn write_u256_le(buf: &mut Vec<u8>, bytes: &[u8; 32]) {
    buf.extend_from_slice(bytes);
}

/// Appends `value` as an unsigned LEB128 varint, matching BCS sequence-length encoding.
fn write_uleb128(buf: &mut Vec<u8>, mut value: usize) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if value == 0 {
            break;
        }
    }
}

/// A receipt as stored in the ring buffer / served at `GET /receipts/:id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredReceipt {
    pub receipt_id: String,
    pub timestamp_ms: u64,
    pub config_hash: String,
    pub provider: u8,
    pub endpoint_host: String,
    pub tls_cert_sha256: String,
    pub request_blob: String,
    pub upstream_request_blob: String,
    pub upstream_headers_hash: String,
    pub model_id: String,
    pub provider_request_id: String,
    pub response_blob: String,
    pub provider_meta_hash: String,
    pub input_tokens: u64,
    pub cache_creation_tokens: u64,
    pub cache_read_tokens: u64,
    pub output_tokens: u64,
    pub outcome: u8,
    pub signature: String,
}

impl StoredReceipt {
    pub fn new(payload: &Receipt, timestamp_ms: u64, signature: &[u8; 64]) -> Self {
        Self {
            // Hex, like every other byte field: a client reconstructing the
            // signed BCS payload from this JSON must decode all byte fields the
            // same way. A dashed UUID here would be the one special case, and
            // feeding it to a hex decoder either throws or silently yields the
            // wrong bytes. `ReceiptStore::get` still accepts the dashed form so
            // a hand-pasted UUID resolves.
            receipt_id: hex::encode(payload.receipt_id),
            timestamp_ms,
            config_hash: hex::encode(payload.config_hash),
            provider: payload.provider,
            endpoint_host: payload.endpoint_host.clone(),
            tls_cert_sha256: hex::encode(payload.tls_cert_sha256),
            // `*_blob` fields are hex of the raw 32 LE bytes here too (not
            // the decimal u256 string form used in `docs/receipt-vectors.json`
            // JSON fixtures) — consistent with every other byte field on
            // this struct; a client already hex-decodes the hash fields, so
            // hex here avoids a second decoding convention.
            request_blob: hex::encode(payload.request_blob),
            upstream_request_blob: hex::encode(payload.upstream_request_blob),
            upstream_headers_hash: hex::encode(payload.upstream_headers_hash),
            model_id: payload.model_id.clone(),
            provider_request_id: payload.provider_request_id.clone(),
            response_blob: hex::encode(payload.response_blob),
            provider_meta_hash: hex::encode(payload.provider_meta_hash),
            input_tokens: payload.input_tokens,
            cache_creation_tokens: payload.cache_creation_tokens,
            cache_read_tokens: payload.cache_read_tokens,
            output_tokens: payload.output_tokens,
            outcome: payload.outcome,
            signature: hex::encode(signature),
        }
    }
}

pub const DEFAULT_RING_BUFFER_SIZE: usize = 4096;

/// Bounded in-memory receipt store. No disk persistence (`docs/SPEC.md` §4).
pub struct ReceiptStore {
    capacity: usize,
    entries: RwLock<VecDeque<StoredReceipt>>,
}

impl ReceiptStore {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            entries: RwLock::new(VecDeque::with_capacity(capacity.max(1))),
        }
    }

    /// Inserts a receipt, evicting the oldest entry if at capacity.
    pub fn insert(&self, receipt: StoredReceipt) {
        let mut entries = self
            .entries
            .write()
            .unwrap_or_else(|poison| poison.into_inner());
        if entries.len() >= self.capacity {
            entries.pop_front();
        }
        entries.push_back(receipt);
    }

    /// Looks up a receipt by id. Receipts are stored and served with a hex
    /// `receipt_id`, but the dashed UUID form is accepted too so an id copied
    /// out of a log or an older `x-receipt-id` header still resolves.
    pub fn get(&self, receipt_id: &str) -> Option<StoredReceipt> {
        let wanted = receipt_id.replace('-', "").to_ascii_lowercase();
        let entries = self
            .entries
            .read()
            .unwrap_or_else(|poison| poison.into_inner());
        entries
            .iter()
            .rev()
            .find(|entry| entry.receipt_id == wanted)
            .cloned()
    }
}

impl Default for ReceiptStore {
    fn default() -> Self {
        Self::new(DEFAULT_RING_BUFFER_SIZE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn hash_fill(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn empty_receipt() -> Receipt {
        Receipt {
            receipt_id: [0; 16],
            config_hash: [0; 32],
            provider: 0,
            endpoint_host: String::new(),
            tls_cert_sha256: [0; 32],
            request_blob: [0; 32],
            upstream_request_blob: [0; 32],
            upstream_headers_hash: [0; 32],
            model_id: String::new(),
            provider_request_id: String::new(),
            response_blob: [0; 32],
            provider_meta_hash: [0; 32],
            input_tokens: 0,
            cache_creation_tokens: 0,
            cache_read_tokens: 0,
            output_tokens: 0,
            outcome: 0,
        }
    }

    /// Vector 1 from `docs/receipt-vectors.json` ("nominal-anthropic-success").
    #[test]
    fn parity_vector_nominal_anthropic_success() {
        let payload = Receipt {
            receipt_id: [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f,
            ],
            config_hash: hash_fill(0xaa),
            provider: 0,
            endpoint_host: "api.anthropic.com".to_owned(),
            tls_cert_sha256: hash_fill(0xbb),
            request_blob: [0x11; 32],
            upstream_request_blob: [0x22; 32],
            upstream_headers_hash: hash_fill(0xcc),
            model_id: "claude-haiku-4-5-20251001".to_owned(),
            provider_request_id: "msg_011Ce3rq3tLXgrQNPLAYKda8".to_owned(),
            response_blob: [0x33; 32],
            provider_meta_hash: hash_fill(0xdd),
            input_tokens: 17,
            cache_creation_tokens: 0,
            cache_read_tokens: 0,
            output_tokens: 9,
            outcome: 0,
        };
        let timestamp_ms = 1_786_767_276_534u64;

        let bytes = serialize_intent_message(&payload, timestamp_ms);

        let expected_hex = "00f6f9a003a001000010000102030405060708090a0b0c0d0e0f20aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00116170692e616e7468726f7069632e636f6d20bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb1111111111111111111111111111111111111111111111111111111111111111222222222222222222222222222222222222222222222222222222222222222220cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc19636c617564652d6861696b752d342d352d32303235313030311c6d73675f303131436533727133744c586772514e504c41594b646138333333333333333333333333333333333333333333333333333333333333333320dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd110000000000000000000000000000000000000000000000090000000000000000";
        assert_eq!(bytes.len(), 361);
        assert_eq!(hex::encode(&bytes), expected_hex);
    }

    /// Vector 2 from `docs/receipt-vectors.json`
    /// ("refusal-unarchived-max-tokens") — exercises `u64::MAX`, zero
    /// (unarchived) blob IDs, an empty `provider_request_id`, and a
    /// 200-character `model_id` (multi-byte ULEB128 length prefix).
    #[test]
    fn parity_vector_refusal_unarchived_max_tokens() {
        let payload = Receipt {
            receipt_id: [0xff; 16],
            config_hash: hash_fill(0x01),
            provider: 1,
            endpoint_host: "api.openai.com".to_owned(),
            tls_cert_sha256: hash_fill(0x02),
            request_blob: [0; 32],
            upstream_request_blob: [0; 32],
            upstream_headers_hash: hash_fill(0x03),
            model_id: "m".repeat(200),
            provider_request_id: String::new(),
            response_blob: [0; 32],
            provider_meta_hash: hash_fill(0x04),
            input_tokens: u64::MAX,
            cache_creation_tokens: u64::MAX,
            cache_read_tokens: 0,
            output_tokens: 0,
            outcome: 1,
        };
        let timestamp_ms = 1_735_689_600_000u64;

        let bytes = serialize_intent_message(&payload, timestamp_ms);

        let expected_hex = "00007c291f9401000010ffffffffffffffffffffffffffffffff200101010101010101010101010101010101010101010101010101010101010101010e6170692e6f70656e61692e636f6d20020202020202020202020202020202020202020202020202020202020202020200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200303030303030303030303030303030303030303030303030303030303030303c8016d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d000000000000000000000000000000000000000000000000000000000000000000200404040404040404040404040404040404040404040404040404040404040404ffffffffffffffffffffffffffffffff0000000000000000000000000000000001";
        assert_eq!(bytes.len(), 506);
        assert_eq!(hex::encode(&bytes), expected_hex);
    }

    #[test]
    fn uleb128_multi_byte_length_matches_model_id_prefix() {
        // "m" * 200 -> ULEB128(200) = 0xc8, 0x01 (200 = 0b1100_1000).
        let mut buf = Vec::new();
        write_uleb128(&mut buf, 200);
        assert_eq!(buf, vec![0xc8, 0x01]);
    }

    #[test]
    fn blob_fields_are_fixed_32_bytes_with_no_length_prefix() {
        // Unlike `config_hash` (a `vector<u8>`, which gets a `0x20` ULEB128
        // prefix before its 32 bytes), a `*_blob` field's 32 bytes must
        // appear with nothing in front of them: this test isolates that
        // property by comparing byte offsets rather than relying on a full
        // fixture round-trip.
        let mut payload = empty_receipt();
        payload.request_blob = [0x77; 32];
        let bytes = serialize_intent_message(&payload, 0);
        // intent(1) + timestamp(8) + receipt_id(1 prefix + 16) +
        // config_hash(1 prefix + 32) + provider(1) + endpoint_host(1 prefix
        // + 0) + tls_cert_sha256(1 prefix + 32) = 1+8+17+33+1+1+33 = 94.
        let request_blob_offset = 1 + 8 + 17 + 33 + 1 + 1 + 33;
        assert_eq!(
            &bytes[request_blob_offset..request_blob_offset + 32],
            &[0x77u8; 32]
        );
    }

    #[test]
    fn ring_buffer_evicts_oldest_when_over_capacity() {
        let store = ReceiptStore::new(2);
        let make = |id: [u8; 16]| {
            let payload = Receipt {
                receipt_id: id,
                ..empty_receipt()
            };
            StoredReceipt::new(&payload, 0, &[0; 64])
        };
        let first = make([1; 16]);
        let second = make([2; 16]);
        let third = make([3; 16]);
        let first_id = first.receipt_id.clone();
        let third_id = third.receipt_id.clone();

        store.insert(first);
        store.insert(second);
        store.insert(third);

        assert!(store.get(&first_id).is_none());
        assert!(store.get(&third_id).is_some());
    }

    #[test]
    fn stored_receipt_id_is_hex_and_lookup_accepts_the_dashed_uuid_form() {
        let id = [0xab; 16];
        let payload = Receipt {
            receipt_id: id,
            ..empty_receipt()
        };
        let stored = StoredReceipt::new(&payload, 0, &[0; 64]);

        // Served as hex, so a client decodes every byte field the same way.
        assert_eq!(stored.receipt_id, hex::encode(id));

        let store = ReceiptStore::new(4);
        store.insert(stored);

        assert!(store.get(&hex::encode(id)).is_some());
        assert!(store.get(&Uuid::from_bytes(id).to_string()).is_some());
        assert!(store.get(&hex::encode(id).to_ascii_uppercase()).is_some());
        assert!(store.get(&hex::encode([0x01; 16])).is_none());
    }
}
