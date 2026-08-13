//! `ReceiptV1` payload, hand-rolled BCS intent serialization (byte-identical
//! to the Move side's `bcs::to_bytes(IntentMessage<ReceiptV1>)`), signing,
//! and the in-memory ring-buffer receipt store served at `GET /receipts/:id`.
//!
//! Serialization layout (`docs/SPEC.md` §3, `docs/receipt-v1-vectors.json`):
//! `intent(u8) || timestamp_ms(u64 LE) || receipt_id || config_hash ||
//! request_hash || upstream_request_hash || model_id || response_hash ||
//! input_tokens(u64 LE) || output_tokens(u64 LE) || outcome(u8)`, with
//! `vector<u8>`/`String` fields BCS-encoded as ULEB128 length + bytes. This
//! mirrors `an internal sibling project/enclave/src/audio/intent.rs` exactly.

use std::collections::VecDeque;
use std::sync::RwLock;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Domain-separator byte for `IntentMessage<ReceiptV1>`. Matches the Move
/// `RECEIPT_INTENT_V1` constant.
pub const RECEIPT_INTENT_V1: u8 = 0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptV1 {
    pub receipt_id: [u8; 16],
    pub config_hash: [u8; 32],
    pub request_hash: [u8; 32],
    pub upstream_request_hash: [u8; 32],
    pub model_id: String,
    pub response_hash: [u8; 32],
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub outcome: u8,
}

/// Serializes `intent(0) || timestamp_ms LE || ReceiptV1 fields` in spec
/// order. This is the exact byte sequence that gets Ed25519-signed and that
/// the Move `receipt::verify` reconstructs via `bcs::to_bytes`.
pub fn serialize_intent_message(payload: &ReceiptV1, timestamp_ms: u64) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(
        1 + 8 + 1 + 16 + 1 + 32 + 1 + 32 + 1 + 32 + 1 + payload.model_id.len() + 1 + 32 + 8 + 8 + 1,
    );
    bytes.push(RECEIPT_INTENT_V1);
    bytes.extend_from_slice(&timestamp_ms.to_le_bytes());
    write_bcs_bytes(&mut bytes, &payload.receipt_id);
    write_bcs_bytes(&mut bytes, &payload.config_hash);
    write_bcs_bytes(&mut bytes, &payload.request_hash);
    write_bcs_bytes(&mut bytes, &payload.upstream_request_hash);
    write_bcs_string(&mut bytes, &payload.model_id);
    write_bcs_bytes(&mut bytes, &payload.response_hash);
    bytes.extend_from_slice(&payload.input_tokens.to_le_bytes());
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
    pub request_hash: String,
    pub upstream_request_hash: String,
    pub model_id: String,
    pub response_hash: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub outcome: u8,
    pub signature: String,
}

impl StoredReceipt {
    pub fn new(payload: &ReceiptV1, timestamp_ms: u64, signature: &[u8; 64]) -> Self {
        Self {
            receipt_id: Uuid::from_bytes(payload.receipt_id).to_string(),
            timestamp_ms,
            config_hash: hex::encode(payload.config_hash),
            request_hash: hex::encode(payload.request_hash),
            upstream_request_hash: hex::encode(payload.upstream_request_hash),
            model_id: payload.model_id.clone(),
            response_hash: hex::encode(payload.response_hash),
            input_tokens: payload.input_tokens,
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

    /// Looks up a receipt by its string `receipt_id` (UUID form).
    pub fn get(&self, receipt_id: &str) -> Option<StoredReceipt> {
        let entries = self
            .entries
            .read()
            .unwrap_or_else(|poison| poison.into_inner());
        entries
            .iter()
            .rev()
            .find(|entry| entry.receipt_id == receipt_id)
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

    fn hash_fill(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    /// Vector 1 from `docs/receipt-v1-vectors.json` ("nominal-success").
    #[test]
    fn parity_vector_nominal_success() {
        let payload = ReceiptV1 {
            receipt_id: [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f,
            ],
            config_hash: hash_fill(0xaa),
            request_hash: hash_fill(0xbb),
            upstream_request_hash: hash_fill(0xcc),
            model_id: "claude-sonnet-5".to_owned(),
            response_hash: hash_fill(0xdd),
            input_tokens: 1000,
            output_tokens: 250,
            outcome: 0,
        };
        let timestamp_ms = 1_234_567_890_123u64;

        let bytes = serialize_intent_message(&payload, timestamp_ms);

        let expected_hex = "00cb04fb711f01000010000102030405060708090a0b0c0d0e0f20aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa20bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb20cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc0f636c617564652d736f6e6e65742d3520dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddde803000000000000fa0000000000000000";
        assert_eq!(bytes.len(), 191);
        assert_eq!(hex::encode(&bytes), expected_hex);
    }

    /// Vector 2 from `docs/receipt-v1-vectors.json`
    /// ("refusal-long-model-max-tokens") — exercises `u64::MAX` and a
    /// 200-character `model_id` (multi-byte ULEB128 length prefix).
    #[test]
    fn parity_vector_refusal_long_model_max_tokens() {
        let payload = ReceiptV1 {
            receipt_id: [0xff; 16],
            config_hash: hash_fill(0x01),
            request_hash: hash_fill(0x02),
            upstream_request_hash: hash_fill(0x03),
            model_id: "m".repeat(200),
            response_hash: hash_fill(0x04),
            input_tokens: u64::MAX,
            output_tokens: 0,
            outcome: 1,
        };
        let timestamp_ms = 1_735_689_600_000u64;

        let bytes = serialize_intent_message(&payload, timestamp_ms);

        let expected_hex = "00007c291f9401000010ffffffffffffffffffffffffffffffff200101010101010101010101010101010101010101010101010101010101010101200202020202020202020202020202020202020202020202020202020202020202200303030303030303030303030303030303030303030303030303030303030303c8016d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d200404040404040404040404040404040404040404040404040404040404040404ffffffffffffffff000000000000000001";
        assert_eq!(bytes.len(), 377);
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
    fn ring_buffer_evicts_oldest_when_over_capacity() {
        let store = ReceiptStore::new(2);
        let make = |id: [u8; 16]| StoredReceipt {
            receipt_id: Uuid::from_bytes(id).to_string(),
            timestamp_ms: 0,
            config_hash: String::new(),
            request_hash: String::new(),
            upstream_request_hash: String::new(),
            model_id: String::new(),
            response_hash: String::new(),
            input_tokens: 0,
            output_tokens: 0,
            outcome: 0,
            signature: String::new(),
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
}
