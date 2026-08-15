//! Local (no-network) Walrus blob ID computation for the `request_blob` /
//! `upstream_request_blob` / `response_blob` receipt fields
//! (`docs/SPEC.md` §3). A Walrus blob ID is derived from content (encoding
//! tag + unencoded length + Merkle root over the slivers), so it commits to
//! bytes exactly as a hash would, while additionally addressing them —
//! computed here purely locally (never by contacting a Walrus node), so a
//! receipt never depends on a storage write succeeding. `0` means "computed
//! but not archived" per spec; this module only ever produces `0` for
//! genuinely empty/oversized-beyond-Walrus-limits input, which receipt
//! payloads never are in practice.
//!
//! `walrus-core` (pinned to the same rev as
//! `an internal sibling project/enclave`, the house precedent for exactly this
//! dependency) built and linked cleanly against this crate — see the task
//! report for confirmation. The fallback path described in the task brief
//! (a stub returning zeros, for when `walrus-core` cannot be made to build)
//! was therefore not needed; `compute_blob_id_bytes` below is the real,
//! local `walrus-core`-backed implementation used unconditionally.

use std::num::NonZeroU16;

use walrus_core::encoding::{EncodingConfig, EncodingFactory as _};
use walrus_core::{BlobId, DEFAULT_ENCODING};

/// Walrus mainnet's shard count. The blob ID's Merkle root is computed over
/// per-shard slivers, so `n_shards` is part of what a blob ID commits to —
/// this must stay fixed for a receipt's `*_blob` fields to mean the same
/// thing across enclave builds (and to match a real mainnet-archived blob's
/// ID, should the content later actually be stored on Walrus).
const WALRUS_N_SHARDS: u16 = 1000;

/// Computes the Walrus blob ID for `canonical_bytes` and returns it as raw
/// 32 bytes.
///
/// These bytes are BCS-serialized as a `u256` little-endian fixed-width
/// integer (`docs/SPEC.md` §3) — i.e. written with NO ULEB128 length
/// prefix, unlike this crate's `vector<u8>` fields (see `receipt.rs`).
/// `BlobId`'s inner `[u8; 32]` is used directly as those LE bytes, matching
/// `an internal sibling project/enclave/src/audio/walrus.rs`'s
/// `blob_id_bcs_u256_bytes` — the house precedent for this exact
/// byte-representation choice.
pub fn compute_blob_id_bytes(canonical_bytes: &[u8]) -> [u8; 32] {
    let n_shards = NonZeroU16::new(WALRUS_N_SHARDS).expect("WALRUS_N_SHARDS is non-zero");
    let config = EncodingConfig::new(n_shards).get_for_type(DEFAULT_ENCODING);
    match config.compute_blob_id(canonical_bytes) {
        Ok(id) => id.0,
        // Encoding only fails when the input exceeds Walrus's maximum blob
        // size; receipt payloads (JSON request/response bodies bounded by
        // `DEFAULT_MAX_BODY_BYTES`) never come close. Falling back to the
        // documented "not archived" sentinel keeps this failure mode
        // non-fatal to receipt issuance rather than panicking.
        Err(_) => BlobId::ZERO.0,
    }
}

/// Canonicalizes `value` then computes its Walrus blob ID in one step — the
/// blob analog of `canonical::sha256_of`.
pub fn blob_id_of<T: serde::Serialize>(value: &T) -> serde_json::Result<[u8; 32]> {
    Ok(compute_blob_id_bytes(&crate::canonical::canonical_bytes(
        value,
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_bytes_produce_the_same_blob_id() {
        let a = compute_blob_id_bytes(b"hello receipt");
        let b = compute_blob_id_bytes(b"hello receipt");
        assert_eq!(a, b);
    }

    #[test]
    fn different_bytes_produce_different_blob_ids() {
        let a = compute_blob_id_bytes(b"request one");
        let b = compute_blob_id_bytes(b"request two");
        assert_ne!(a, b);
    }

    #[test]
    fn non_empty_input_never_produces_the_zero_sentinel() {
        let id = compute_blob_id_bytes(b"non-empty canonical bytes");
        assert_ne!(id, [0u8; 32]);
    }
}
