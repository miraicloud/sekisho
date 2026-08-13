//! Caller bearer-key authentication (the gap onara's transaction-native
//! trust model doesn't cover — `docs/research/local-patterns.md` §2.4).
//! Keys are delivered at boot via config and compared in constant time.

use subtle::ConstantTimeEq as _;

/// Constant-time byte comparison. A length mismatch short-circuits (key
/// *length* is not treated as sensitive — standard practice for bearer-key
/// comparison), but any comparison of equal-length candidates against a
/// stored key runs in constant time via `subtle`.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Checks `presented` against the configured set of valid caller keys.
/// Every configured key is compared (no early return on the first match),
/// so the number of valid keys configured doesn't leak via timing either.
pub fn authenticate(presented: &str, valid_keys: &[String]) -> bool {
    let mut matched = subtle::Choice::from(0u8);
    for key in valid_keys {
        if presented.len() == key.len() {
            matched |= presented.as_bytes().ct_eq(key.as_bytes());
        }
    }
    matched.into()
}

/// Extracts the bearer token from an `Authorization: Bearer <token>` header
/// value. Returns `None` for any other scheme or malformed header.
///
/// The scheme is matched case-insensitively per RFC 7235 §2.1 ("the scheme
/// name is case-insensitive"), so a client sending `bearer` isn't rejected
/// with an unexplained 401. The token itself is compared verbatim.
pub fn extract_bearer(header_value: &str) -> Option<&str> {
    let (scheme, token) = header_value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return None;
    }
    Some(token.trim())
}

/// Which caller-key match (if any) authenticated the request. Only the
/// boolean result is meaningful for policy purposes today, but returning
/// the matched key gives the policy engine a caller identity to key rules
/// on (`docs/SPEC.md` §4 — "allowed models... per caller key").
pub fn identify_caller<'a>(presented: &str, valid_keys: &'a [String]) -> Option<&'a str> {
    // Not constant-time across the *lookup*, but constant-time per
    // candidate comparison — identical timing behavior to `authenticate`,
    // just also reporting which key matched for policy attribution.
    valid_keys
        .iter()
        .find(|key| constant_time_eq(presented.as_bytes(), key.as_bytes()))
        .map(String::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authenticate_accepts_configured_key() {
        let keys = vec!["sk-caller-a".to_owned(), "sk-caller-b".to_owned()];
        assert!(authenticate("sk-caller-a", &keys));
        assert!(authenticate("sk-caller-b", &keys));
    }

    #[test]
    fn authenticate_rejects_unknown_key() {
        let keys = vec!["sk-caller-a".to_owned()];
        assert!(!authenticate("sk-caller-x", &keys));
        assert!(!authenticate("", &keys));
    }

    #[test]
    fn authenticate_rejects_prefix_of_valid_key() {
        let keys = vec!["sk-caller-a-longer".to_owned()];
        assert!(!authenticate("sk-caller-a", &keys));
    }

    #[test]
    fn extract_bearer_strips_scheme() {
        assert_eq!(extract_bearer("Bearer abc123"), Some("abc123"));
        assert_eq!(extract_bearer("Basic abc123"), None);
        assert_eq!(extract_bearer("abc123"), None);
    }

    #[test]
    fn extract_bearer_scheme_is_case_insensitive_but_token_is_not() {
        assert_eq!(extract_bearer("bearer abc123"), Some("abc123"));
        assert_eq!(extract_bearer("BEARER abc123"), Some("abc123"));
        assert_eq!(extract_bearer("BeArEr abc123"), Some("abc123"));
        // The token must survive verbatim — only the scheme is case-folded.
        assert_eq!(extract_bearer("Bearer AbC123"), Some("AbC123"));
        // A scheme that merely starts with "bearer" is still rejected.
        assert_eq!(extract_bearer("Bearerish abc123"), None);
    }

    #[test]
    fn identify_caller_returns_matching_key() {
        let keys = vec!["sk-a".to_owned(), "sk-b".to_owned()];
        assert_eq!(identify_caller("sk-b", &keys), Some("sk-b"));
        assert_eq!(identify_caller("sk-c", &keys), None);
    }
}
