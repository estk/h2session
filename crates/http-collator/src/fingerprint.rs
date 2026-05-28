//! Request fingerprinting — a deterministic xxhash3-64 over canonicalised
//! request headers that survives proxy stream-ID renumbering and HPACK
//! re-encoding.
//!
//! See docs/correlator-failure-modes.md (snif repo) for context: this is the
//! signal that lets the binary-agnostic `fifo-fingerprint` correlator pair
//! ingress and egress exchanges across an HTTP/2 proxy hop.
//!
//! Determinism matters across processes and runs because eventual consumers
//! may compare fingerprints across snif instances. xxhash3 has no per-process
//! seed and is ~10x faster than SipHash for short header inputs.

use http::{HeaderMap, Method, Uri};
use twox_hash::XxHash3_64;

/// Header names that proxies legitimately add, strip, or rewrite, plus the
/// `x-id` test-injected per-request disambiguator. Excluded from the
/// fingerprint so:
///
/// - the same logical request fingerprints identically on the ingress and
///   egress side of a proxy (RFC 7230 §6.1 hop-by-hop headers + the
///   `Forwarded` / `X-Forwarded-*` / `Via` chain proxies inject), and
/// - test-driven traffic that distinguishes requests only by `x-id`
///   collapses into fingerprint-collision buckets, exercising the
///   degenerate-FIFO fallback path that the strategy must handle correctly
///   in production.
const EXCLUDED_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "x-forwarded-for",
    "x-forwarded-proto",
    "x-forwarded-host",
    "x-forwarded-port",
    "forwarded",
    "via",
    "x-id",
];

/// Compute a deterministic fingerprint over the request's logical content.
/// Returns the same `u64` (across processes, machines, runs) for two requests
/// that carry the same method, path, authority, and non-excluded headers —
/// even if HPACK encoding, header iteration order, or HTTP/2 stream IDs
/// differ between the two observations.
pub fn compute_request_fingerprint(
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
) -> u64 {
    use std::hash::{Hash, Hasher};

    let mut hasher = XxHash3_64::new();

    method.as_str().hash(&mut hasher);
    b'\n'.hash(&mut hasher);
    uri.path().hash(&mut hasher);
    b'\n'.hash(&mut hasher);
    if let Some(authority) = uri.authority() {
        authority.as_str().hash(&mut hasher);
    }
    b'\n'.hash(&mut hasher);

    // Sort headers by name to make the hash insensitive to HeaderMap iteration
    // order (HPACK-dependent on HTTP/2). Skip non-UTF-8 values (binary headers).
    let mut entries: Vec<(String, String)> = Vec::new();
    for (name, value) in headers.iter() {
        let name_lower = name.as_str().to_ascii_lowercase();
        if EXCLUDED_HEADERS.contains(&name_lower.as_str()) {
            continue;
        }
        let v = match value.to_str() {
            Ok(s) => s.to_owned(),
            Err(_) => continue,
        };
        entries.push((name_lower, v));
    }
    entries.sort();
    for (name, value) in &entries {
        name.hash(&mut hasher);
        b'\0'.hash(&mut hasher);
        value.hash(&mut hasher);
        b'\n'.hash(&mut hasher);
    }

    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::header::{HeaderName, HeaderValue};

    fn hv(s: &str) -> HeaderValue {
        s.parse().unwrap()
    }

    fn build(method: &str, path: &str, hdrs: &[(&str, &str)]) -> u64 {
        let m: Method = method.parse().unwrap();
        let u: Uri = path.parse().unwrap();
        let mut h = HeaderMap::new();
        for (name, value) in hdrs {
            h.append(HeaderName::from_bytes(name.as_bytes()).unwrap(), hv(value));
        }
        compute_request_fingerprint(&m, &u, &h)
    }

    #[test]
    fn same_request_hashes_same() {
        let a = build("GET", "/api/users/1", &[("x-id", "abc"), ("user-agent", "ua")]);
        let b = build("GET", "/api/users/1", &[("x-id", "abc"), ("user-agent", "ua")]);
        assert_eq!(a, b);
    }

    #[test]
    fn header_order_does_not_matter() {
        let a = build("GET", "/x", &[("a", "1"), ("b", "2")]);
        let b = build("GET", "/x", &[("b", "2"), ("a", "1")]);
        assert_eq!(a, b);
    }

    #[test]
    fn header_case_does_not_matter() {
        let a = build("GET", "/x", &[("X-ID", "abc")]);
        let b = build("GET", "/x", &[("x-id", "abc")]);
        assert_eq!(a, b);
    }

    #[test]
    fn excluded_proxy_headers_are_ignored() {
        // Proxy-injected forwarded chain must not change the fingerprint.
        let a = build("GET", "/x", &[("user-agent", "ua")]);
        let b = build(
            "GET",
            "/x",
            &[
                ("user-agent", "ua"),
                ("x-forwarded-for", "10.0.0.1"),
                ("via", "1.1 haproxy"),
                ("forwarded", "for=10.0.0.1"),
            ],
        );
        assert_eq!(a, b);
    }

    #[test]
    fn x_id_is_excluded_from_fingerprint() {
        // Validation invariant: the gauntlet distinguishes requests only by
        // x-id, and the fingerprint MUST exclude it so that gauntlet traffic
        // exercises the fingerprint-collision fallback path.
        let a = build("GET", "/api/resource/1", &[("x-id", "h2e2e-c0-s0")]);
        let b = build("GET", "/api/resource/1", &[("x-id", "h2e2e-c0-s1")]);
        assert_eq!(a, b, "x-id must not affect the fingerprint");
    }

    #[test]
    fn different_path_hashes_differently() {
        let a = build("GET", "/api/users/1", &[]);
        let b = build("GET", "/api/users/2", &[]);
        assert_ne!(a, b);
    }

    #[test]
    fn different_method_hashes_differently() {
        let a = build("GET", "/x", &[]);
        let b = build("POST", "/x", &[]);
        assert_ne!(a, b);
    }

    #[test]
    fn different_distinguishing_header_hashes_differently() {
        // A non-excluded header (`x-request-id`) DOES change the fingerprint.
        // Demonstrates that the strategy isn't structurally crippled — only
        // x-id is suppressed.
        let a = build("GET", "/api/resource/1", &[("x-request-id", "abc")]);
        let b = build("GET", "/api/resource/1", &[("x-request-id", "xyz")]);
        assert_ne!(a, b);
    }

    #[test]
    fn fingerprint_is_deterministic_across_invocations() {
        // xxhash3 is unseeded — same input must produce the same output every
        // time, regardless of process state.
        let a = build("GET", "/x", &[("user-agent", "ua")]);
        let b = build("GET", "/x", &[("user-agent", "ua")]);
        let c = build("GET", "/x", &[("user-agent", "ua")]);
        assert_eq!(a, b);
        assert_eq!(b, c);
    }
}
