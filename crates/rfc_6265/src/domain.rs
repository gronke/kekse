//! RFC 6265 §5.1.3 domain matching, plus the §5.1.2 host canonicalization it assumes.
//!
//! <https://www.rfc-editor.org/rfc/rfc6265#section-5.1.3>
//!
//! Both arguments to [`domain_matches`] are expected to be [`canonicalize`]d first.

use std::net::IpAddr;

/// Canonicalize a host for comparison — RFC 6265 §5.1.2. Performs the ASCII lower-casing the
/// algorithm requires; full IDNA/punycode conversion of non-ASCII labels is out of scope (a future
/// feature), so such labels are only ASCII-case-folded.
#[must_use]
pub fn canonicalize(host: &str) -> String {
    host.to_ascii_lowercase()
}

/// Whether `host` **domain-matches** `domain` per RFC 6265 §5.1.3: they are identical, or `domain`
/// is a suffix of `host` immediately preceded by a `.` and `host` is not an IP literal. Both
/// arguments should already be [`canonicalize`]d, and `domain` should have no leading dot.
#[must_use]
pub fn domain_matches(host: &str, domain: &str) -> bool {
    if host == domain {
        return true;
    }
    if domain.is_empty() {
        return false;
    }
    let Some(prefix) = host.strip_suffix(domain) else {
        return false;
    };
    // The character before the suffix must be the label boundary `.`, and a host that is an IP
    // literal can only match by identity (handled above).
    prefix.ends_with('.') && host.parse::<IpAddr>().is_err()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_matches() {
        assert!(domain_matches("example.com", "example.com"));
    }

    #[test]
    fn suffix_on_a_dot_boundary_matches() {
        assert!(domain_matches("foo.example.com", "example.com"));
        assert!(domain_matches("a.b.example.com", "example.com"));
    }

    #[test]
    fn suffix_without_a_dot_boundary_does_not_match() {
        assert!(!domain_matches("badexample.com", "example.com"));
        assert!(!domain_matches("example.com", "ample.com"));
    }

    #[test]
    fn longer_or_empty_domain_does_not_match() {
        assert!(!domain_matches("example.com", "www.example.com"));
        assert!(!domain_matches("example.com", ""));
    }

    #[test]
    fn ip_hosts_match_only_by_identity() {
        assert!(domain_matches("192.168.0.1", "192.168.0.1"));
        assert!(!domain_matches("192.168.0.1", "168.0.1"));
        assert!(domain_matches("::1", "::1"));
    }

    #[test]
    fn canonicalize_lowercases_ascii() {
        assert_eq!(canonicalize("EXAMPLE.Com"), "example.com");
    }
}
