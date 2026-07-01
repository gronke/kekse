//! RFC 6265 §5.1.3 domain matching, the §5.1.2 host canonicalization it assumes, and the host-name
//! syntax (RFC 952 / RFC 1123 "LDH") it implies.
//!
//! <https://www.rfc-editor.org/rfc/rfc6265#section-5.1.3>
//!
//! Inputs to [`domain_matches`] are expected to be [`canonicalize`]d, with any leading dot stripped
//! from the cookie `domain` (RFC 6265 §5.2.3). Beyond that, both sides are validated as host names
//! ([`is_host_name`]) before the suffix test, so a string carrying characters a host name cannot
//! hold can never match.

use std::net::IpAddr;

/// Canonicalize a host for comparison — RFC 6265 §5.1.2: the ASCII lower-casing the algorithm
/// requires. Full IDNA/punycode (UTS-46 ToASCII) conversion of non-ASCII labels is provided by the
/// `idna` feature (`to_ascii`); without it, non-ASCII labels are only ASCII-case-folded.
///
/// ```
/// use rfc_6265::domain::canonicalize;
/// assert_eq!(canonicalize("EXAMPLE.Com"), "example.com");
/// ```
#[must_use]
pub fn canonicalize(host: &str) -> String {
    host.to_ascii_lowercase()
}

/// Whether `s` is a syntactically valid ASCII host name: one or more `.`-separated labels, each a
/// non-empty run of ASCII letters, digits, or `-` (the RFC 952 / RFC 1123 "LDH" rule). This rejects
/// anything a host name cannot hold — `:`, `@`, `/`, whitespace, embedded userinfo, empty labels, a
/// leading or trailing dot. Internationalized names must already be punycode-encoded to ASCII (full
/// IDNA, §5.1.2, is a future feature). An all-numeric string such as an IPv4 literal is LDH-valid;
/// [`domain_matches`] handles IP hosts separately.
///
/// ```
/// use rfc_6265::domain::is_host_name;
/// assert!(is_host_name("sub.example.com") && is_host_name("192.168.0.1"));
/// assert!(!is_host_name(".example.com") && !is_host_name("a..b") && !is_host_name("ex ample"));
/// ```
#[must_use]
pub fn is_host_name(s: &str) -> bool {
    !s.is_empty()
        && s.split('.').all(|label| {
            !label.is_empty()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

/// Whether `host` **domain-matches** `domain` per RFC 6265 §5.1.3: they are identical, or `domain`
/// is a suffix of `host` immediately preceded by a `.` (a label boundary) and `host` is not an IP
/// literal. Both arguments should already be [`canonicalize`]d, with any leading dot stripped from
/// `domain` (§5.2.3).
///
/// Beyond the identity case both sides must be valid host names ([`is_host_name`]); a host or
/// cookie-domain carrying non-name characters (e.g. the embedded userinfo in
/// `example.org:hack@attackercontrolled.example.com`) never matches. The label-boundary rule is
/// what stops `hostileexample.org` from matching `example.org`: the character before the suffix
/// would be `e`, not `.`.
///
/// ```
/// use rfc_6265::domain::domain_matches;
/// assert!(domain_matches("foo.example.com", "example.com")); // label-boundary suffix
/// assert!(!domain_matches("badexample.com", "example.com")); // not a boundary
/// ```
#[must_use]
pub fn domain_matches(host: &str, domain: &str) -> bool {
    if host == domain {
        return true;
    }
    if !is_host_name(host) || !is_host_name(domain) {
        return false;
    }
    // An IP-literal host can only match by identity (handled above), never by suffix.
    if host.parse::<IpAddr>().is_ok() {
        return false;
    }
    match host.strip_suffix(domain) {
        Some(prefix) => prefix.ends_with('.'),
        None => false,
    }
}

// ---- IDN (UTS-46), behind the `idna` feature -------------------------------

/// Convert `host` to its canonical ASCII form per RFC 6265 §5.1.2 — UTS-46 ToASCII (punycode
/// A-labels) plus lower-casing. `None` if `host` is not a valid IDN / host name. After this,
/// [`domain_matches`] / [`is_host_name`] operate on the ASCII form. (`idna` feature.)
///
/// ```
/// use rfc_6265::domain::to_ascii;
/// assert_eq!(to_ascii("münchen.de").as_deref(), Some("xn--mnchen-3ya.de"));
/// assert_eq!(to_ascii("xn--").as_deref(), None); // malformed punycode
/// ```
#[cfg(feature = "idna")]
#[must_use]
pub fn to_ascii(host: &str) -> Option<String> {
    idna::domain_to_ascii(host).ok().filter(|s| !s.is_empty())
}

/// Whether `host` is a valid host name **or** internationalized domain name — i.e. it has a
/// canonical ASCII form ([`to_ascii`]). Stricter than [`is_host_name`] (ASCII-LDH only): it accepts
/// well-formed `xn--` punycode and rejects malformed punycode. (`idna` feature.)
///
/// ```
/// use rfc_6265::domain::is_valid_domain;
/// assert!(is_valid_domain("münchen.de") && is_valid_domain("xn--mnchen-3ya.de"));
/// assert!(!is_valid_domain("xn--"));
/// ```
#[cfg(feature = "idna")]
#[must_use]
pub fn is_valid_domain(host: &str) -> bool {
    to_ascii(host).is_some()
}

// ---- Public Suffix List, behind the `psl` feature --------------------------

/// Whether `domain` is itself a public suffix (e.g. `com`, `co.uk`, `github.io`) — a cookie must
/// **not** set `Domain` to a public suffix (the supercookie defense, RFC 6265 §4.1.2.3 / §5.3). An
/// optional leading dot is ignored. (`psl` feature.)
///
/// ```
/// use rfc_6265::domain::is_public_suffix;
/// assert!(is_public_suffix("co.uk") && is_public_suffix("com"));
/// assert!(!is_public_suffix("example.com"));
/// ```
#[cfg(feature = "psl")]
#[must_use]
pub fn is_public_suffix(domain: &str) -> bool {
    let d = domain.strip_prefix('.').unwrap_or(domain);
    !d.is_empty() && psl::suffix_str(d) == Some(d)
}

/// The registrable domain (eTLD+1) of `host` — e.g. `example.com` for `a.b.example.com` — or `None`
/// when `host` is itself a public suffix or otherwise not registrable. (`psl` feature.)
///
/// ```
/// use rfc_6265::domain::registrable_domain;
/// assert_eq!(registrable_domain("a.b.example.com"), Some("example.com"));
/// assert_eq!(registrable_domain("com"), None); // a public suffix isn't registrable
/// ```
#[cfg(feature = "psl")]
#[must_use]
pub fn registrable_domain(host: &str) -> Option<&str> {
    psl::domain_str(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_matches() {
        assert!(domain_matches("example.com", "example.com"));
    }

    #[test]
    fn suffix_on_a_label_boundary_matches() {
        assert!(domain_matches("foo.example.com", "example.com"));
        assert!(domain_matches("a.b.example.com", "example.com"));
    }

    #[test]
    fn suffix_without_a_label_boundary_does_not_match() {
        // A longer name that merely *ends with* the domain string must not match: the character
        // before the suffix is `d`, not the `.` label boundary. (Same class as the
        // `hostileexample.org` vs `example.org` case raised in review.)
        assert!(!domain_matches("badexample.com", "example.com"));
    }

    #[test]
    fn longer_or_empty_domain_does_not_match() {
        assert!(!domain_matches("example.com", "www.example.com"));
        assert!(!domain_matches("example.com", ""));
    }

    #[test]
    fn hosts_with_non_name_characters_never_match() {
        // Embedded userinfo / port / path / whitespace — none of these are host names, so the
        // suffix comparison is never even reached.
        for (host, domain) in [
            (
                "example.org:hack@attackercontrolled.example.com",
                "example.com",
            ),
            (
                "attackercontrolled.example.com",
                "example.org:hack@attackercontrolled.example.com",
            ),
            ("a@b.example.com", "example.com"),
            ("example.com:8080", "example.com"),
            ("example.com/.evil.com", "evil.com"),
            ("exa mple.example.com", "example.com"),
        ] {
            assert!(
                !domain_matches(host, domain),
                "{host:?} vs {domain:?} must not match"
            );
        }
    }

    #[test]
    fn empty_labels_and_dotted_edges_are_rejected() {
        // A leading-dot cookie-domain must be stripped by the caller (§5.2.3) before matching.
        assert!(!domain_matches("foo.example.com", ".example.com"));
        assert!(!domain_matches("foo..example.com", "example.com"));
        assert!(is_host_name("sub.example.com"));
        assert!(is_host_name("xn--bcher-kva.example")); // punycode is plain LDH
        assert!(is_host_name("192.168.0.1"));
        for bad in [
            "",
            ".example.com",
            "example.com.",
            "a..b",
            "a_b.com",
            "ex ample",
        ] {
            assert!(!is_host_name(bad), "{bad:?} must be rejected");
        }
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

    #[cfg(feature = "idna")]
    #[test]
    fn idna_to_ascii_and_validity() {
        assert_eq!(to_ascii("münchen.de").as_deref(), Some("xn--mnchen-3ya.de"));
        assert_eq!(to_ascii("EXAMPLE.com").as_deref(), Some("example.com")); // lower-cased
        assert_eq!(
            to_ascii("xn--mnchen-3ya.de").as_deref(),
            Some("xn--mnchen-3ya.de")
        );
        assert!(is_valid_domain("xn--mnchen-3ya.de") && is_valid_domain("example.com"));
        // Malformed punycode and the empty string are not valid domains.
        assert!(!is_valid_domain("xn--") && !is_valid_domain(""));
        // A UTF-8 host converts, then matches on the ASCII form.
        let host = to_ascii("foo.münchen.de").unwrap();
        assert!(domain_matches(&host, "xn--mnchen-3ya.de"));
    }

    #[cfg(feature = "idna")]
    #[test]
    fn idna_emoji_domain() {
        // UTS-46 encodes an emoji label to its A-label, and the encoding is *valid* IDNA
        // — even though a registry such as .eu would refuse the emoji. Registry policy and
        // IDNA validity are different concerns, and only the latter is this layer's job.
        assert_eq!(to_ascii("🍪.eu").as_deref(), Some("xn--hj8h.eu"));
        assert!(is_valid_domain("🍪.eu"));
        // Idempotent on the already-encoded A-label, which is also a valid domain.
        assert_eq!(to_ascii("xn--hj8h.eu").as_deref(), Some("xn--hj8h.eu"));
        assert!(is_valid_domain("xn--hj8h.eu"));
    }

    #[cfg(feature = "psl")]
    #[test]
    fn psl_public_suffix_and_registrable() {
        assert!(is_public_suffix("com"));
        assert!(is_public_suffix("co.uk"));
        assert!(is_public_suffix("github.io"));
        assert!(is_public_suffix(".com")); // leading dot ignored
        assert!(!is_public_suffix("example.com") && !is_public_suffix(""));
        assert_eq!(registrable_domain("a.b.example.com"), Some("example.com"));
        assert_eq!(registrable_domain("example.co.uk"), Some("example.co.uk"));
        assert_eq!(registrable_domain("com"), None);
    }
}
