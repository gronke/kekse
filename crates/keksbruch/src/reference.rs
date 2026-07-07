//! The jar-probe **reference**: RFC 6265 §5.3 storage and §5.4 retrieval executed directly
//! from `rfc_6265`'s primitives (`canonicalize`, `domain_matches`, `path_matches`,
//! `default_path`), with kekse's lenient codec as the §5.2 wire layer. This is the baseline
//! column the jar probes pin in Layer A and compare real client jars against.
//!
//! Deliberately minimal: one cookie per probe, no expiry/eviction (probes carry no
//! `Expires`/`Max-Age`), no HttpOnly filtering (an API axis, not a matching axis). In the
//! default build it is the *bare* RFC algorithm — §5.3 step 5's public-suffix rejection is
//! optional in the RFC and applies only under the `hardened` feature.
//!
//! Compiled unconditionally (no `differential`-only deps — probe URLs are harness-authored,
//! so a hand-rolled splitter replaces the `url` crate), so the Layer A pins gate it on the
//! default CI legs.

use rfc_6265::domain::{canonicalize, domain_matches};
use rfc_6265::path::{default_path, path_matches};

/// A probe URL split into its parts. Probe URLs are harness-authored ASCII of the shape
/// `scheme://host/path` — no port, userinfo, fragment, or query — so a plain split is exact.
struct UrlParts<'a> {
    scheme: &'a str,
    host: &'a str,
    /// The uri-path, `/`-leading (an absent path reads as `/`).
    path: &'a str,
}

impl<'a> UrlParts<'a> {
    fn parse(url: &'a str) -> Option<Self> {
        let (scheme, rest) = url.split_once("://")?;
        let (host, path) = match rest.find('/') {
            Some(idx) => (&rest[..idx], &rest[idx..]),
            None => (rest, "/"),
        };
        (!scheme.is_empty() && !host.is_empty()).then_some(UrlParts { scheme, host, path })
    }
}

/// Store `set_cookie` as if received in a response from `origin_url` (§5.3), then return the
/// `(name, value)` pairs a request to `request_url` would carry (§5.4 step 1). An empty vec
/// means "not sent" — whether storage refused the cookie or the match failed; the probes
/// keep those one observable, like the jars they are compared against.
///
/// Panics on a malformed probe URL: the URLs are harness-authored, so a bad one is a corpus
/// bug that must fail loudly (Layer A) or surface as `☠️` (the matrix's `catch_unwind`).
#[must_use]
pub fn probe_retrieval(
    set_cookie: &str,
    origin_url: &str,
    request_url: &str,
) -> Vec<(String, String)> {
    let origin = UrlParts::parse(origin_url).expect("probe origin_url is scheme://host/path");
    let request = UrlParts::parse(request_url).expect("probe request_url is scheme://host/path");

    // §5.2: the wire layer. kekse's lenient parse is the codec under test elsewhere; here it
    // only lifts the header into (name, value, attributes) so the §5.3 algorithm can run.
    let Ok(reported) = kekse::SetCookie::parse(set_cookie) else {
        return Vec::new();
    };
    let sc = reported.into_value();
    let attrs = sc.attributes();
    let request_host = canonicalize(origin.host);

    // §5.2.3: strip one leading dot from the domain-attribute, then §5.1.2-canonicalize it.
    let domain_attr = attrs
        .domain
        .as_ref()
        .map(|d| canonicalize(d.as_str().strip_prefix('.').unwrap_or(d.as_str())));

    // §5.3 step 5 (optional, `hardened` only): a public-suffix domain-attribute is allowed
    // only when it equals the request-host itself — then the cookie degrades to host-only;
    // any other host is refused (the supercookie defense).
    #[cfg(feature = "hardened")]
    let domain_attr = match domain_attr {
        Some(d) if rfc_6265::domain::is_public_suffix(&d) => {
            if d == request_host {
                None
            } else {
                return Vec::new();
            }
        }
        other => other,
    };

    // §5.3 step 6: a present domain-attribute must domain-match the request-host; the cookie
    // then widens to that domain. Absent → a host-only cookie on the request-host itself.
    let (host_only, cookie_domain) = match domain_attr {
        Some(domain) => {
            if !domain_matches(&request_host, &domain) {
                return Vec::new();
            }
            (false, domain)
        }
        None => (true, request_host.clone()),
    };

    // §5.2.4 / §5.3 step 7: a Path that is absent or not `/`-leading is replaced by the
    // origin's default-path.
    let cookie_path = match attrs.path.as_ref().map(|p| p.as_str()) {
        Some(p) if p.starts_with('/') => p.to_string(),
        _ => default_path(origin.path).to_string(),
    };

    // §5.4 step 1: host-only cookies need the identical canonicalized host, domain cookies a
    // domain-match; the request path must path-match; Secure needs a secure channel.
    let target_host = canonicalize(request.host);
    let host_ok = if host_only {
        target_host == cookie_domain
    } else {
        domain_matches(&target_host, &cookie_domain)
    };
    let sent = host_ok
        && path_matches(request.path, &cookie_path)
        && (!attrs.secure || request.scheme == "https");
    if sent {
        vec![(sc.name().to_string(), sc.value().to_string())]
    } else {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_parts_splits_scheme_host_path() {
        let u = UrlParts::parse("https://sub.example.com/dir/page").unwrap();
        assert_eq!(
            (u.scheme, u.host, u.path),
            ("https", "sub.example.com", "/dir/page")
        );
        let bare = UrlParts::parse("http://example.com").unwrap();
        assert_eq!(bare.path, "/");
        assert!(UrlParts::parse("example.com/no-scheme").is_none());
    }

    #[test]
    fn leading_dot_is_stripped_before_domain_match() {
        let sent = probe_retrieval(
            "SID=abc; Domain=.example.com",
            "https://sub.example.com/",
            "https://example.com/",
        );
        assert_eq!(sent, vec![("SID".to_string(), "abc".to_string())]);
    }

    #[test]
    fn default_path_applies_when_path_is_missing_or_relative() {
        for wire in ["SID=abc", "SID=abc; Path=name"] {
            let origin = "https://example.com/dir/page";
            assert!(!probe_retrieval(wire, origin, "https://example.com/dir/other").is_empty());
            assert!(probe_retrieval(wire, origin, "https://example.com/elsewhere").is_empty());
        }
    }

    #[test]
    fn host_only_cookie_never_flows_to_subdomains() {
        let origin = "https://example.com/";
        assert!(!probe_retrieval("SID=abc", origin, "https://example.com/").is_empty());
        assert!(probe_retrieval("SID=abc", origin, "https://sub.example.com/").is_empty());
    }

    #[test]
    fn secure_cookie_needs_an_https_request() {
        let origin = "https://example.com/";
        assert!(!probe_retrieval("SID=abc; Secure", origin, "https://example.com/").is_empty());
        assert!(probe_retrieval("SID=abc; Secure", origin, "http://example.com/").is_empty());
    }
}
