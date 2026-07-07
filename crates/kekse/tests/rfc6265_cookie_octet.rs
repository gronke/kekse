//! RFC 6265 §4.1.1: `cookie-octet` (the bytes a value may carry bare) and
//! `av-octet` (the bytes a `Path`/`Domain` attribute value may carry).
//! <https://www.rfc-editor.org/rfc/rfc6265#section-4.1.1>
//!
//! Exercised through the public codec (`encode_value` / `parse_pairs`) and the
//! published `is_cookie_octet` predicate and `Path`/`Domain` newtypes.

mod common;

use kekse::{Domain, Path, ValueEncoding, encode_value, is_cookie_octet, parse_pairs};

/// RFC 6265 §4.1.1 `cookie-octet = %x21 / %x23-2B / %x2D-3A / %x3C-5B / %x5D-7E`.
fn is_rfc_cookie_octet(b: u8) -> bool {
    matches!(b, 0x21 | 0x23..=0x2b | 0x2d..=0x3a | 0x3c..=0x5b | 0x5d..=0x7e)
}

/// RFC 6265 §4.1.1 `av-octet`: visible ASCII and SP, minus `;` and DEL —
/// `%x20-3A / %x3C-7E`.
fn is_rfc_av_octet(b: u8) -> bool {
    matches!(b, 0x20..=0x3a | 0x3c..=0x7e)
}

#[test]
fn published_predicate_matches_the_rfc_over_all_256_bytes() {
    for b in 0u8..=0xff {
        assert_eq!(is_cookie_octet(b), is_rfc_cookie_octet(b), "byte 0x{b:02x}");
    }
}

#[test]
fn octet_clean_value_rides_bare_through_auto() {
    // Every cookie-octet except `%` (which Auto force-escapes) — emitted verbatim.
    let octets: String = (0u8..=0x7f)
        .filter(|&b| is_cookie_octet(b) && b != b'%')
        .map(|b| b as char)
        .collect();
    assert_eq!(encode_value(&octets, ValueEncoding::Auto), octets.as_str());
}

#[test]
fn percent_is_an_octet_but_self_escapes() {
    assert!(is_cookie_octet(b'%'));
    assert_eq!(encode_value("%", ValueEncoding::Percent), "%25");
    // `%41` is preserved literally, never decoded to `A`.
    assert_eq!(encode_value("%41", ValueEncoding::Percent), "%2541");
    let round = parse_pairs("n=%2541").next().unwrap().1.into_owned();
    assert_eq!(round, "%41");
}

#[test]
fn encode_then_parse_is_identity_across_ascii() {
    for (_, s) in common::ascii_singletons() {
        let wire = format!("n={}", encode_value(&s, ValueEncoding::Percent));
        let back = parse_pairs(&wire).next().map(|(_, v)| v.into_owned());
        assert_eq!(back.as_deref(), Some(s.as_str()), "round-trip of {s:?}");
    }
}

#[test]
fn non_octet_bytes_are_escaped_not_emitted_raw() {
    for b in [b' ', b'"', b',', b';', b'\\', 0x7f, 0x01] {
        let v = format!("x{}y", b as char);
        let enc = encode_value(&v, ValueEncoding::Percent);
        assert!(
            !enc.as_bytes().contains(&b),
            "0x{b:02x} leaked raw in {enc:?}"
        );
        let back = parse_pairs(&format!("n={enc}"))
            .next()
            .unwrap()
            .1
            .into_owned();
        assert_eq!(back, v);
    }
}

#[test]
fn managed_encodings_never_emit_injection_bytes() {
    // kekse's own injection invariant, pinned at the `encode_value` boundary:
    // Auto/Percent/Quoted never let `;`, CR, LF, or NUL onto the wire.
    for &v in common::HOSTILE {
        for enc in [
            ValueEncoding::Auto,
            ValueEncoding::Percent,
            ValueEncoding::Quoted,
        ] {
            let out = encode_value(v, enc);
            assert!(
                !out.bytes().any(|b| matches!(b, b';' | b'\r' | b'\n' | 0)),
                "{enc:?} of {v:?} leaked an injection byte: {out:?}"
            );
        }
    }
}

#[test]
fn av_octet_boundary_governs_path_and_domain() {
    for (b, s) in common::ascii_singletons() {
        assert_eq!(
            Path::new(&s).is_ok(),
            is_rfc_av_octet(b),
            "Path byte 0x{b:02x}"
        );
        // For the pure codec the av-octet rule alone governs `Domain` acceptance.
        #[cfg(not(any(feature = "psl", feature = "idna")))]
        assert_eq!(
            Domain::new(&s).is_ok(),
            is_rfc_av_octet(b),
            "Domain byte 0x{b:02x}"
        );
        // The `psl`/`idna` features only *narrow* this: the av-octet rule still gates (a non-octet
        // is always refused), but an octet-clean value may be refused too (a bare single label is a
        // public suffix, etc.). So under hardening only the rejection direction is an equivalence.
        #[cfg(any(feature = "psl", feature = "idna"))]
        if !is_rfc_av_octet(b) {
            assert!(
                Domain::new(&s).is_err(),
                "Domain byte 0x{b:02x} must be refused"
            );
        }
    }
    // SP is an av-octet (allowed) though not a cookie-octet; `;` and non-ASCII not.
    assert!(Path::new("/a b").is_ok());
    assert!(Path::new("/a;b").is_err());
    assert!(Domain::new("café.test").is_err());
}
