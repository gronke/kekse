//! RFC 7230 §3.2.6 token grammar, which RFC 6265 §4.1.1 adopts for `cookie-name`.
//! <https://www.rfc-editor.org/rfc/rfc7230#section-3.2.6>
//!
//! `tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." / "^" /
//! "_" / "`" / "|" / "~" / DIGIT / ALPHA`; everything else — the delimiters, CTL,
//! SP, and non-ASCII — is rejected. These exercise the published `is_cookie_name`
//! predicate at the API boundary and confirm the parsers route names through it.

mod common;

use kekse::{SetCookie, is_cookie_name, parse_pairs};

/// The RFC 7230 `tchar` predicate, spelled out as the spec defines it.
fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

#[test]
fn every_tchar_is_a_valid_one_char_name() {
    for b in 0u8..=0x7f {
        if is_tchar(b) {
            let name = (b as char).to_string();
            assert!(is_cookie_name(&name), "tchar {name:?} must be a valid name");
        }
    }
    // The RFC's own example token (RFC 7230 §3.2.6).
    assert!(is_cookie_name("a!#$%&'*+-.^_`|~9"));
}

#[test]
fn full_ascii_boundary_matches_the_tchar_set() {
    for (b, s) in common::ascii_singletons() {
        assert_eq!(
            is_cookie_name(&s),
            is_tchar(b),
            "byte 0x{b:02x} ({s:?}) classified wrong"
        );
    }
}

#[test]
fn delimiters_and_space_are_rejected() {
    // The RFC 7230 delimiters, DQUOTE, and SP — standalone and embedded.
    for d in "\"(),/:;<=>?@[\\]{} ".chars() {
        let solo = d.to_string();
        assert!(!is_cookie_name(&solo), "{solo:?} must be rejected");
        let embedded = format!("a{d}b");
        assert!(!is_cookie_name(&embedded), "{embedded:?} must be rejected");
    }
}

#[test]
fn controls_and_non_ascii_are_rejected() {
    for b in (0u8..=0x20).chain(std::iter::once(0x7f)) {
        let s = (b as char).to_string();
        assert!(!is_cookie_name(&s), "control 0x{b:02x} must be rejected");
    }
    for name in ["naïve", "café", "Ω", "🦀", "a\u{80}"] {
        assert!(!is_cookie_name(name), "{name:?} must be rejected");
    }
    assert!(!is_cookie_name(""), "an empty name must be rejected");
}

#[test]
fn the_parsers_enforce_the_token_grammar() {
    // A space or non-tchar delimiter in the name refuses the pair — as a
    // witnessed issue, never a silent drop.
    assert!(parse_pairs("na me=v").next().unwrap().is_err());
    assert!(parse_pairs("a@b=v").next().unwrap().is_err());
    // `a;b=v` splits on `;`: `a` has no `=` and is refused, `b=v` survives.
    let surviving: Vec<_> = parse_pairs("a;b=v")
        .filter_map(Result::ok)
        .map(|(n, _)| n)
        .collect();
    assert_eq!(surviving, ["b"]);
    // `Set-Cookie` routes the name through the same gate.
    assert!(SetCookie::parse("na me=v").is_err());
    assert!(SetCookie::parse("a@b=v").is_err());
    assert!(SetCookie::parse("SID=x").is_ok());
}
