//! Layer A: kekse's behaviour pinned against the `Keksbruch` corpus. Pure Rust, no
//! python/node/network — runs in CI on a bare runner as a regression oracle. If a
//! future kekse change alters fail-soft parsing, these assertions break here.

use keksbruch::{
    assert_no_injection_echo, assert_strict_subset_of_lenient, drive, payloads, scenarios,
    Direction, Expect,
};
use kekse::{parse_pairs, parse_pairs_strict, SetCookie};

fn pairs(wire: &str, strict: bool) -> Vec<(String, String)> {
    if strict {
        parse_pairs_strict(wire)
            .map(|(n, v)| (n.to_string(), v.into_owned()))
            .collect()
    } else {
        parse_pairs(wire)
            .map(|(n, v)| (n.to_string(), v.into_owned()))
            .collect()
    }
}

fn owned(want: &[(&str, &str)]) -> Vec<(String, String)> {
    want.iter()
        .map(|(n, v)| (n.to_string(), v.to_string()))
        .collect()
}

#[test]
fn every_keksbruch_survives_the_universal_invariants() {
    for recipe in payloads() {
        match recipe.render_str() {
            Some(wire) if recipe.direction == Direction::Request => {
                drive(&wire); // never panics
                assert_no_injection_echo(&wire); // no ; CR LF NUL echoed
                assert_strict_subset_of_lenient(&wire); // strict only removes
            }
            Some(wire) => {
                // Response: parsing never panics. The cookie value is decoded and
                // octet-validated, so it is always injection-free. Attribute values
                // (Path/Domain) are stored raw, so the wire boundary is the
                // HeaderValue conversion — if it succeeds the bytes carry no
                // injection; a raw byte that would inject is rejected there.
                let _ = SetCookie::parse_strict(&wire);
                if let Some(sc) = SetCookie::parse(&wire) {
                    assert!(
                        !sc.value()
                            .bytes()
                            .any(|b| matches!(b, b';' | b'\r' | b'\n' | 0)),
                        "Set-Cookie value carried an injection byte: {:?}",
                        sc.value()
                    );
                    if let Ok(header_value) = http::HeaderValue::try_from(&sc) {
                        assert!(
                            !header_value
                                .as_bytes()
                                .iter()
                                .any(|b| matches!(b, b'\r' | b'\n' | 0)),
                            "Set-Cookie HeaderValue carried an injection byte for {wire:?}"
                        );
                    }
                }
            }
            None => { /* Unrepresentable: the wire can never reach a &str parser */ }
        }
    }
}

#[test]
fn each_scenario_matches_its_pinned_expectation() {
    for scenario in scenarios() {
        let id = scenario.id;
        let wire = match (scenario.recipe.render_str(), &scenario.expect) {
            (None, Expect::Unrepresentable) => continue, // correct: not a &str
            (None, other) => panic!("{id}: wire is not UTF-8 but expected {other:?}"),
            (Some(_), Expect::Unrepresentable) => {
                panic!("{id}: expected a non-UTF-8 wire but it rendered as a &str")
            }
            (Some(wire), _) => wire,
        };
        match &scenario.expect {
            Expect::BothPairs(want) => {
                let want = owned(want);
                assert_eq!(pairs(&wire, false), want, "{id} lenient");
                assert_eq!(pairs(&wire, true), want, "{id} strict");
            }
            Expect::SplitPairs { lenient, strict } => {
                assert_eq!(pairs(&wire, false), owned(lenient), "{id} lenient");
                assert_eq!(pairs(&wire, true), owned(strict), "{id} strict");
            }
            Expect::BothPairsCount(k) => {
                assert_eq!(parse_pairs(&wire).count(), *k, "{id} lenient count");
                assert_eq!(parse_pairs_strict(&wire).count(), *k, "{id} strict count");
            }
            Expect::ResponseStrictRejectsLenientKeeps { value } => {
                assert!(
                    SetCookie::parse_strict(&wire).is_none(),
                    "{id} strict must reject"
                );
                let sc = SetCookie::parse(&wire)
                    .unwrap_or_else(|| panic!("{id} default must keep the cookie"));
                assert_eq!(sc.value(), *value, "{id} value");
            }
            Expect::ResponseValue {
                value,
                max_age,
                http_only,
                secure,
            } => {
                for (mode, parsed) in [
                    ("strict", SetCookie::parse_strict(&wire)),
                    ("default", SetCookie::parse(&wire)),
                ] {
                    let sc = parsed.unwrap_or_else(|| panic!("{id} {mode} must keep the cookie"));
                    assert_eq!(sc.value(), *value, "{id} {mode} value");
                    assert_eq!(sc.attributes().max_age, *max_age, "{id} {mode} max_age");
                    assert_eq!(
                        sc.attributes().http_only,
                        *http_only,
                        "{id} {mode} http_only"
                    );
                    assert_eq!(sc.attributes().secure, *secure, "{id} {mode} secure");
                }
            }
            Expect::ResponseDated {
                value,
                lenient_dated,
                strict_dated,
            } => {
                for (mode, parsed, want_dated) in [
                    ("strict", SetCookie::parse_strict(&wire), *strict_dated),
                    ("default", SetCookie::parse(&wire), *lenient_dated),
                ] {
                    let sc = parsed.unwrap_or_else(|| panic!("{id} {mode} must keep the cookie"));
                    assert_eq!(sc.value(), *value, "{id} {mode} value");
                    assert_eq!(
                        sc.attributes().expires.is_some(),
                        want_dated,
                        "{id} {mode} expires presence"
                    );
                }
            }
            Expect::ResponseDomain {
                value,
                default_domain,
                hardened_domain,
            } => {
                // keksbruch's `hardened` feature forwards to `kekse/hardened`, so the resolved
                // `Domain` depends on the build: the pure codec stores it, the hardened build may
                // refuse a public-suffix / malformed value. A single `Domain` is no duplicate, so
                // strict and lenient agree.
                let want_domain = if cfg!(feature = "hardened") {
                    *hardened_domain
                } else {
                    *default_domain
                };
                for (mode, parsed) in [
                    ("strict", SetCookie::parse_strict(&wire)),
                    ("default", SetCookie::parse(&wire)),
                ] {
                    let sc = parsed.unwrap_or_else(|| panic!("{id} {mode} must keep the cookie"));
                    assert_eq!(sc.value(), *value, "{id} {mode} value");
                    assert_eq!(
                        sc.attributes().domain.map(|d| d.as_str()),
                        want_domain,
                        "{id} {mode} domain"
                    );
                }
            }
            Expect::ResponsePath { value, path } => {
                // A path-av is just av-octets, so kekse stores it verbatim in both modes,
                // independent of the hardened feature (Path has no psl/idna policy).
                for (mode, parsed) in [
                    ("strict", SetCookie::parse_strict(&wire)),
                    ("default", SetCookie::parse(&wire)),
                ] {
                    let sc = parsed.unwrap_or_else(|| panic!("{id} {mode} must keep the cookie"));
                    assert_eq!(sc.value(), *value, "{id} {mode} value");
                    assert_eq!(
                        sc.attributes().path.map(|p| p.as_str()),
                        *path,
                        "{id} {mode} path"
                    );
                }
            }
            Expect::ResponseNone => {
                assert!(SetCookie::parse_strict(&wire).is_none(), "{id} strict");
                assert!(SetCookie::parse(&wire).is_none(), "{id} default");
            }
            Expect::Unrepresentable => unreachable!("handled before the value match"),
        }
    }
}
