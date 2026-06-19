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
                // Response: parsing must not panic, and a re-render must carry no
                // header-injection byte (CR/LF/NUL — `;` is the legal separator).
                let _ = SetCookie::parse(&wire);
                if let Some(sc) = SetCookie::parse_lenient(&wire) {
                    let rendered = sc.to_set_cookie();
                    assert!(
                        !rendered.bytes().any(|b| matches!(b, b'\r' | b'\n' | 0)),
                        "Set-Cookie re-render carried an injection byte: {rendered:?}"
                    );
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
                assert!(SetCookie::parse(&wire).is_none(), "{id} strict must reject");
                let sc = SetCookie::parse_lenient(&wire)
                    .unwrap_or_else(|| panic!("{id} lenient must keep the cookie"));
                assert_eq!(sc.value(), *value, "{id} value");
            }
            Expect::ResponseValue {
                value,
                max_age,
                http_only,
                secure,
            } => {
                for (mode, parsed) in [
                    ("strict", SetCookie::parse(&wire)),
                    ("lenient", SetCookie::parse_lenient(&wire)),
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
            Expect::ResponseNone => {
                assert!(SetCookie::parse(&wire).is_none(), "{id} strict");
                assert!(SetCookie::parse_lenient(&wire).is_none(), "{id} lenient");
            }
            Expect::Unrepresentable => unreachable!("handled before the value match"),
        }
    }
}
