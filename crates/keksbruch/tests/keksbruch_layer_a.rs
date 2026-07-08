//! Layer A: kekse's behaviour pinned against the `Keksbruch` corpus. Pure Rust, no
//! python/node/network — runs in CI on a bare runner as a regression oracle. If a
//! future kekse change alters fail-soft parsing, these assertions break here.

use keksbruch::IssueKind;
use keksbruch::{
    Direction, Expect, assert_baseline_parses_clean, assert_no_injection_echo,
    assert_no_injection_echo_bytes, assert_pair_conservation, assert_pair_conservation_bytes,
    assert_report_consistency, assert_report_consistency_bytes,
    assert_response_divergence_witnessed, assert_set_cookie_report_consistency,
    assert_strict_subset_of_lenient, assert_strict_subset_of_lenient_bytes, drive, drive_bytes,
    jar_probes, payloads, probe_retrieval, scenarios,
};
use kekse::{
    CookieConstraint, SetCookie, SetCookieIssue, is_cookie_name, parse_pairs, parse_pairs_strict,
};

fn pairs(wire: &str, strict: bool) -> Vec<(String, String)> {
    if strict {
        parse_pairs_strict(wire)
            .filter_map(Result::ok)
            .map(|(n, v)| (n.to_string(), v.into_owned()))
            .collect()
    } else {
        parse_pairs(wire)
            .filter_map(Result::ok)
            .map(|(n, v)| (n.to_string(), v.into_owned()))
            .collect()
    }
}

/// The build-independent kinds of a report, for comparison against a row's
/// pinned `IssueKind` list.
fn issue_kinds(issues: &[SetCookieIssue<'_>]) -> Vec<IssueKind> {
    issues
        .iter()
        .map(|issue| match issue {
            SetCookieIssue::UnknownAttribute { .. } => IssueKind::Unknown,
            SetCookieIssue::DuplicateAttribute { attribute, .. } => {
                IssueKind::Duplicate(attribute.name())
            }
            SetCookieIssue::InvalidAttributeValue { attribute, .. } => {
                IssueKind::InvalidValue(attribute.name())
            }
            SetCookieIssue::FlagWithValue { attribute, .. } => {
                IssueKind::FlagWithValue(attribute.name())
            }
            SetCookieIssue::ConstraintViolation { constraint, .. } => {
                IssueKind::Constraint(match constraint {
                    CookieConstraint::SecurePrefixWithoutSecure => "SecurePrefixWithoutSecure",
                    CookieConstraint::HostPrefixWithoutSecure => "HostPrefixWithoutSecure",
                    CookieConstraint::HostPrefixWithDomain => "HostPrefixWithDomain",
                    CookieConstraint::HostPrefixWithoutRootPath => "HostPrefixWithoutRootPath",
                    CookieConstraint::PartitionedWithoutSecure => "PartitionedWithoutSecure",
                    other => panic!("unmodeled constraint: {other:?}"),
                })
            }
            other => panic!("unmodeled issue variant: {other:?}"),
        })
        .collect()
}

fn owned(want: &[(&str, &str)]) -> Vec<(String, String)> {
    want.iter()
        .map(|(n, v)| (n.to_string(), v.to_string()))
        .collect()
}

#[test]
fn every_keksbruch_survives_the_universal_invariants() {
    for recipe in payloads() {
        // kekse's own clean rendering of the base cookie must read back with an
        // empty report — writer and reporting reader may never drift. Gated on a
        // token name: the corpus deliberately carries hostile bases (`<script>`,
        // non-ASCII names), and the writer documentedly does not validate names.
        if is_cookie_name(recipe.base.name) {
            assert_baseline_parses_clean(&recipe.base.baseline(recipe.direction), recipe.direction);
        }
        // The raw wire reaches the byte-level readers for EVERY request recipe —
        // including the Unrepresentable (non-UTF-8) ones a &str parser can never
        // see. The same promises must hold below the UTF-8 boundary.
        if recipe.direction == Direction::Request {
            let wire = recipe.render();
            drive_bytes(&wire);
            assert_no_injection_echo_bytes(&wire);
            assert_strict_subset_of_lenient_bytes(&wire);
            assert_report_consistency_bytes(&wire);
            assert_pair_conservation_bytes(&wire);
        }
        match recipe.render_str() {
            Some(wire) if recipe.direction == Direction::Request => {
                drive(&wire); // never panics
                assert_no_injection_echo(&wire); // no ; CR LF NUL echoed
                assert_strict_subset_of_lenient(&wire); // strict only removes
                assert_report_consistency(&wire); // jar = stream, graded consistently
                assert_pair_conservation(&wire); // every segment lands somewhere
            }
            Some(wire) => {
                // The gradings agree on every corrupted response wire, their
                // issues render safely, and no drop or mutation goes
                // unwitnessed.
                assert_set_cookie_report_consistency(&wire);
                assert_response_divergence_witnessed(&wire);
                // Response: parsing never panics. The cookie value is decoded and
                // octet-validated, so it is always injection-free. Attribute values
                // (Path/Domain) are stored raw, so the wire boundary is the
                // HeaderValue conversion — if it succeeds the bytes carry no
                // injection; a raw byte that would inject is rejected there.
                let _ = SetCookie::parse_strict(&wire);
                if let Ok(reported) = SetCookie::parse(&wire) {
                    let sc = reported.into_value();
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
                assert_eq!(
                    parse_pairs(&wire).filter_map(Result::ok).count(),
                    *k,
                    "{id} lenient count"
                );
                assert_eq!(
                    parse_pairs_strict(&wire).filter_map(Result::ok).count(),
                    *k,
                    "{id} strict count"
                );
            }
            Expect::ResponseKeptWithIssues { value, issues } => {
                for (mode, parsed) in [
                    ("strict", SetCookie::parse_strict(&wire)),
                    ("default", SetCookie::parse(&wire)),
                ] {
                    let reported =
                        parsed.unwrap_or_else(|_| panic!("{id} {mode} must keep the cookie"));
                    assert_eq!(reported.value.value(), *value, "{id} {mode} value");
                    assert_eq!(
                        issue_kinds(&reported.issues).as_slice(),
                        *issues,
                        "{id} {mode} witnessed deviations"
                    );
                }
            }
            Expect::ResponseKeptWithIssuesDomain {
                value,
                domain,
                issues,
            } => {
                for (mode, parsed) in [
                    ("strict", SetCookie::parse_strict(&wire)),
                    ("default", SetCookie::parse(&wire)),
                ] {
                    let reported =
                        parsed.unwrap_or_else(|_| panic!("{id} {mode} must keep the cookie"));
                    assert_eq!(reported.value.value(), *value, "{id} {mode} value");
                    assert_eq!(
                        reported.value.attributes().domain.map(|d| d.as_str()),
                        *domain,
                        "{id} {mode} Domain — §5.2.2 keeps the earlier valid occurrence"
                    );
                    assert_eq!(
                        issue_kinds(&reported.issues).as_slice(),
                        *issues,
                        "{id} {mode} witnessed deviations"
                    );
                }
            }
            Expect::ResponseValue {
                value,
                max_age,
                http_only,
                secure,
                partitioned,
                issues,
            } => {
                for (mode, parsed) in [
                    ("strict", SetCookie::parse_strict(&wire)),
                    ("default", SetCookie::parse(&wire)),
                ] {
                    let reported =
                        parsed.unwrap_or_else(|_| panic!("{id} {mode} must keep the cookie"));
                    let sc = &reported.value;
                    assert_eq!(sc.value(), *value, "{id} {mode} value");
                    assert_eq!(sc.attributes().max_age, *max_age, "{id} {mode} max_age");
                    assert_eq!(
                        sc.attributes().http_only,
                        *http_only,
                        "{id} {mode} http_only"
                    );
                    assert_eq!(sc.attributes().secure, *secure, "{id} {mode} secure");
                    assert_eq!(
                        sc.attributes().partitioned,
                        *partitioned,
                        "{id} {mode} partitioned"
                    );
                    assert_eq!(
                        issue_kinds(&reported.issues).as_slice(),
                        *issues,
                        "{id} {mode} witnessed deviations"
                    );
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
                    let reported =
                        parsed.unwrap_or_else(|_| panic!("{id} {mode} must keep the cookie"));
                    assert_eq!(reported.value.value(), *value, "{id} {mode} value");
                    assert_eq!(
                        reported.value.attributes().expires.is_some(),
                        want_dated,
                        "{id} {mode} expires presence"
                    );
                    // Every dated row's wire is `pair; Expires=…`, so an undated
                    // outcome must be witnessed by exactly the Expires drop.
                    let want_issues: &[IssueKind] = if want_dated {
                        &[]
                    } else {
                        &[IssueKind::InvalidValue("Expires")]
                    };
                    assert_eq!(
                        issue_kinds(&reported.issues).as_slice(),
                        want_issues,
                        "{id} {mode} witnessed deviations"
                    );
                }
            }
            Expect::ResponseDatedAt {
                value,
                lenient,
                strict,
            } => {
                // Each pin is decoded through the strict IMF-fixdate parser, so a mistyped
                // pin (wrong pivot year, wrong weekday, non-canonical form) panics here
                // instead of silently pinning nothing.
                let decode = |pin: Option<&str>, mode: &str| {
                    pin.map(|p| {
                        rfc_6265::date::parse_imf_fixdate(p).unwrap_or_else(|| {
                            panic!("{id} {mode}: pin {p:?} is not a canonical IMF-fixdate")
                        })
                    })
                };
                for (mode, parsed, want) in [
                    ("strict", SetCookie::parse_strict(&wire), *strict),
                    ("default", SetCookie::parse(&wire), *lenient),
                ] {
                    let reported =
                        parsed.unwrap_or_else(|_| panic!("{id} {mode} must keep the cookie"));
                    assert_eq!(reported.value.value(), *value, "{id} {mode} value");
                    assert_eq!(
                        reported.value.attributes().expires,
                        decode(want, mode),
                        "{id} {mode} expires instant"
                    );
                    let want_issues: &[IssueKind] = if want.is_some() {
                        &[]
                    } else {
                        &[IssueKind::InvalidValue("Expires")]
                    };
                    assert_eq!(
                        issue_kinds(&reported.issues).as_slice(),
                        want_issues,
                        "{id} {mode} witnessed deviations"
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
                    let reported =
                        parsed.unwrap_or_else(|_| panic!("{id} {mode} must keep the cookie"));
                    assert_eq!(reported.value.value(), *value, "{id} {mode} value");
                    assert_eq!(
                        reported.value.attributes().domain.map(|d| d.as_str()),
                        want_domain,
                        "{id} {mode} domain"
                    );
                    // Every domain row's wire is `pair; Domain=…`, so a refused
                    // Domain must be witnessed by exactly that drop.
                    let want_issues: &[IssueKind] = if want_domain.is_some() {
                        &[]
                    } else {
                        &[IssueKind::InvalidValue("Domain")]
                    };
                    assert_eq!(
                        issue_kinds(&reported.issues).as_slice(),
                        want_issues,
                        "{id} {mode} witnessed deviations"
                    );
                }
            }
            Expect::ResponsePath {
                value,
                path,
                issues,
            } => {
                // A path-av is just av-octets, so kekse stores it verbatim in both modes,
                // independent of the hardened feature (Path has no psl/idna policy).
                for (mode, parsed) in [
                    ("strict", SetCookie::parse_strict(&wire)),
                    ("default", SetCookie::parse(&wire)),
                ] {
                    let reported =
                        parsed.unwrap_or_else(|_| panic!("{id} {mode} must keep the cookie"));
                    assert_eq!(reported.value.value(), *value, "{id} {mode} value");
                    assert_eq!(
                        reported.value.attributes().path.map(|p| p.as_str()),
                        *path,
                        "{id} {mode} path"
                    );
                    assert_eq!(
                        issue_kinds(&reported.issues).as_slice(),
                        *issues,
                        "{id} {mode} witnessed deviations"
                    );
                }
            }
            Expect::ResponseSameSite {
                value,
                same_site,
                issues,
            } => {
                // kekse's SameSite is a closed typed enum; a malformed value is
                // dropped — witnessed, never fatal — in BOTH gradings, so strict
                // and lenient agree. The pin compares canonical `as_str()` forms.
                for (mode, parsed) in [
                    ("strict", SetCookie::parse_strict(&wire)),
                    ("default", SetCookie::parse(&wire)),
                ] {
                    let reported =
                        parsed.unwrap_or_else(|_| panic!("{id} {mode} must keep the cookie"));
                    assert_eq!(reported.value.value(), *value, "{id} {mode} value");
                    assert_eq!(
                        reported.value.attributes().same_site.map(|s| s.as_str()),
                        *same_site,
                        "{id} {mode} same_site"
                    );
                    assert_eq!(
                        issue_kinds(&reported.issues).as_slice(),
                        *issues,
                        "{id} {mode} witnessed deviations"
                    );
                }
            }
            Expect::ResponseNone => {
                assert!(SetCookie::parse_strict(&wire).is_err(), "{id} strict");
                assert!(SetCookie::parse(&wire).is_err(), "{id} default");
            }
            Expect::Unrepresentable => unreachable!("handled before the value match"),
        }
    }
}

#[test]
fn each_jar_probe_matches_its_pinned_expectation() {
    // The §5.3/§5.4 reference retrieval, pinned per probe. The default build pins the bare
    // RFC algorithm; the `hardened` build pins it with §5.3 step 5's public-suffix rejection
    // — the only probe where the two differ is the deliberate supercookie row.
    for probe in jar_probes() {
        let want: Vec<(String, String)> = if cfg!(feature = "hardened") {
            probe.expect_attached_hardened
        } else {
            probe.expect_attached
        }
        .iter()
        .map(|(n, v)| (n.to_string(), v.to_string()))
        .collect();
        let got = probe_retrieval(probe.set_cookie, probe.origin_url, probe.request_url);
        assert_eq!(got, want, "{} attached pairs", probe.id);
    }
}
