//! Property-based invariants for the `rfc_6265` primitives, via `proptest`.
//!
//! These complement the exhaustive byte sweeps and enumerated sub-domains in the unit tests: where
//! an input space is unbounded (arbitrary strings, the whole range of instants) a property asserts
//! a law that must hold for *every* generated input. Each module is feature-gated so the file
//! compiles under any single feature (`cargo hack --each-feature`) as well as `--all-features`.

use proptest::prelude::*;
use rfc_6265::grammar::{is_cookie_name, is_cookie_name_bytes, is_tchar};

proptest! {
    /// A cookie-name is exactly a non-empty run of RFC 7230 tchars.
    #[test]
    fn cookie_name_is_a_nonempty_tchar_run(bytes in prop::collection::vec(any::<u8>(), 0..32)) {
        let expected = !bytes.is_empty() && bytes.iter().all(|&b| is_tchar(b));
        prop_assert_eq!(is_cookie_name_bytes(&bytes), expected);
    }

    /// The `&str` form never diverges from the bytes form.
    #[test]
    fn cookie_name_str_and_bytes_agree(s in ".*") {
        prop_assert_eq!(is_cookie_name(&s), is_cookie_name_bytes(s.as_bytes()));
    }
}

#[cfg(feature = "date")]
mod date_props {
    use proptest::prelude::*;
    use rfc_6265::OffsetDateTime;
    use rfc_6265::date::{HttpDateFormat, format_http_date, parse_cookie_date, parse_imf_fixdate};

    prop_compose! {
        // Whole-second UTC instants in [1970-01-01, 2070-01-01) — the range where all three
        // HTTP-date shapes, including RFC 850's two-digit year, round-trip unambiguously.
        fn instants()(secs in 0i64..3_155_760_000) -> OffsetDateTime {
            OffsetDateTime::from_unix_timestamp(secs).unwrap()
        }
    }

    proptest! {
        /// Neither date parser panics, whatever the input — both scan untrusted `Expires` text.
        #[test]
        fn date_parsers_never_panic_on_arbitrary_input(s in ".*") {
            let _ = parse_cookie_date(&s);
            let _ = parse_imf_fixdate(&s);
        }

        /// Every HTTP-date shape round-trips through the tolerant §5.1.1 parser.
        #[test]
        fn all_three_formats_round_trip(t in instants()) {
            for f in [HttpDateFormat::ImfFixdate, HttpDateFormat::Rfc850, HttpDateFormat::Asctime] {
                prop_assert_eq!(parse_cookie_date(&format_http_date(t, f)), Some(t));
            }
        }

        /// The canonical IMF-fixdate parses identically strict and lenient (strict ⊆ lenient).
        #[test]
        fn canonical_imf_is_a_strict_subset_of_lenient(t in instants()) {
            let s = format_http_date(t, HttpDateFormat::ImfFixdate);
            prop_assert_eq!(parse_imf_fixdate(&s), Some(t));
            prop_assert_eq!(parse_cookie_date(&s), Some(t));
        }
    }
}

#[cfg(feature = "domain")]
mod domain_props {
    use proptest::prelude::*;
    use rfc_6265::domain::{canonicalize, domain_matches, is_host_name};

    prop_compose! {
        // Valid LDH host names, each label starting with a letter so the host is never an IP literal.
        fn host_names()(labels in prop::collection::vec("[a-z][a-z0-9]{0,11}", 1..4)) -> String {
            labels.join(".")
        }
    }

    proptest! {
        /// domain-match is reflexive on valid host names.
        #[test]
        fn reflexive_on_valid_hosts(h in host_names()) {
            prop_assert!(is_host_name(&h));
            prop_assert!(domain_matches(&h, &h));
        }

        /// A suffix on a label boundary matches; the same suffix glued on without a `.` does not.
        #[test]
        fn dotted_suffix_matches_but_glued_prefix_does_not(
            sub in "[a-z][a-z0-9]{0,11}",
            h in host_names(),
        ) {
            let dotted = format!("{}.{}", sub, h);
            let glued = format!("{}{}", sub, h);
            prop_assert!(domain_matches(&dotted, &h));
            prop_assert!(!domain_matches(&glued, &h));
        }

        /// canonicalize is idempotent and leaves no ASCII upper-case behind.
        #[test]
        fn canonicalize_is_idempotent_and_lowercase(s in ".*") {
            let once = canonicalize(&s);
            prop_assert!(!once.bytes().any(|b| b.is_ascii_uppercase()));
            prop_assert_eq!(canonicalize(&once), once.clone());
        }
    }
}

#[cfg(feature = "path")]
mod path_props {
    use proptest::prelude::*;
    use rfc_6265::path::{default_path, path_matches};

    proptest! {
        /// default-path is always a non-empty, `/`-rooted string.
        #[test]
        fn default_path_is_rooted_and_nonempty(p in ".*") {
            let d = default_path(&p);
            prop_assert!(!d.is_empty() && d.starts_with('/'));
        }

        /// path-match is reflexive, and any match implies a string prefix.
        #[test]
        fn reflexive_and_a_match_implies_a_prefix(r in ".*", c in ".*") {
            prop_assert!(path_matches(&r, &r));
            if path_matches(&r, &c) {
                prop_assert!(r.starts_with(c.as_str()));
            }
        }

        /// Any `/`-rooted path matches its own default-path.
        #[test]
        fn a_path_matches_its_own_default_path(body in ".*") {
            let p = format!("/{body}");
            prop_assert!(path_matches(&p, default_path(&p)));
        }
    }
}
