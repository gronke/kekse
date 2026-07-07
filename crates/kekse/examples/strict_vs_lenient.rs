//! Lenient vs. strict request parsing — one interface, two gradings.
//!
//! Run with: `cargo run -p kekse --example strict_vs_lenient`

use kekse::{parse_pairs, parse_pairs_strict};

fn main() {
    // `pref` carries a quoted value with a space; `SID` is clean cookie-octets.
    let header = r#"pref="a b"; SID=deadbeef"#;
    println!("header: {header}\n");

    // Lenient grading: strips one wrapping quote pair and tolerates the inner
    // space, so every pair here parses.
    let lenient: Vec<(String, String)> = parse_pairs(header)
        .filter_map(Result::ok)
        .map(|(n, v)| (n.to_owned(), v.into_owned()))
        .collect();
    println!("lenient (parse_pairs):        {lenient:?}");

    // Strict grading: cookie-octets only. The quoted/whitespace `pref` is
    // refused — the one bad pair never aborts the parse, so `SID` survives —
    // and the refusal is yielded in place instead of vanishing.
    let strict: Vec<(String, String)> = parse_pairs_strict(header)
        .filter_map(Result::ok)
        .map(|(n, v)| (n.to_owned(), v.into_owned()))
        .collect();
    let refusals: Vec<String> = parse_pairs_strict(header)
        .filter_map(Result::err)
        .map(|issue| issue.to_string())
        .collect();
    println!("strict  (parse_pairs_strict): {strict:?}");
    println!("strict refusals:              {refusals:?}");

    assert!(lenient.iter().any(|(n, v)| n == "pref" && v == "a b"));
    assert!(!strict.iter().any(|(n, _)| n == "pref"));
    assert!(strict.iter().any(|(n, v)| n == "SID" && v == "deadbeef"));
    assert_eq!(refusals.len(), 1);

    println!(
        "\nRule of thumb:\n  parse_pairs_strict — session ids and anything you minted yourself\n  parse_pairs        — lenient, user-facing values (themes, prefs)"
    );
}
