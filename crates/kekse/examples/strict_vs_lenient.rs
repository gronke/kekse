//! Lenient vs. strict request parsing — kekse's two reader modes.
//!
//! Run with: `cargo run -p kekse --example strict_vs_lenient`

use kekse::{parse_pairs, parse_pairs_strict};

fn main() {
    // `pref` carries a quoted value with a space; `SID` is clean cookie-octets.
    let header = r#"pref="a b"; SID=deadbeef"#;
    println!("header: {header}\n");

    // Lenient: strips one wrapping quote pair and tolerates the inner space.
    let lenient: Vec<(String, String)> = parse_pairs(header)
        .map(|(n, v)| (n.to_owned(), v.into_owned()))
        .collect();
    println!("lenient (parse_pairs):        {lenient:?}");

    // Strict: cookie-octets only. The quoted/whitespace `pref` is refused — but
    // fail-soft means the one bad pair never aborts the parse, so `SID` survives.
    let strict: Vec<(String, String)> = parse_pairs_strict(header)
        .map(|(n, v)| (n.to_owned(), v.into_owned()))
        .collect();
    println!("strict  (parse_pairs_strict): {strict:?}");

    assert!(lenient.iter().any(|(n, v)| n == "pref" && v == "a b"));
    assert!(!strict.iter().any(|(n, _)| n == "pref"));
    assert!(strict.iter().any(|(n, v)| n == "SID" && v == "deadbeef"));

    println!(
        "\nRule of thumb:\n  parse_pairs_strict — session ids and anything you minted yourself\n  parse_pairs        — lenient, user-facing values (themes, prefs)"
    );
}
