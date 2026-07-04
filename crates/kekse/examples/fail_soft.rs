//! Fail-soft parsing and the never-panic guarantee — kekse's security headline.
//!
//! A malformed pair is skipped, never aborting the header, so attacker-appended
//! junk can't evict a later valid cookie. And no untrusted input — however
//! corrupted — can make kekse panic.
//!
//! Run with: `cargo run -p kekse --example fail_soft`

use kekse::CookieJar;

fn main() {
    // A header an attacker has salted with junk around the real session cookie:
    // a bare token, an empty name, a spaced pair, stray delimiters.
    let hostile = "garbage; =novalue; broken pair; SID=deadbeef; ;;; theme";
    let jar = CookieJar::parse_strict(hostile);
    let sid = jar
        .get_all("SID")
        .find(|c| !c.value().is_empty())
        .map(|c| c.value());
    println!("hostile header: {hostile:?}");
    println!(
        "  -> recovered SID = {sid:?}  ({} pair(s) kept)\n",
        jar.len()
    );
    assert_eq!(sid, Some("deadbeef"));

    // Fail-soft, observed: the reporting reader recovers the same jar AND says
    // exactly what it refused — so a skip is a log line, not a mystery. Each
    // issue renders with its control bytes escaped, safe to print.
    let reported = CookieJar::parse_strict_reported(hostile);
    println!("the report for the same header:");
    for issue in &reported.issues {
        println!("  - {issue}");
    }
    assert_eq!(reported.value.len(), jar.len());
    // A caller who would rather refuse the whole header: `into_result` is Ok
    // only when the parse was clean — fail-hard is one method away.
    assert!(reported.into_result().is_err());
    println!();

    // Never panics: throw deliberately corrupted wire at it and watch it shrug.
    // We assert only that each call *returns* — not what it parsed.
    let long = "a=b; ".repeat(10_000);
    let nasties = [
        "",                        // empty
        "=",                       // just a separator
        ";;;;;;",                  // only delimiters
        "k=\u{0}\u{1}\u{7f}",      // control bytes in the value
        "x=y\r\nInjected: header", // a CRLF header-injection attempt
        "🍪=🎃",                   // non-ASCII name and value
        long.as_str(),             // a 10k-pair giant
    ];
    println!("corrupted inputs (none panic):");
    for nasty in nasties {
        let jar = CookieJar::parse_strict(nasty);
        let preview: String = nasty.chars().take(16).collect();
        println!("  {:>2} pair(s) from {preview:?}", jar.len());
    }
    println!("\nevery input returned a (possibly empty) jar — no panics.");
}
