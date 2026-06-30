//! Reading — and rewriting — a `Cookie:` request header through a `CookieJar`.
//!
//! Run with: `cargo run -p kekse --example parse_request`

use kekse::{Cookie, CookieJar, ValueEncoding};

fn main() {
    // A header carrying a stale empty `SID=` before the real one, plus a
    // duplicate `theme`. The wire allows duplicates, so the jar keeps them in
    // order rather than collapsing them.
    let jar = CookieJar::parse_strict("SID=; SID=deadbeef; theme=dark; theme=light");

    println!("all pairs, in wire order:");
    for c in jar.iter() {
        println!("  {} = {:?}", c.name(), c.value());
    }

    // Stale-shadow defense: take the first NON-EMPTY `SID`, so an attacker who
    // plants an empty `SID=` cannot shadow the real session id that follows it.
    let sid = jar
        .get_all("SID")
        .find(|c| !c.value().is_empty())
        .map(|c| c.value());
    println!("session id (first non-empty): {sid:?}");
    assert_eq!(sid, Some("deadbeef"));

    // `get` returns the first match unconditionally — here the stale empty one.
    println!(
        "first SID (raw `get`):        {:?}",
        jar.get("SID").map(|c| c.value())
    );

    // The jar is writable, too: parse, edit, and re-render canonically.
    let mut jar = CookieJar::parse_strict("a=1; b=2; c=3");
    jar.remove("b"); // drop every `b`
    jar.replace(Cookie::new("c", "30")); // drop every `c`, append the new one
    jar.add(Cookie::new("d", "4")); // append (duplicates are legal)
    let rebuilt = jar.to_header_string(ValueEncoding::Percent);
    println!("rebuilt header:               {rebuilt}");
    assert_eq!(rebuilt, "a=1; c=30; d=4");
}
