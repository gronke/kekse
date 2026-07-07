//! Building a `Set-Cookie` response header — the write side of kekse.
//!
//! Run with: `cargo run -p kekse --example build_set_cookie`

use kekse::{Cookie, CookieAttributes, Path, SameSite, SetCookie, ValueEncoding};

fn main() {
    // 1. The fluent builder. The nullary flags (`http_only`, `secure`) and the
    //    valued setters (`same_site`, `path`, `max_age`) render in a fixed
    //    attribute order, each only when set.
    let header = SetCookie::new("SID", "deadbeef")
        .http_only()
        .secure()
        .same_site(SameSite::Strict)
        .path(Path::new("/").expect("`/` is av-octet-clean"))
        .max_age(3600)
        .to_set_cookie();
    println!("1. built:       {header}");
    assert_eq!(
        header,
        "SID=deadbeef; HttpOnly; SameSite=Strict; Secure; Path=/; Max-Age=3600"
    );

    // 2. Hand it straight to `http`. Every managed encoding is valid header
    //    bytes, so this only ever fails for a `Raw` value the caller built with
    //    deliberately illegal bytes.
    let cookie = SetCookie::new("SID", "deadbeef").http_only().secure();
    let header_value = http::HeaderValue::try_from(&cookie)
        .expect("a managed encoding is always a valid HeaderValue");
    println!("2. HeaderValue: {header_value:?}");

    // 3. Define a hardening policy once as a `CookieAttributes`, then reuse it
    //    across cookies — the same verbs that build a `SetCookie` build a policy.
    let hardened = CookieAttributes::default()
        .http_only()
        .secure()
        .same_site(SameSite::Lax)
        .path(Path::new("/").expect("`/` is av-octet-clean"));
    for (name, value) in [("SID", "deadbeef"), ("csrf", "tok-123")] {
        let line = Cookie::new(name, value)
            .with_attributes(hardened.clone())
            .to_set_cookie();
        println!("3. policy:      {line}");
    }

    // 4. The same attributes as a plain struct literal — `CookieAttributes` has
    //    public fields and derives `Default`, so the verbs are optional sugar.
    //    (`path`/`domain` are validated newtypes: `Path::new` refuses a value
    //    that could break the header line, naming it in the error.)
    let attrs = CookieAttributes {
        http_only: true,
        secure: true,
        same_site: Some(SameSite::Strict),
        path: Path::new("/").ok(),
        max_age: Some(3600),
        ..Default::default()
    };
    let literal = SetCookie::new("SID", "deadbeef")
        .with_attributes(attrs)
        .to_set_cookie();
    println!("4. literal:     {literal}");
    assert_eq!(
        literal,
        "SID=deadbeef; HttpOnly; SameSite=Strict; Secure; Path=/; Max-Age=3600"
    );

    // 5. Round-trip: render a cookie, parse the line back, and confirm it
    //    survives. The `Percent` value `a%20b` decodes back to `a b`.
    let wire = SetCookie::new("pref", "a b")
        .with_encoding(ValueEncoding::Percent)
        .max_age(60)
        .to_set_cookie();
    let parsed = SetCookie::parse(&wire).expect("our own output round-trips");
    println!(
        "5. round-trip:  {wire:?} -> name={:?} value={:?} max_age={:?}",
        parsed.name(),
        parsed.value(),
        parsed.attributes().max_age
    );
    assert_eq!(parsed.name(), "pref");
    assert_eq!(parsed.value(), "a b");
    assert_eq!(parsed.attributes().max_age, Some(60));
}
