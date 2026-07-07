//! Shared inputs for the bench targets, so the timing view (`codec`) and the
//! allocation view (`allocs`) measure exactly the same scenarios.

// Each bench target compiles this module on its own and uses its own subset.
#![allow(dead_code)]

use kekse::{CookieJar, SameSite, SetCookie};
use time::OffsetDateTime;
use time::macros::datetime;

/// One session cookie — the minimal hot path (~28 B).
pub const SMALL: &str = "SID=deadbeef1234567890abcdef";

/// A typical web-app header: session, analytics, and preference pairs (5 pairs, ~130 B).
pub const MEDIUM: &str = "session=abc123def456ghi789; _ga=GA1.2.1234567890.1700000000; _gid=GA1.2.0987654321.1700000000; theme=dark; lang=en-US";

/// Percent-escaped values (the decode must allocate) next to one clean pair.
pub const ESCAPED: &str =
    "pref=caf%C3%A9%20au%20lait; name=Jos%C3%A9%20Garc%C3%ADa; q=100%25%20done; plain=untouched";

/// Quoted and whitespace-bearing values — the lenient-only shapes.
pub const QUOTED: &str = "pref=\"dark mode\"; msg=hello world; SID=deadbeef";

/// Junk segments between valid pairs — the fail-soft / reporting path.
pub const DIRTY: &str = "garbage; =nix; na me=v; SID=deadbeef; bad=a\u{1}b; theme=dark";

/// A minimal `Set-Cookie` value.
pub const SET_COOKIE_MIN: &str = "n=v";

/// A `Set-Cookie` value with every dateless attribute.
pub const SET_COOKIE_FULL: &str =
    "SID=deadbeef; HttpOnly; SameSite=Strict; Secure; Path=/; Max-Age=3600";

/// A `Set-Cookie` value with the full attribute set including `Expires`.
pub const SET_COOKIE_EXPIRES: &str = "SID=deadbeef; Path=/; Domain=example.com; Expires=Wed, 09 Jun 2021 10:18:14 GMT; Max-Age=3600; Secure; HttpOnly";

/// The canonical RFC 7231 IMF-fixdate example.
pub const IMF: &str = "Sun, 06 Nov 1994 08:49:37 GMT";

/// The same instant in the obsolete RFC 850 shape.
pub const RFC850: &str = "Sunday, 06-Nov-94 08:49:37 GMT";

/// The instant `IMF`/`RFC850` spell, for the formatting benchmarks.
pub const WHEN: OffsetDateTime = datetime!(1994-11-06 08:49:37 UTC);

/// The expiry instant `SET_COOKIE_EXPIRES` spells.
pub const EXPIRY: OffsetDateTime = datetime!(2021-06-09 10:18:14 UTC);

/// A ~1.6 KB header: a JWT-sized token plus 30 tracking-style pairs.
pub fn large_header() -> String {
    let mut header = String::from(
        "token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    );
    for i in 0..30 {
        header.push_str(&format!("; k{i}=value-{i}-0123456789abcdef"));
    }
    header
}

/// A 20-cookie header for the query benchmarks: `k0`..`k16` plus three `dup` pairs.
pub fn query_jar_header() -> String {
    let mut header = String::new();
    for i in 0..17 {
        if i > 0 {
            header.push_str("; ");
        }
        header.push_str(&format!("k{i}=value{i}"));
    }
    header.push_str("; dup=a; dup=b; dup=c");
    header
}

/// The parsed form of [`query_jar_header`]'s output.
pub fn query_jar(header: &str) -> CookieJar<'_> {
    let jar = CookieJar::parse(header);
    assert_eq!(jar.len(), 20);
    jar
}

/// The builder-made counterpart of [`SET_COOKIE_FULL`].
pub fn set_cookie_full() -> SetCookie<'static> {
    SetCookie::new("SID", "deadbeef")
        .http_only()
        .same_site(SameSite::Strict)
        .secure()
        .path("/")
        .max_age(3600)
}

/// The builder-made counterpart of [`SET_COOKIE_EXPIRES`].
pub fn set_cookie_expires() -> SetCookie<'static> {
    set_cookie_full().domain("example.com").expires(EXPIRY)
}
