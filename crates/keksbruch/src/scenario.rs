//! The curated corpus: a [`Scenario`] is one `Keksbruch` plus the [`Expect`]ation of
//! what kekse does with it — the regression oracle Layer A asserts. Every value
//! here is pinned to kekse's *actual* behaviour (fail-soft, strict-octet,
//! case-sensitive), so a future change that alters it breaks the suite on purpose.

use crate::recipe::{KeksbruchRecipe, LogicalCookie};
use crate::taxonomy::{Direction, Keksbruch};

/// What kekse is expected to do with one `Keksbruch`. Coarse on purpose — it pins
/// the *survival shape* (which pairs come out, whether a Set-Cookie is rejected),
/// not internal bytes, so the corpus is robust to kekse's evolution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Expect {
    /// Lenient and strict both yield exactly these `(name, value)` pairs, in order.
    BothPairs(Vec<(&'static str, &'static str)>),
    /// Lenient yields `lenient`; strict yields `strict` (necessarily a subset).
    SplitPairs {
        lenient: Vec<(&'static str, &'static str)>,
        strict: Vec<(&'static str, &'static str)>,
    },
    /// Both modes yield exactly this many pairs (for values too large to spell out).
    BothPairsCount(usize),
    /// Response: strict `parse` rejects (`None`); lenient keeps a cookie with `value`.
    ResponseStrictRejectsLenientKeeps { value: &'static str },
    /// Response: both modes parse to a cookie with this value and these known attrs.
    ResponseValue {
        value: &'static str,
        max_age: Option<u64>,
        http_only: bool,
        secure: bool,
    },
    /// Response: both modes keep a cookie with `value`; the `Expires` date parses
    /// (`expires.is_some()`) in lenient mode iff `lenient_dated` and in strict mode
    /// iff `strict_dated` (strict ⊆ lenient — obsolete forms parse only leniently).
    ResponseDated {
        value: &'static str,
        lenient_dated: bool,
        strict_dated: bool,
    },
    /// Response: both modes keep a cookie with `value`; its resolved `Domain` is `default_domain`
    /// in the pure-codec build and `hardened_domain` under the `hardened` feature (where `psl` /
    /// `idna` may refuse a public-suffix or malformed value, leaving it `None`). For a single
    /// `Domain` (no duplicate) strict and lenient agree, so both are asserted.
    ResponseDomain {
        value: &'static str,
        default_domain: Option<&'static str>,
        hardened_domain: Option<&'static str>,
    },
    /// Response: both modes reject (`None`).
    ResponseNone,
    /// The wire is not valid UTF-8, so it can never reach a `&str` parser.
    Unrepresentable,
}

/// One named test case: a stable `id` (the matrix row key), a human description,
/// the direction, the `recipe` that renders the wire, and the `expect`ation.
#[derive(Clone, Debug)]
pub struct Scenario {
    pub id: &'static str,
    pub description: &'static str,
    pub direction: Direction,
    pub recipe: KeksbruchRecipe<'static>,
    pub expect: Expect,
}

/// Assemble one scenario. The base value is fixed per direction (the request
/// `Keksbruch` variants render their own value bytes; the response baseline needs `abc`).
fn s(
    id: &'static str,
    description: &'static str,
    direction: Direction,
    name: &'static str,
    keksbruch: Keksbruch,
    expect: Expect,
) -> Scenario {
    let value = match direction {
        Direction::Request => "v",
        Direction::Response => "abc",
    };
    Scenario {
        id,
        description,
        direction,
        recipe: KeksbruchRecipe::new(LogicalCookie::new(name, value), keksbruch, direction),
        expect,
    }
}

/// The curated corpus, covering every category in the taxonomy. Static and
/// deterministic — no I/O, time, or randomness — so it is safe to run in CI.
pub fn scenarios() -> Vec<Scenario> {
    use Direction::{Request, Response};
    vec![
        // ── whitespace ──────────────────────────────────────────────────────
        s(
            "ws-surrounding",
            "SP/HTAB around name and value are trimmed away",
            Request,
            "n",
            Keksbruch::SurroundingWhitespace,
            Expect::BothPairs(vec![("n", "v")]),
        ),
        s(
            "ws-internal",
            "an internal space: lenient keeps it, strict refuses the non-octet",
            Request,
            "n",
            Keksbruch::InternalWhitespace,
            Expect::SplitPairs {
                lenient: vec![("n", "a b")],
                strict: vec![],
            },
        ),
        // ── control-char injection ──────────────────────────────────────────
        s(
            "ctl-nul",
            "a NUL in the value drops that pair, never the later one",
            Request,
            "n",
            Keksbruch::NulInValue,
            Expect::BothPairs(vec![("m", "ok")]),
        ),
        s(
            "ctl-crlf",
            "a CR/LF in the value is refused (the header-injection probe)",
            Request,
            "n",
            Keksbruch::CrlfInValue,
            Expect::BothPairs(vec![("m", "ok")]),
        ),
        s(
            "ctl-other",
            "a C0 control byte in the value drops that pair",
            Request,
            "n",
            Keksbruch::ControlInValue(0x01),
            Expect::BothPairs(vec![("m", "ok")]),
        ),
        // ── quoting ─────────────────────────────────────────────────────────
        s(
            "quote-unbalanced",
            "a dangling quote is a non-octet, so the pair is dropped",
            Request,
            "n",
            Keksbruch::UnbalancedQuote,
            Expect::BothPairs(vec![("m", "ok")]),
        ),
        s(
            "quote-interior",
            "an interior quote is a non-octet, so the pair is dropped",
            Request,
            "n",
            Keksbruch::InteriorQuote,
            Expect::BothPairs(vec![("m", "ok")]),
        ),
        // ── percent-encoding ────────────────────────────────────────────────
        s(
            "pct-truncated",
            "a stray % passes through verbatim",
            Request,
            "n",
            Keksbruch::TruncatedPercent,
            Expect::BothPairs(vec![("n", "%4"), ("m", "ok")]),
        ),
        s(
            "pct-bad-utf8",
            "an escape that decodes to invalid UTF-8 drops the pair",
            Request,
            "n",
            Keksbruch::InvalidUtf8Percent,
            Expect::BothPairs(vec![("m", "ok")]),
        ),
        s(
            "raw-non-utf8",
            "a raw non-UTF-8 byte cannot be a &str at all",
            Request,
            "n",
            Keksbruch::RawInvalidUtf8Byte,
            Expect::Unrepresentable,
        ),
        // ── delimiter abuse ─────────────────────────────────────────────────
        s(
            "delim-semicolon",
            "a raw ; splits the header — it cannot be smuggled into a value",
            Request,
            "n",
            Keksbruch::SemicolonInValue,
            Expect::BothPairs(vec![("n", "a"), ("evil", "1")]),
        ),
        s(
            "delim-empty-segments",
            "empty ;-segments are skipped",
            Request,
            "n",
            Keksbruch::EmptySegments,
            Expect::BothPairs(vec![("n", "v"), ("m", "w")]),
        ),
        s(
            "no-equals",
            "a segment with no = is skipped",
            Request,
            "n",
            Keksbruch::NoEquals,
            Expect::BothPairs(vec![("n", "v")]),
        ),
        s(
            "extra-equals",
            "split is on the first = only; the rest is the value",
            Request,
            "n",
            Keksbruch::ExtraEquals,
            Expect::BothPairs(vec![("n", "a=b")]),
        ),
        // ── duplicates ──────────────────────────────────────────────────────
        s(
            "dup-name",
            "duplicate names are all kept, in order",
            Request,
            "k",
            Keksbruch::DuplicateName,
            Expect::BothPairs(vec![("k", "1"), ("k", "2"), ("k", "3")]),
        ),
        s(
            "dup-case",
            "names are case-sensitive: sid and SID are distinct cookies",
            Request,
            "sid",
            Keksbruch::CaseVariantDuplicate,
            Expect::BothPairs(vec![("sid", "lo"), ("SID", "hi")]),
        ),
        // ── empties ─────────────────────────────────────────────────────────
        s(
            "empty-name",
            "an empty name drops that pair",
            Request,
            "n",
            Keksbruch::EmptyName,
            Expect::BothPairs(vec![("m", "ok")]),
        ),
        s(
            "empty-value",
            "an empty value is a valid, empty cookie",
            Request,
            "n",
            Keksbruch::EmptyValue,
            Expect::BothPairs(vec![("n", ""), ("m", "ok")]),
        ),
        // ── non-ASCII ───────────────────────────────────────────────────────
        s(
            "raw-non-ascii",
            "a raw non-ASCII value is refused (not a cookie-octet)",
            Request,
            "n",
            Keksbruch::RawNonAsciiValue,
            Expect::BothPairs(vec![("m", "ok")]),
        ),
        s(
            "non-ascii-name",
            "a non-token name is refused",
            Request,
            "n",
            Keksbruch::NonAsciiName,
            Expect::BothPairs(vec![("m", "ok")]),
        ),
        // ── scale ───────────────────────────────────────────────────────────
        s(
            "scale-huge-value",
            "a 4 KiB value survives as one pair",
            Request,
            "n",
            Keksbruch::HugeValue(4096),
            Expect::BothPairsCount(1),
        ),
        s(
            "scale-many-pairs",
            "20 pairs plus a sentinel all parse",
            Request,
            "n",
            Keksbruch::ManyPairs(20),
            Expect::BothPairsCount(21),
        ),
        s(
            "scale-control-junk",
            "a long control-junk segment is dropped, its neighbours kept",
            Request,
            "n",
            Keksbruch::ControlJunkRun(4096),
            Expect::BothPairs(vec![("a", "1"), ("b", "2")]),
        ),
        // ── attribute abuse (Response) ──────────────────────────────────────
        s(
            "attr-unknown",
            "strict rejects an unknown attribute; lenient keeps the cookie",
            Response,
            "SID",
            Keksbruch::UnknownAttribute("Priority"),
            Expect::ResponseStrictRejectsLenientKeeps { value: "abc" },
        ),
        s(
            "attr-bad-maxage",
            "a non-numeric Max-Age is dropped; the cookie is kept",
            Response,
            "SID",
            Keksbruch::BadMaxAge("banana"),
            Expect::ResponseValue {
                value: "abc",
                max_age: None,
                http_only: false,
                secure: false,
            },
        ),
        s(
            "attr-garbage-samesite",
            "a garbage SameSite token is dropped; the cookie is kept",
            Response,
            "SID",
            Keksbruch::GarbageSameSite("Bogus"),
            Expect::ResponseValue {
                value: "abc",
                max_age: None,
                http_only: false,
                secure: false,
            },
        ),
        s(
            "attr-valued-flag",
            "Secure=1 sets the flag; the bogus value is ignored",
            Response,
            "SID",
            Keksbruch::ValuedFlag("Secure"),
            Expect::ResponseValue {
                value: "abc",
                max_age: None,
                http_only: false,
                secure: true,
            },
        ),
        s(
            "attr-duplicate",
            "a duplicated known attribute: lenient keeps it (last wins), strict rejects the cookie",
            Response,
            "SID",
            Keksbruch::DuplicateAttribute("Path"),
            Expect::ResponseStrictRejectsLenientKeeps { value: "abc" },
        ),
        // ── Expires dates (Response) ────────────────────────────────────────
        // Lenient parse = RFC 6265 §5.1.1 cookie-date (accepts the IMF-fixdate, the
        // obsolete RFC 850 / asctime() forms, and real-world slop); strict parse =
        // RFC 7231 IMF-fixdate only. A bad date is dropped, never fatal, so the
        // cookie always survives. These also feed the differential matrix, where
        // other parsers' date handling is compared.
        s(
            "date-imf-fixdate",
            "the canonical RFC 7231 IMF-fixdate parses in both modes",
            Response,
            "SID",
            Keksbruch::ExpiresDate("Sun, 06 Nov 1994 08:49:37 GMT"),
            Expect::ResponseDated {
                value: "abc",
                lenient_dated: true,
                strict_dated: true,
            },
        ),
        s(
            "date-rfc850",
            "the obsolete RFC 850 form parses leniently; strict refuses it",
            Response,
            "SID",
            Keksbruch::ExpiresDate("Sunday, 06-Nov-94 08:49:37 GMT"),
            Expect::ResponseDated {
                value: "abc",
                lenient_dated: true,
                strict_dated: false,
            },
        ),
        s(
            "date-asctime",
            "the asctime() form parses leniently; strict refuses it",
            Response,
            "SID",
            Keksbruch::ExpiresDate("Sun Nov  6 08:49:37 1994"),
            Expect::ResponseDated {
                value: "abc",
                lenient_dated: true,
                strict_dated: false,
            },
        ),
        s(
            "date-garbage",
            "an unparseable date is dropped in both modes; the cookie survives",
            Response,
            "SID",
            Keksbruch::ExpiresDate("not-a-date"),
            Expect::ResponseDated {
                value: "abc",
                lenient_dated: false,
                strict_dated: false,
            },
        ),
        s(
            "date-impossible-day",
            "a well-formed but impossible day (31 Feb) is rejected by both modes",
            Response,
            "SID",
            Keksbruch::ExpiresDate("Sun, 31 Feb 1994 00:00:00 GMT"),
            Expect::ResponseDated {
                value: "abc",
                lenient_dated: false,
                strict_dated: false,
            },
        ),
        // Non-RFC date formats keksbruch probes to characterise the matrix: kekse is RFC-bounded
        // and rejects them all in both modes; other parsers may accept some.
        s(
            "date-iso8601",
            "an ISO 8601 timestamp is not an RFC 6265 cookie-date",
            Response,
            "SID",
            Keksbruch::ExpiresDate("1994-11-06T08:49:37Z"),
            Expect::ResponseDated {
                value: "abc",
                lenient_dated: false,
                strict_dated: false,
            },
        ),
        s(
            "date-unix",
            "the Unix `date` form (zone before the year) is not a cookie-date",
            Response,
            "SID",
            Keksbruch::ExpiresDate("Sun Nov  6 08:49:37 UTC 1994"),
            Expect::ResponseDated {
                value: "abc",
                lenient_dated: false,
                strict_dated: false,
            },
        ),
        s(
            "date-us-slash",
            "a US M/D/Y numeric date is not a cookie-date",
            Response,
            "SID",
            Keksbruch::ExpiresDate("11/06/1994 08:49:37"),
            Expect::ResponseDated {
                value: "abc",
                lenient_dated: false,
                strict_dated: false,
            },
        ),
        s(
            "date-eu-dotted",
            "a European D.M.Y numeric date is not a cookie-date",
            Response,
            "SID",
            Keksbruch::ExpiresDate("06.11.1994 08:49:37"),
            Expect::ResponseDated {
                value: "abc",
                lenient_dated: false,
                strict_dated: false,
            },
        ),
        s(
            "date-epoch",
            "a bare Unix epoch-seconds integer is not a cookie-date",
            Response,
            "SID",
            Keksbruch::ExpiresDate("784108177"),
            Expect::ResponseDated {
                value: "abc",
                lenient_dated: false,
                strict_dated: false,
            },
        ),
        // ── domain: supercookie defense + IDN notation (Response) ───────────
        // Default kekse is a pure codec: it stores any av-octet `Domain` verbatim (it does not even
        // strip the leading dot — the matrix shows which parsers do). The `psl` / `idna` features
        // (the `hardened` build) turn it into policy: a public-suffix `Domain` (the supercookie) and
        // malformed punycode are refused, leaving the cookie host-only. The matrix compares how
        // other parsers strip the dot and read IDNs.
        s(
            "domain-supercookie-tld",
            "Domain=.com is a supercookie: stored verbatim by the pure codec, refused under `psl`",
            Response,
            "SID",
            Keksbruch::DomainValue(".com"),
            Expect::ResponseDomain {
                value: "abc",
                default_domain: Some(".com"),
                hardened_domain: None,
            },
        ),
        s(
            "domain-supercookie-icann",
            "Domain=co.uk is a multi-label public suffix: stored by the pure codec, refused under `psl`",
            Response,
            "SID",
            Keksbruch::DomainValue("co.uk"),
            Expect::ResponseDomain {
                value: "abc",
                default_domain: Some("co.uk"),
                hardened_domain: None,
            },
        ),
        s(
            "domain-registrable",
            "a real registrable Domain (eTLD+1) survives in every build",
            Response,
            "SID",
            Keksbruch::DomainValue("example.co.uk"),
            Expect::ResponseDomain {
                value: "abc",
                default_domain: Some("example.co.uk"),
                hardened_domain: Some("example.co.uk"),
            },
        ),
        s(
            "domain-punycode",
            "a punycode A-label IDN (xn--mnchen-3ya.de = münchen.de) is valid in every build",
            Response,
            "SID",
            Keksbruch::DomainValue("xn--mnchen-3ya.de"),
            Expect::ResponseDomain {
                value: "abc",
                default_domain: Some("xn--mnchen-3ya.de"),
                hardened_domain: Some("xn--mnchen-3ya.de"),
            },
        ),
        s(
            "domain-utf8",
            "a raw UTF-8 (U-label) Domain is non-ASCII, so the av-octet rule drops it in every build",
            Response,
            "SID",
            Keksbruch::DomainValue("münchen.de"),
            Expect::ResponseDomain {
                value: "abc",
                default_domain: None,
                hardened_domain: None,
            },
        ),
        s(
            "domain-malformed-punycode",
            "malformed punycode is av-octet-clean, so the pure codec stores it; the hardened build refuses it",
            Response,
            "SID",
            Keksbruch::DomainValue("xn--"),
            Expect::ResponseDomain {
                value: "abc",
                default_domain: Some("xn--"),
                hardened_domain: None,
            },
        ),
        // Multiple Domain= on one cookie — kekse never emits this (a `SetCookie` holds one
        // `Domain`); keksbruch hand-builds it to characterise the duplicate-attribute split.
        s(
            "domain-dup-last-wins",
            "two valid Domains: lenient takes the last, strict rejects the duplicate",
            Response,
            "SID",
            Keksbruch::DuplicateDomain {
                first: "a.example.com",
                second: "b.example.com",
            },
            Expect::ResponseStrictRejectsLenientKeeps { value: "abc" },
        ),
        s(
            "domain-dup-valid-then-invalid",
            "a valid then an invalid Domain: lenient ends host-only (last wins, then dropped), strict rejects",
            Response,
            "SID",
            Keksbruch::DuplicateDomain {
                first: "valid.example.com",
                second: "café",
            },
            Expect::ResponseStrictRejectsLenientKeeps { value: "abc" },
        ),
        s(
            "resp-crlf",
            "a CR/LF in the Set-Cookie value is refused outright",
            Response,
            "SID",
            Keksbruch::CrlfInValue,
            Expect::ResponseNone,
        ),
        // ── value corruption (Response) ─────────────────────────────────────
        // The Set-Cookie analogues of the request-value Keksbruch variants, so the
        // response-only parsers (go/.NET/tough-cookie/SimpleCookie) are exercised
        // on the same malformed *values*, not only on attributes. kekse refuses a
        // value carrying a non-cookie-octet in both modes (a value reject is harder
        // than an unknown-attribute reject, which is strict-only).
        s(
            "resp-ws-surrounding",
            "SP around the Set-Cookie name and value are trimmed away",
            Response,
            "SID",
            Keksbruch::SurroundingWhitespace,
            Expect::ResponseValue {
                value: "v",
                max_age: None,
                http_only: false,
                secure: false,
            },
        ),
        s(
            "resp-empty-value",
            "an empty Set-Cookie value is a valid, empty cookie",
            Response,
            "SID",
            Keksbruch::EmptyValue,
            Expect::ResponseValue {
                value: "",
                max_age: None,
                http_only: false,
                secure: false,
            },
        ),
        s(
            "resp-ctl-nul",
            "a NUL in the Set-Cookie value is not a cookie-octet — the cookie is refused",
            Response,
            "SID",
            Keksbruch::NulInValue,
            Expect::ResponseNone,
        ),
        s(
            "resp-ctl-other",
            "a C0 control byte in the Set-Cookie value is refused",
            Response,
            "SID",
            Keksbruch::ControlInValue(0x01),
            Expect::ResponseNone,
        ),
        s(
            "resp-quote-interior",
            "an interior DQUOTE is not a cookie-octet — the cookie is refused",
            Response,
            "SID",
            Keksbruch::InteriorQuote,
            Expect::ResponseNone,
        ),
        s(
            "resp-non-ascii",
            "a raw non-ASCII Set-Cookie value is refused (not cookie-octets)",
            Response,
            "SID",
            Keksbruch::RawNonAsciiValue,
            Expect::ResponseNone,
        ),
        // ── extra coverage: NUL positions, HTAB, multibyte UTF-8 ────────────
        s(
            "nul-in-name",
            "a NUL in the cookie name makes it a non-token — that pair is dropped",
            Request,
            "n",
            Keksbruch::NulInName,
            Expect::BothPairs(vec![("m", "ok")]),
        ),
        s(
            "nul-between-cookies",
            "a NUL fused to a later pair's name drops only it; neighbours survive",
            Request,
            "n",
            Keksbruch::NulBetweenCookies,
            Expect::BothPairs(vec![("a", "1"), ("c", "3")]),
        ),
        s(
            "tab-around",
            "HTAB around name and value is trimmed just like SP — tab is accepted",
            Request,
            "n",
            Keksbruch::TabAround,
            Expect::BothPairs(vec![("n", "v"), ("m", "ok")]),
        ),
        s(
            "raw-emoji",
            "a raw 4-byte emoji value is refused (not cookie-octets), like any non-ASCII",
            Request,
            "n",
            Keksbruch::RawEmojiValue,
            Expect::BothPairs(vec![("m", "ok")]),
        ),
        s(
            "pct-emoji",
            "a percent-encoded emoji round-trips to the 4-byte codepoint",
            Request,
            "n",
            Keksbruch::PercentEmojiValue,
            Expect::BothPairs(vec![("n", "🤖"), ("m", "ok")]),
        ),
        s(
            "attr-nul-name",
            "a NUL in an attribute name is an unknown attribute: strict rejects, lenient keeps",
            Response,
            "SID",
            Keksbruch::NulInAttrName,
            Expect::ResponseStrictRejectsLenientKeeps { value: "abc" },
        ),
        s(
            "attr-nul-value",
            "a NUL in a Path value survives parse (raw &str); the HeaderValue gate catches it (#9)",
            Response,
            "SID",
            Keksbruch::NulInAttrValue,
            Expect::ResponseValue {
                value: "abc",
                max_age: None,
                http_only: false,
                secure: false,
            },
        ),
        // ── structured & injection-flavoured (rich-type probes) ─────────────
        // Names/values that might coax a parser into a rich type (array/map) or
        // an injection. kekse is token-strict (drops bracket/angle names) and
        // octet-strict (drops a value carrying a non-octet); PHP's $_COOKIE is
        // the lone structurer (request-only) — see the matrix prose.
        s(
            "array-name",
            "a bracketed array-name: kekse drops the non-token; PHP builds an array",
            Request,
            "token",
            Keksbruch::BracketName { assoc: false },
            Expect::BothPairs(vec![("m", "ok")]),
        ),
        s(
            "assoc-name",
            "a bracketed map-name: kekse drops the non-token; PHP builds a map",
            Request,
            "sess",
            Keksbruch::BracketName { assoc: true },
            Expect::BothPairs(vec![("m", "ok")]),
        ),
        s(
            "json-value",
            "a JSON object as a value: the interior DQUOTE is a non-octet, so it drops",
            Request,
            "data",
            Keksbruch::ValuePayload("{\"testdata\":\"JSON\"}"),
            Expect::BothPairs(vec![("m", "ok")]),
        ),
        s(
            "bracket-value",
            "brackets in the value are cookie-octets: kept verbatim (cf. array-name)",
            Request,
            "data",
            Keksbruch::ValuePayload("[nested]"),
            Expect::BothPairs(vec![("data", "[nested]"), ("m", "ok")]),
        ),
        s(
            "markup-no-equals",
            "a bare <script> token has no =, so that segment is skipped",
            Request,
            "<script>",
            Keksbruch::MarkupName { valued: false },
            Expect::BothPairs(vec![("m", "ok")]),
        ),
        s(
            "markup-name",
            "angle brackets are not token chars, so the <script> name drops",
            Request,
            "<script>",
            Keksbruch::MarkupName { valued: true },
            Expect::BothPairs(vec![("m", "ok")]),
        ),
        s(
            "quoted-html-value",
            "a quoted markup value: quotes strip, then the interior space splits lenient from strict",
            Request,
            "data",
            Keksbruch::ValuePayload("\"<img src=x />\""),
            Expect::SplitPairs {
                lenient: vec![("data", "<img src=x />"), ("m", "ok")],
                strict: vec![("m", "ok")],
            },
        ),
        s(
            "truthy",
            "a clean truthy value stays the string \"yes\" — no parser coerces a bool",
            Request,
            "truthy",
            Keksbruch::ValuePayload("yes"),
            Expect::BothPairs(vec![("truthy", "yes"), ("m", "ok")]),
        ),
        s(
            "equals-bare",
            "a bare = is an empty name: the pair is dropped",
            Request,
            "n",
            Keksbruch::EqualsOnly(1),
            Expect::BothPairs(vec![]),
        ),
        s(
            "equals-double",
            "== splits to an empty name with value `=`: the pair is dropped",
            Request,
            "n",
            Keksbruch::EqualsOnly(2),
            Expect::BothPairs(vec![]),
        ),
        s(
            "nul-empty-name",
            "a name that is a lone NUL byte is a non-token: that pair is dropped",
            Request,
            "n",
            Keksbruch::NulOnlyName,
            Expect::BothPairs(vec![("m", "ok")]),
        ),
        // ── structured shapes (Response) ────────────────────────────────────
        // The Set-Cookie mirrors of the value-shaped probes. No Set-Cookie parser
        // builds a rich type (PHP is request-only), so these test flat parsing of
        // the same malformed values; kekse's response value rule always allows
        // whitespace (unlike strict request), so quoted-html keeps here.
        s(
            "resp-array-name",
            "a bracketed array-name in Set-Cookie: the non-token name is refused",
            Response,
            "token",
            Keksbruch::BracketName { assoc: false },
            Expect::ResponseNone,
        ),
        s(
            "resp-json-value",
            "a JSON object Set-Cookie value: the interior DQUOTE is refused",
            Response,
            "data",
            Keksbruch::ValuePayload("{\"testdata\":\"JSON\"}"),
            Expect::ResponseNone,
        ),
        s(
            "resp-bracket-value",
            "brackets in a Set-Cookie value are octets: a valid cookie",
            Response,
            "data",
            Keksbruch::ValuePayload("[nested]"),
            Expect::ResponseValue {
                value: "[nested]",
                max_age: None,
                http_only: false,
                secure: false,
            },
        ),
        s(
            "resp-quoted-html-value",
            "a quoted markup Set-Cookie value: response always allows WS, so both modes keep it",
            Response,
            "data",
            Keksbruch::ValuePayload("\"<img src=x />\""),
            Expect::ResponseValue {
                value: "<img src=x />",
                max_age: None,
                http_only: false,
                secure: false,
            },
        ),
        s(
            "resp-quoted-pair-flag",
            "a whole quoted name=value plus a flag: the leading DQUOTE makes the name a non-token",
            Response,
            "sid",
            Keksbruch::QuotedPairWithFlag,
            Expect::ResponseNone,
        ),
    ]
}
