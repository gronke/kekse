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
            "a duplicated known attribute is accepted (last wins)",
            Response,
            "SID",
            Keksbruch::DuplicateAttribute("Path"),
            Expect::ResponseValue {
                value: "abc",
                max_age: None,
                http_only: false,
                secure: false,
            },
        ),
        s(
            "resp-crlf",
            "a CR/LF in the Set-Cookie value is refused outright",
            Response,
            "SID",
            Keksbruch::CrlfInValue,
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
    ]
}
