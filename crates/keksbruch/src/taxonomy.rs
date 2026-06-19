//! The corruption taxonomy: every *category* of malformed cookie wire keksbruch
//! knows how to build, plus the direction a scenario targets.

/// Which header a scenario exercises — they parse through different kekse
/// entry points and tolerate different shapes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// A request `Cookie:` header — tested via `parse_pairs` / `parse_pairs_strict`.
    Request,
    /// A response `Set-Cookie:` header value — tested via `SetCookie::parse` /
    /// `parse_lenient`.
    Response,
}

/// One category of corruption applied to a logical cookie when building wire.
/// A closed enum so [`render`](crate::KeksbruchRecipe::render) is an exhaustive
/// match and the corpus stays deterministic; variants carry the concrete payload
/// where one is needed (a control byte, an attribute name, a size).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Keksbruch {
    // ── whitespace ──────────────────────────────────────────────────────────
    /// Raw `SP`/`HTAB` around the name and value: `  n  =  v  `.
    SurroundingWhitespace,
    /// A raw internal space in the value: `n=a b` (lenient keeps `a b`; strict
    /// refuses the non-octet space).
    InternalWhitespace,

    // ── control-char injection (the security core) ───────────────────────────
    /// A NUL byte spliced into the value (truncation / log-poison probe).
    NulInValue,
    /// A bare CR/LF in the value — the header-injection probe.
    CrlfInValue,
    /// Some other C0 control byte in the value.
    ControlInValue(u8),

    // ── quoting anomalies ─────────────────────────────────────────────────────
    /// A single dangling quote: `n="v`.
    UnbalancedQuote,
    /// An interior quote in an otherwise bare value: `n=a"b`.
    InteriorQuote,

    // ── percent-encoding anomalies ────────────────────────────────────────────
    /// A truncated escape: `n=%4`.
    TruncatedPercent,
    /// A percent escape that decodes to invalid UTF-8: `n=%FF`.
    InvalidUtf8Percent,
    /// A raw, un-escaped non-UTF-8 byte in the wire — cannot be a `&str` at all.
    RawInvalidUtf8Byte,

    // ── delimiter abuse ────────────────────────────────────────────────────────
    /// A raw `;` spliced into the value, smuggling a second pair: `n=a;evil=1`.
    SemicolonInValue,
    /// Empty `;`-segments: `n=v;;;m=w`.
    EmptySegments,
    /// A segment with no `=` at all: `flag; n=v`.
    NoEquals,
    /// An extra `=` in the value (split is on the first `=` only): `n=a=b`.
    ExtraEquals,

    // ── duplicate names ────────────────────────────────────────────────────────
    /// The same name repeated: `k=1; k=2; k=3`.
    DuplicateName,
    /// A case-variant duplicate: `sid=lo; SID=hi`.
    CaseVariantDuplicate,

    // ── empty name / value ─────────────────────────────────────────────────────
    /// An empty name: `=v`.
    EmptyName,
    /// An empty value: `n=` (a valid, empty cookie).
    EmptyValue,

    // ── non-ASCII ──────────────────────────────────────────────────────────────
    /// A raw non-ASCII (but valid UTF-8) value: `n=café`.
    RawNonAsciiValue,
    /// A non-token (non-ASCII) name: `naïve=v`.
    NonAsciiName,

    // ── scale ──────────────────────────────────────────────────────────────────
    /// A very long value — `n=` + `x` × `n` (memory / quadratic probe).
    HugeValue(usize),
    /// Many pairs with a sentinel `target=found` at the end.
    ManyPairs(usize),
    /// A long run of control junk in one segment between two valid pairs.
    ControlJunkRun(usize),

    // ── attribute abuse (Response only) ─────────────────────────────────────────
    /// An unrecognised attribute: `; Priority=High`.
    UnknownAttribute(&'static str),
    /// A non-numeric or negative `Max-Age`: `; Max-Age=banana`.
    BadMaxAge(&'static str),
    /// A garbage `SameSite` token: `; SameSite=Bogus`.
    GarbageSameSite(&'static str),
    /// A valueless flag handed a value: `; Secure=1`.
    ValuedFlag(&'static str),
    /// A duplicated attribute: `; Path=/a; Path=/b`.
    DuplicateAttribute(&'static str),
}
