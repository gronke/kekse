//! The corruption taxonomy: every *category* of malformed cookie wire keksbruch
//! knows how to build, plus the direction a scenario targets.

/// Which header a scenario exercises — they parse through different kekse
/// entry points and tolerate different shapes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// A request `Cookie:` header — tested via `parse_pairs` / `parse_pairs_strict`.
    Request,
    /// A response `Set-Cookie:` header value — tested via `SetCookie::parse` /
    /// `parse_strict`.
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
    /// A garbage `SameSite` token: `; SameSite=Bogus`. (The renderer is generic —
    /// `; SameSite=<val>` — so the well-defined values ride this variant too.)
    GarbageSameSite(&'static str),
    /// A `SameSite` value plus the `Secure` flag: `; SameSite=<val>; Secure`
    /// (Response). Probes 6265bis's "SameSite=None requires Secure" policy —
    /// engines refuse the bare form and accept this one.
    SameSiteSecure(&'static str),
    /// A valueless flag handed a value: `; Secure=1`.
    ValuedFlag(&'static str),
    /// A duplicated attribute: `; Path=/a; Path=/b`.
    DuplicateAttribute(&'static str),
    /// An `Expires` date in some format: `; Expires=<val>` (Response). Probes the
    /// lenient RFC 6265 §5.1.1 cookie-date vs strict RFC 7231 IMF-fixdate split,
    /// and how other parsers read the obsolete RFC 850 / asctime() forms.
    ExpiresDate(&'static str),
    /// A `Domain` attribute carrying a specific value: `; Domain=<v>` (Response). Probes
    /// supercookie (public-suffix) `Domain`s and punycode-vs-UTF-8 host notation. Default kekse
    /// stores the raw av-octet value; under the `psl`/`idna` features it enforces policy (a
    /// public-suffix or malformed-IDN value is refused, leaving the cookie host-only).
    DomainValue(&'static str),
    /// A `Path` attribute carrying a specific value: `; Path=<v>` (Response). Probes how
    /// parsers treat a path that is empty, a bare/relative `.`/`./`, or a non-path URI
    /// (`file:///etc/passwd`). RFC 6265 §4.1.1 path-av is just av-octets with no
    /// semantics, so kekse stores the value verbatim; the matrix shows who normalises,
    /// rejects, or applies default-path logic at parse time.
    PathValue(&'static str),
    /// A `Path` whose value is `/` plus `a` × `n` (Response). RFC 6265 has no length
    /// cap on an av — kekse keeps it — while 6265bis caps attribute values at 1024
    /// bytes, so engines drop the attribute and fall back to the default-path.
    OverlongPath(usize),
    /// Two `Domain=` attributes on one cookie: `; Domain=<first>; Domain=<second>` (Response).
    /// kekse never *emits* this (a `SetCookie` holds one `Domain`), so keksbruch hand-builds it:
    /// lenient parse takes the last value, strict parse rejects the duplicate outright.
    DuplicateDomain {
        first: &'static str,
        second: &'static str,
    },
    /// A "kitchen-sink" Set-Cookie that sets **all seven** non-date attributes at once
    /// (`; Path=…; Domain=…; Max-Age=…; Secure; HttpOnly; SameSite=…; Partitioned`) (Response). Probes
    /// attribute *fidelity*: which parsers surface every attribute vs silently drop one —
    /// the matrix renders this as an explicit per-attribute grid.
    AllAttributes,
    /// The CHIPS `Partitioned` flag appended to the baseline: `; Partitioned`,
    /// repeated when `duplicated`, with the conformant `; Secure` pairing
    /// appended when `with_secure` (Response). Probes which parsers model the
    /// flag and who witnesses (or enforces) the missing `Secure`.
    PartitionedFlag { with_secure: bool, duplicated: bool },
    /// A cookie pair with a verbatim attribute tail: `name=value<attrs>`
    /// (Response). The tail is authored directly — deliberately *not* the base
    /// cookie's attributes — so the wire can omit or violate what the base's
    /// conformant baseline carries (the RFC 6265bis §4.1.3 prefix rules) or
    /// combine attributes no single-attribute variant renders (the CHIPS
    /// pairings). An empty tail probes the bare pair itself, e.g. a cookie
    /// literally named `Partitioned`.
    AttrTail { attrs: &'static str },
    /// A known attribute token in the *pair position*: `<token>; name=value`
    /// (Response). RFC 6265 §5.2 makes the leading segment the pair, and this
    /// one has no `=`, so a conformant parser finds no usable pair — while a
    /// parser that pattern-matches attribute names anywhere may skip the token
    /// and adopt the later pair instead.
    LeadingToken(&'static str),

    // ── extra coverage: NUL positions, HTAB, multibyte UTF-8 ─────────────────
    /// A NUL byte in the cookie *name*: `n\0x=v`.
    NulInName,
    /// A NUL fused to a middle pair's name, between valid cookies: `a=1; \0b=2; c=3`.
    NulBetweenCookies,
    /// A NUL byte in a `Set-Cookie` attribute *name*: `Pa\0th` (Response).
    NulInAttrName,
    /// A NUL byte in a `Set-Cookie` attribute *value*: `Path=/a\0b` (Response).
    NulInAttrValue,
    /// HTAB (not SP) around name and value — is tab accepted as whitespace?
    TabAround,
    /// A raw 4-byte UTF-8 emoji value: `n=🤖`.
    RawEmojiValue,
    /// A percent-encoded 4-byte UTF-8 emoji value: `n=%F0%9F%A4%96`.
    PercentEmojiValue,

    // ── structured / injection-flavoured (rich-type) shapes ──────────────────
    /// A bracketed (array-style) name: `n[]=nested` (indexed) or `n[k]=v`
    /// (associative). PHP's `$_COOKIE` builds an array/map from these — the
    /// matrix's only rich types; a token-strict parser drops the pair.
    BracketName { assoc: bool },
    /// A structured-looking *value* carried verbatim — a JSON object
    /// `n={"a":"b"}`, a bracket value `n=[x]`, a quoted-markup value
    /// `n="<img src=x>"`, or a plain control `n=yes`. The payload is the value.
    ValuePayload(&'static str),
    /// A markup/injection name: `<script>=empty` (valued) or bare `<script>`
    /// (no `=`). Probes whether a non-token, XSS-flavoured name is kept.
    MarkupName { valued: bool },
    /// A degenerate run of `=` and nothing else: `=` (`k=1`) or `==` (`k=2`).
    EqualsOnly(usize),
    /// A name that is a single NUL byte with an empty value: `\0=`.
    NulOnlyName,
    /// A bare token with no `=` at all — the whole wire is the name: `justvalue`
    /// (Response). RFC 6265 §5.2 ignores a set-cookie-string without `=`; 6265bis
    /// reads it as a nameless cookie.
    BareValue,
    /// A raw SP inside the cookie *name*: `S ID=…` — SP is not a token character.
    SpaceInName,
    /// A whole `name=value` wrapped in DQUOTEs plus a flag attribute:
    /// `"sid=..." ; Secure` (Response).
    QuotedPairWithFlag,
}
