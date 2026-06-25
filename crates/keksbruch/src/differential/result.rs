//! The common normalized schema every comparator (in-process Rust, or a
//! language sidecar over JSONL) maps its parse into, so wildly different parser
//! APIs become diff-able cells. Internally tagged so the sidecar JSON reads
//! `{"outcome":"Cookies","cookies":[...]}`.

use serde::{Deserialize, Serialize};

/// What one parser did with one payload, normalized.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome")]
pub enum ParseOutcome {
    /// A request header parsed into these `(name, value)` cookies, in order.
    Cookies { cookies: Vec<CookieView> },
    /// A request parser rejected the whole header (fail-hard — biscotti's mode).
    Rejected { error: String },
    /// A `Set-Cookie` parsed into one cookie.
    SetCookie { set_cookie: SetCookieView },
    /// A `Set-Cookie` parser rejected the input.
    SetCookieRejected { error: String },
    /// A *forwarding* target (nginx proxy) passed the request Cookie header on
    /// byte-for-byte. A fidelity verdict, not a parse — kept off the consensus
    /// vote (see `matrix::consensus`), so it never groups with the parse columns.
    ForwardedVerbatim,
    /// A forwarding target passed a Cookie header on, but altered the bytes;
    /// `forwarded` is what the upstream received.
    ForwardedAltered { forwarded: String },
    /// A forwarding target did not pass the Cookie on — it rejected the request
    /// (e.g. nginx 400 on a malformed header) or dropped the header.
    ForwardedRejected,
    /// This parser does not handle this direction (e.g. biscotti has no
    /// `Set-Cookie` parser; a request-only library asked for a response).
    NotApplicable,
    /// An in-process adapter panicked — a finding about the parser. Rendered
    /// `☠️`, the same crash marker as [`Crashed`](ParseOutcome::Crashed).
    Panicked { message: String },
    /// A sidecar subprocess **crashed** on this payload — it died on a signal
    /// (e.g. a segfault), exited non-zero, or hung past the timeout. `reason`
    /// carries the diagnosis (`signal 11`, `exit 134`, `timeout`); the cell shows
    /// `☠️`. Distinct from [`Skipped`](ParseOutcome::Skipped) (the tool was never
    /// available) and from an empty/`❌` parse — a crash is its own finding,
    /// attributed to the exact payload that triggered it.
    Crashed { reason: String },
    /// The comparator was unavailable (interpreter or dependency missing) — SKIP.
    Skipped,
}

/// The structural shape of a parsed cookie value. Almost every parser returns a
/// flat string ([`ValueShape::Scalar`]); PHP's `$_COOKIE` (and any future
/// structuring parser) builds an array from `name[]=v` or a map from `name[k]=v`
/// — a *rich type* the flat `value` string cannot honestly represent. The `value`
/// still carries the JSON-encoded shape for display; this field is the explicit
/// marker that the result *is* structured, so it is never confused with a string
/// that merely looks like JSON. Defaults to `Scalar`, so a sidecar that omits it
/// (every one but PHP) deserializes correctly.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValueShape {
    /// A flat string value — the shape every parser but PHP produces.
    #[default]
    Scalar,
    /// An indexed array (PHP `name[]=v`); `value` carries its JSON encoding.
    Array,
    /// An associative map (PHP `name[k]=v`); `value` carries its JSON encoding.
    Object,
}

impl ValueShape {
    /// Whether this is the default flat-string shape — drives the
    /// `skip_serializing_if` so a scalar cookie serializes with no `shape` key.
    fn is_scalar(&self) -> bool {
        matches!(self, ValueShape::Scalar)
    }

    /// The type name to display when the parsed value is not a string, or `None`
    /// for a plain string (which needs no annotation).
    fn type_name(self) -> Option<&'static str> {
        match self {
            ValueShape::Scalar => None,
            ValueShape::Array => Some("array"),
            ValueShape::Object => Some("object"),
        }
    }
}

/// One parsed request cookie, normalized to name and decoded value. `shape` marks
/// a value the parser built as a rich type (array/map) rather than a string —
/// only PHP's `$_COOKIE` does this today; see [`ValueShape`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CookieView {
    pub name: String,
    pub value: String,
    #[serde(default, skip_serializing_if = "ValueShape::is_scalar")]
    pub shape: ValueShape,
}

impl CookieView {
    /// A scalar (plain-string) cookie — the shape every in-process comparator and
    /// every sidecar but PHP produces. PHP's structured values arrive over the
    /// wire with an explicit `shape`, so they are built by deserialization.
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            shape: ValueShape::Scalar,
        }
    }
}

/// One parsed `Set-Cookie`, normalized. `max_age` is `i64` to preserve a
/// negative delta some parsers keep; `same_site` is a `String` to preserve a
/// token kekse's enum would not (e.g. a parser that echoes a bogus value).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SetCookieView {
    pub name: String,
    pub value: String,
    #[serde(default)]
    pub http_only: bool,
    #[serde(default)]
    pub secure: bool,
    #[serde(default)]
    pub same_site: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub max_age: Option<i64>,
}

impl ParseOutcome {
    /// A compact, single-cell rendering for the matrix.
    pub fn cell(&self) -> String {
        match self {
            ParseOutcome::Cookies { cookies } => render_cookies(cookies),
            ParseOutcome::Rejected { .. } => "❌".to_string(),
            ParseOutcome::SetCookie { set_cookie } => set_cookie.cell(),
            ParseOutcome::SetCookieRejected { .. } => "❌".to_string(),
            ParseOutcome::ForwardedVerbatim => "≡".to_string(),
            ParseOutcome::ForwardedAltered { forwarded } => format!("≠ {}", short(forwarded)),
            ParseOutcome::ForwardedRejected => "❌".to_string(),
            ParseOutcome::NotApplicable => "n/a".to_string(),
            // Both crash flavours render the same marker: an in-process panic and a
            // sidecar subprocess death are both "the parser blew up on this input".
            ParseOutcome::Panicked { .. } | ParseOutcome::Crashed { .. } => "☠️".to_string(),
            ParseOutcome::Skipped => "SKIP".to_string(),
        }
    }

    /// The key the consensus vote groups on: the very string the cell shows, so
    /// "agreement" means "rendered the same outcome" and the consensus column
    /// reads identically to the parser cells. A request `Rejected` and a
    /// Set-Cookie `SetCookieRejected` both render `❌`, so they already group
    /// together. (`n/a` and `SKIP` are excluded from the vote by the caller.)
    pub fn consensus_key(&self) -> String {
        self.cell()
    }
}

impl SetCookieView {
    fn cell(&self) -> String {
        let mut flags = Vec::new();
        if self.http_only {
            flags.push("HttpOnly".to_string());
        }
        if self.secure {
            flags.push("Secure".to_string());
        }
        if let Some(s) = &self.same_site {
            flags.push(format!("SameSite={s}"));
        }
        if let Some(p) = &self.path {
            flags.push(format!("Path={p}"));
        }
        if let Some(d) = &self.domain {
            flags.push(format!("Domain={d}"));
        }
        if let Some(m) = self.max_age {
            flags.push(format!("Max-Age={m}"));
        }
        if flags.is_empty() {
            format!("{}={}", self.name, short(&self.value))
        } else {
            format!("{}={} ;{}", self.name, short(&self.value), flags.join(";"))
        }
    }
}

/// Render a parsed cookie list compactly, truncating long values and long lists
/// so a scale payload (a 4 KiB value, 21 pairs) stays a readable single cell.
fn render_cookies(cookies: &[CookieView]) -> String {
    if cookies.is_empty() {
        return "∅".to_string();
    }
    const MAX: usize = 4;
    let shown = cookies
        .iter()
        .take(MAX)
        // When a parser interpreted the value as a non-string type (PHP's `$_COOKIE`
        // arrays/maps), show that type name in ⟨…⟩ before the JSON-encoded value, so
        // a rich type reads distinctly from a string; the inner `[...]`/`{...}` shows
        // array vs map.
        .map(|c| match c.shape.type_name() {
            None => format!("{}={}", c.name, short(&c.value)),
            Some(t) => format!("{}=⟨{}⟩{}", c.name, t, short(&c.value)),
        })
        .collect::<Vec<_>>()
        .join(", ");
    if cookies.len() > MAX {
        format!("[{shown}, …(+{} more)]", cookies.len() - MAX)
    } else {
        format!("[{shown}]")
    }
}

/// Truncate a long value to a short prefix plus a length marker.
fn short(value: &str) -> String {
    let count = value.chars().count();
    if count > 24 {
        let prefix: String = value.chars().take(12).collect();
        format!("{prefix}…<{count} chars>")
    } else {
        value.to_string()
    }
}
