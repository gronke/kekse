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
    /// `issues` is the accepted-with-issues channel: what the parser recovered
    /// from along the way, as free-form human-facing lines (kekse's typed
    /// issues rendered; another tool's diagnostics). Optional — empty for a
    /// clean parse and for tools that cannot report any — and glyph-neutral:
    /// it never changes the cell outcome or the consensus vote.
    Cookies {
        cookies: Vec<CookieView>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        issues: Vec<String>,
    },
    /// A request parser rejected the whole header (fail-hard — biscotti's mode).
    Rejected { error: String },
    /// A `Set-Cookie` parsed into one cookie, with the same optional
    /// accepted-with-issues channel as [`Cookies`](ParseOutcome::Cookies).
    SetCookie {
        set_cookie: SetCookieView,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        issues: Vec<String>,
    },
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
    /// attributed to the exact payload that triggered it. `stdout`/`stderr` carry
    /// the crashing process's captured output (a stack trace, usually) for the HTML
    /// tooltip; both are `#[serde(default)]` so a sidecar that emits `Crashed`
    /// itself may omit them.
    Crashed {
        reason: String,
        #[serde(default)]
        stdout: Option<String>,
        #[serde(default)]
        stderr: Option<String>,
    },
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
    /// CHIPS' `Partitioned` flag, tri-state: `Some(true)`/`Some(false)` from a
    /// driver whose library and protocol can see the attribute (kept vs
    /// dropped), `None` from one whose reporting channel has no field for it
    /// (classic WebDriver, the Netscape jar format) — "not observable", never
    /// to be scored as a drop.
    #[serde(default)]
    pub partitioned: Option<bool>,
    #[serde(default)]
    pub same_site: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub max_age: Option<i64>,
    /// The parsed `Expires` attribute as a Unix timestamp (seconds), or `None`. Populated by
    /// parsers that expose the parsed attribute distinctly and deterministically; a client jar
    /// that folds `Expires` / `Max-Age` into one effective (possibly now-relative) expiry reports
    /// `None`, so a cell never depends on when the matrix ran.
    #[serde(default)]
    pub expires: Option<i64>,
}

impl ParseOutcome {
    /// A compact, single-cell rendering for the matrix.
    pub fn cell(&self) -> String {
        match self {
            ParseOutcome::Cookies { cookies, .. } => render_cookies(cookies),
            ParseOutcome::Rejected { .. } => "❌".to_string(),
            // Context-free rendering (consensus key, jar-probe cells): the raw stored path.
            // The response table resolves a jar's substituted default-path via `display_cell`.
            ParseOutcome::SetCookie { set_cookie, .. } => set_cookie.cell(PathRender::Verbatim),
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

    /// The recovered issues an *accepted* outcome carried
    /// ([`Cookies`](ParseOutcome::Cookies) / [`SetCookie`](ParseOutcome::SetCookie)),
    /// empty otherwise. A rejection's reason stays its single `error`
    /// (see [`detail`](ParseOutcome::detail)); this channel is what fail-soft
    /// recovered from while still accepting.
    #[must_use]
    pub fn issues(&self) -> &[String] {
        match self {
            ParseOutcome::Cookies { issues, .. } | ParseOutcome::SetCookie { issues, .. } => issues,
            _ => &[],
        }
    }

    /// The diagnostic text a cell carries for an HTML hover tooltip: the rejection
    /// `error`, the crash `reason`, or the panic `message` — error text only; the
    /// accepted-with-issues list renders through
    /// [`diagnostics`](ParseOutcome::diagnostics). `None` for any outcome that
    /// has no error text (a successful parse, `n/a`, `SKIP`, or a forwarding verdict) —
    /// so a tooltip is attached exactly when there is something to explain.
    #[must_use]
    pub fn detail(&self) -> Option<&str> {
        match self {
            ParseOutcome::Rejected { error } | ParseOutcome::SetCookieRejected { error } => {
                Some(error)
            }
            ParseOutcome::Crashed { reason, .. } => Some(reason),
            ParseOutcome::Panicked { message } => Some(message),
            _ => None,
        }
    }

    /// The full multi-line diagnostic for the HTML tooltip's `<pre>`: a rejection
    /// `error` or panic `message` as-is, and for a [`Crashed`](ParseOutcome::Crashed)
    /// sidecar the `reason` plus its captured `stdout`/`stderr` under labelled
    /// dividers; for an accepted outcome carrying recovered `issues`, the list as
    /// bullet lines. `None` when there is nothing to explain (a clean parse, `n/a`,
    /// `SKIP`, a forwarding verdict). Control bytes are made visible, but newlines
    /// and tabs are kept so a stack trace renders line-for-line.
    #[must_use]
    pub fn diagnostics(&self) -> Option<String> {
        match self {
            ParseOutcome::Cookies { issues, .. } | ParseOutcome::SetCookie { issues, .. }
                if !issues.is_empty() =>
            {
                Some(
                    issues
                        .iter()
                        .map(|issue| format!("• {}", sanitize_multiline(issue)))
                        .collect::<Vec<_>>()
                        .join("\n"),
                )
            }
            ParseOutcome::Rejected { error } | ParseOutcome::SetCookieRejected { error } => {
                Some(sanitize_multiline(error))
            }
            ParseOutcome::Panicked { message } => Some(sanitize_multiline(message)),
            ParseOutcome::Crashed {
                reason,
                stdout,
                stderr,
            } => {
                let mut out = sanitize_multiline(reason);
                for (label, stream) in [("stdout", stdout), ("stderr", stderr)] {
                    if let Some(text) = stream {
                        out.push_str(&format!("\n\n── {label} ──\n{}", sanitize_multiline(text)));
                    }
                }
                Some(out)
            }
            _ => None,
        }
    }
}

/// How a jar column's stored `Path` renders in a cell. A jar reports the *effective*
/// scope it stored, which for a cookie whose `Path` it could not use is the request
/// default-path (§5.1.4) — a harness artifact (`/r` for the browser origin, `/` for the
/// client/HttpClient5 origins), never a value read off the wire. The matrix resolves that
/// away rather than printing our own plumbing; see [`matrix::resolve_jar_path`].
///
/// [`matrix::resolve_jar_path`]: super::matrix
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum PathRender {
    /// Render `self.path` verbatim (`Path=<value>`), or nothing when it is `None` — the
    /// context-free default, used by every non-jar column and every genuine wire path.
    Verbatim,
    /// The stored path is the request default-path the jar substituted for an *engaged but
    /// unusable* wire `Path` — render `Path⇒default`, stating the fall-back without the value.
    Defaulted,
    /// The stored path is the substituted default and the wire engaged no `Path` at all —
    /// render nothing (a plain no-Path cookie stays silent).
    Hidden,
}

impl SetCookieView {
    pub(crate) fn cell(&self, path: PathRender) -> String {
        let mut flags = Vec::new();
        if self.http_only {
            flags.push("HttpOnly".to_string());
        }
        if self.secure {
            flags.push("Secure".to_string());
        }
        if self.partitioned == Some(true) {
            flags.push("Partitioned".to_string());
        }
        if let Some(s) = &self.same_site {
            flags.push(format!("SameSite={s}"));
        }
        match path {
            PathRender::Verbatim => {
                if let Some(p) = &self.path {
                    flags.push(format!("Path={p}"));
                }
            }
            // The jar substituted its request default-path for an engaged-but-unusable
            // Path; state the fall-back, not the harness value (`/r` / `/`).
            PathRender::Defaulted => flags.push("Path⇒default".to_string()),
            PathRender::Hidden => {}
        }
        if let Some(d) = &self.domain {
            flags.push(format!("Domain={d}"));
        }
        if let Some(e) = self.expires {
            flags.push(format!("Expires={}", fmt_expires(e)));
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

/// Render a Unix-timestamp `Expires` as the canonical UTC HTTP-date for the cell (falling back to
/// the raw epoch if it is out of range), so parsers that agree on the instant read identically and
/// the value is legible rather than a bare integer.
fn fmt_expires(epoch: i64) -> String {
    rfc_6265::OffsetDateTime::from_unix_timestamp(epoch)
        .map(rfc_6265::date::format_imf_fixdate)
        .unwrap_or_else(|_| epoch.to_string())
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

/// Make control bytes visible for a tooltip `<pre>` while **keeping** newlines and
/// tabs, so a captured stack trace renders line-for-line. `\r` is dropped (so a
/// CRLF trace does not render doubled), and NUL / other C0 / DEL bytes become
/// `\xNN`. (`matrix::escape_controls` deliberately flattens newlines for a
/// single-line cell; this is its multi-line sibling.)
fn sanitize_multiline(s: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\n' | '\t' => out.push(ch),
            '\r' => {}
            c if c.is_control() => {
                let _ = write!(out, "\\x{:02x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detail_exposes_reject_error_crash_reason_and_panic_message() {
        assert_eq!(
            ParseOutcome::Rejected {
                error: "bad header".into()
            }
            .detail(),
            Some("bad header")
        );
        assert_eq!(
            ParseOutcome::SetCookieRejected {
                error: "unknown attribute".into()
            }
            .detail(),
            Some("unknown attribute")
        );
        assert_eq!(
            ParseOutcome::Crashed {
                reason: "signal 11".into(),
                stdout: None,
                stderr: None,
            }
            .detail(),
            Some("signal 11")
        );
        assert_eq!(
            ParseOutcome::Panicked {
                message: "index out of bounds".into()
            }
            .detail(),
            Some("index out of bounds")
        );
        // Outcomes with no error text carry no tooltip.
        assert_eq!(ParseOutcome::NotApplicable.detail(), None);
        assert_eq!(ParseOutcome::ForwardedVerbatim.detail(), None);
    }

    fn set_cookie(expires: Option<i64>) -> SetCookieView {
        SetCookieView {
            name: "SID".into(),
            value: "abc".into(),
            http_only: false,
            secure: false,
            partitioned: None,
            same_site: None,
            path: None,
            domain: None,
            max_age: None,
            expires,
        }
    }

    #[test]
    fn cell_renders_expires_as_a_readable_utc_date() {
        // A Unix-timestamp expiry round-trips to the canonical HTTP-date in the cell.
        let epoch = rfc_6265::date::parse_imf_fixdate("Sun, 06 Nov 1994 08:49:37 GMT")
            .unwrap()
            .unix_timestamp();
        assert_eq!(
            set_cookie(Some(epoch)).cell(PathRender::Verbatim),
            "SID=abc ;Expires=Sun, 06 Nov 1994 08:49:37 GMT"
        );
    }

    #[test]
    fn cell_without_expires_is_unchanged() {
        assert_eq!(set_cookie(None).cell(PathRender::Verbatim), "SID=abc");
    }

    #[test]
    fn diagnostics_joins_crash_reason_with_captured_streams() {
        let d = ParseOutcome::Crashed {
            reason: "signal 11".into(),
            stdout: Some("go: downloading\r\n".into()),
            stderr: Some("panic: runtime error\n\tmain.parse()\n".into()),
        }
        .diagnostics()
        .unwrap();
        assert!(d.contains("signal 11"), "{d}");
        assert!(d.contains("── stdout ──"), "{d}");
        assert!(d.contains("── stderr ──"), "{d}");
        // Newlines and tabs survive for the <pre>; CR is dropped so CRLF is not doubled.
        assert!(d.contains("panic: runtime error\n\tmain.parse()"), "{d}");
        assert!(!d.contains('\r'), "{d}");
    }

    #[test]
    fn diagnostics_omits_absent_streams_and_clean_outcomes() {
        // A crash with no captured output is just its reason.
        assert_eq!(
            ParseOutcome::Crashed {
                reason: "timeout".into(),
                stdout: None,
                stderr: None,
            }
            .diagnostics()
            .as_deref(),
            Some("timeout")
        );
        // A reject surfaces its text; clean outcomes have none.
        assert_eq!(
            ParseOutcome::SetCookieRejected {
                error: "unknown attribute".into()
            }
            .diagnostics()
            .as_deref(),
            Some("unknown attribute")
        );
        assert_eq!(ParseOutcome::NotApplicable.diagnostics(), None);
        assert_eq!(ParseOutcome::Skipped.diagnostics(), None);
    }

    #[test]
    fn issue_channel_is_optional_and_glyph_neutral() {
        // A sidecar predating the channel deserializes with an empty list…
        let old_wire = r#"{"outcome":"SetCookie","set_cookie":{"name":"SID","value":"x"}}"#;
        let outcome: ParseOutcome = serde_json::from_str(old_wire).unwrap();
        assert!(outcome.issues().is_empty());
        // …and a clean outcome serializes without the key, byte-identical to
        // the pre-channel wire — the protocol only grows for dirty accepts.
        assert!(!serde_json::to_string(&outcome).unwrap().contains("issues"));

        // The cell and the consensus key ignore the channel entirely.
        let dirty = ParseOutcome::SetCookie {
            set_cookie: set_cookie(None),
            issues: vec!["value `1` on the presence-only `Secure` flag".into()],
        };
        let clean = ParseOutcome::SetCookie {
            set_cookie: set_cookie(None),
            issues: Vec::new(),
        };
        assert_eq!(dirty.cell(), clean.cell());
        assert_eq!(dirty.consensus_key(), clean.consensus_key());
    }

    #[test]
    fn accepted_with_issues_renders_a_bullet_list() {
        let dirty = ParseOutcome::Cookies {
            cookies: vec![CookieView::new("SID", "x")],
            issues: vec!["cookie pair `junk` has no `=`".into(), "second".into()],
        };
        assert_eq!(
            dirty.diagnostics().as_deref(),
            Some("• cookie pair `junk` has no `=`\n• second")
        );
        // detail() stays error-text-only: an accepted outcome has none.
        assert_eq!(dirty.detail(), None);
    }
}
