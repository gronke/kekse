//! Render the differential matrix from **one prose template plus precompiled
//! fragments**. The document's English text lives in `cookie_matrix.md.tera`
//! (authored Markdown with `{{ … }}` markers); the dynamic parts — the two wide
//! matrix tables, the attribute-fidelity grid, and the divergences / versions lists —
//! are built here in two forms and spliced in by Tera:
//!
//! * [`render`] inserts the **Markdown** fragments → `COOKIE_MATRIX.md`.
//! * [`render_html`] converts the template's prose to HTML (via `pulldown-cmark`),
//!   then inserts the **HTML** fragments (built by [`maud`], which entity-encodes
//!   every untrusted cell by construction) and wraps the body in a self-contained
//!   scaffold → the `COOKIE_MATRIX.html` report.
//! * [`render_csv`] is unchanged — the transposed CSV carries no prose.
//!
//! The tables are precompiled (not converted from Markdown) because they need HTML
//! that Markdown cannot express: the `.matrix-scroll` wrapper, sticky headers,
//! per-cell `diverge`/`reject`/`crash` classes, and the payload `title` tooltip. Two
//! reference rows frame the user's question — **RFC** (the *standard*, hand-authored
//! where 6265 is prescriptive) and **consensus** (the *expectation*, the modal
//! outcome of the real-world parsers). kekse's deviations are surfaced, not hidden.
//!
//! The [`Table`] model is the single source of truth for both
//! the Markdown and HTML views of a table, so the two cannot drift apart.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt::Write as _;

use maud::{html, Markup, PreEscaped};
use pulldown_cmark::{html as cmark_html, Options, Parser};
use tera::{Context, Tera};

use crate::differential::result::ParseOutcome;
use crate::differential::table::{self, Cell, CellKind, CellText, Row, Table};
use crate::scenario::Scenario;
use crate::taxonomy::Direction;

/// The prose template: all the document's English text, plus the `{{ … }}` markers
/// for the fragments. Embedded at compile time (the path resolves relative to this
/// source file, so the generator has no runtime working-directory dependency).
const TEMPLATE: &str = include_str!("cookie_matrix.md.tera");

/// The HTML-only "download the same matrix" paragraph: trusted static markup linking
/// the report to its sibling `.md`/`.csv` (published flat beside it on GitHub Pages).
/// Inserted via the `{{ downloads }}` marker — empty in the Markdown render.
const DOWNLOADS_HTML: &str = "<p class=\"downloads\">Download the same matrix: \
     <a href=\"COOKIE_MATRIX.md\">Markdown</a> · \
     <a href=\"COOKIE_MATRIX.csv\">CSV</a></p>";

/// The HTML report's stylesheet, inlined so the page is fully self-contained (no
/// CDN/fonts — it must render offline and as a static GitHub Pages file). The wide
/// matrix tables scroll horizontally inside `.matrix-scroll`; their header row and
/// first column stick so a tool/test stays identifiable across ~60 columns. The
/// dense table rules are scoped under `.matrix-scroll` so the class-less legend table
/// (converted from the template's Markdown pipe table) keeps a plain, readable grid.
const CSS: &str = r#":root{--fg:#1f2933;--muted:#9aa5b1;--line:#e1e6eb;--head:#1f2933;--head-fg:#f5f7fa;--rowhead:#f4f6f9;--ref:#eaf1f8;--diverge:#fff3bf;--accent:#1565c0}
*{box-sizing:border-box}
body{margin:0;padding:0 0 4rem;font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;color:var(--fg);background:#fff}
h1,h2,p,ul{padding-left:1.5rem;padding-right:1.5rem}
h1{margin:1.6rem 0 .3rem;font-size:1.55rem}
h2{margin:2.2rem 0 .6rem;font-size:1.2rem}
p{margin:.55rem 0;color:#3e4c59}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.85em}
table:not(.matrix-scroll table){margin:.6rem 1.5rem 1.2rem;border-collapse:collapse;font-size:13px}
table:not(.matrix-scroll table) th,table:not(.matrix-scroll table) td{border:1px solid var(--line);padding:.3rem .55rem;text-align:left;vertical-align:top}
table:not(.matrix-scroll table) td:last-child{white-space:normal}
.matrix-scroll{overflow-x:auto;margin:1.3rem 0;border-top:1px solid var(--line);border-bottom:1px solid var(--line)}
.matrix-scroll table{border-collapse:separate;border-spacing:0;font-size:12.5px}
.matrix-scroll th,.matrix-scroll td{border-right:1px solid var(--line);border-bottom:1px solid var(--line);padding:.32rem .55rem;text-align:left;white-space:nowrap;vertical-align:top}
.matrix-scroll thead th{position:sticky;top:0;z-index:2;background:var(--head);color:var(--head-fg);font-weight:600}
.matrix-scroll th:first-child,.matrix-scroll td:first-child{position:sticky;left:0;z-index:1;background:var(--rowhead);font-weight:600;border-right:2px solid var(--line)}
.matrix-scroll thead th:first-child{z-index:3}
.matrix-scroll tr.ref td,.matrix-scroll tr.ref th:first-child{background:var(--ref)}
.matrix-scroll td.diverge{background:var(--diverge);font-weight:700}
.matrix-scroll td.reject{color:#c92a2a}
.matrix-scroll td.muted{color:var(--muted)}
.matrix-scroll td.crash{color:#c92a2a;font-weight:700;text-decoration:underline}"#;

/// One matrix column: a parser, with one [`ParseOutcome`] per scenario (aligned
/// to the scenario order).
pub struct Column {
    pub lang: String,
    pub dep: String,
    pub cells: Vec<ParseOutcome>,
}

impl Column {
    fn header(&self) -> String {
        format!("{}/{}", self.lang, self.dep)
    }

    /// kekse is the *subject* under test, excluded from the consensus vote so
    /// we can judge it against the rest of the field.
    fn is_subject(&self) -> bool {
        self.dep.starts_with("kekse")
    }
}

/// The RFC-6265-prescribed verdict, given only where the standard is clear.
/// `None` renders as `—` (the RFC is silent or implementation-defined here).
fn rfc_verdict(id: &str) -> Option<&'static str> {
    match id {
        "delim-semicolon" => Some("`;` splits → 2 pairs"),
        "empty-value" => Some("empty value is valid"),
        "dup-name" => Some("all duplicates kept"),
        "no-equals" | "empty-name" => Some("skip bad pair, keep rest"),
        "extra-equals" => Some("split on first `=`"),
        "markup-no-equals" | "equals-bare" | "equals-double" => Some("skip bad pair, keep rest"),
        "array-name"
        | "assoc-name"
        | "markup-name"
        | "nul-empty-name"
        | "resp-array-name"
        | "resp-quoted-pair-flag" => Some("non-token name skipped"),
        "bracket-value" | "resp-bracket-value" => Some("`[` `]` are cookie-octets"),
        "json-value" | "resp-json-value" => Some("DQUOTE is not a cookie-octet"),
        "attr-unknown" | "attr-bad-maxage" | "attr-garbage-samesite" => {
            Some("keep cookie, ignore attr (§5.2)")
        }
        "attr-duplicate" => Some("keep cookie, last wins (§5.2)"),
        "resp-crlf" => Some("CR/LF must not be smuggled"),
        "resp-ws-surrounding" => Some("trim leading/trailing WSP"),
        "resp-empty-value" => Some("empty value is valid"),
        "resp-ctl-nul" | "resp-ctl-other" => Some("CTL is not a cookie-octet"),
        "resp-quote-interior" => Some("DQUOTE is not a cookie-octet"),
        "resp-non-ascii" => Some("non-ASCII is not a cookie-octet"),
        _ => None,
    }
}

/// The modal outcome across the non-subject, applicable columns — the empirical
/// "expectation". `None` if every real-world parser was n/a or skipped.
fn consensus(row: usize, columns: &[Column]) -> Option<String> {
    let mut votes: BTreeMap<String, usize> = BTreeMap::new();
    for column in columns {
        if column.is_subject() {
            continue;
        }
        match &column.cells[row] {
            // n/a and SKIP never vote; nor do the proxy *forwarding* verdicts —
            // they measure transit fidelity, a different axis than parsing, so
            // they must not sway (or read as) the parse consensus. A crash (an
            // in-process panic or a sidecar that died) is not a parse opinion
            // either — it is excluded so `☠️` never groups into the consensus.
            ParseOutcome::NotApplicable
            | ParseOutcome::Skipped
            | ParseOutcome::Panicked { .. }
            | ParseOutcome::Crashed { .. }
            | ParseOutcome::ForwardedVerbatim
            | ParseOutcome::ForwardedAltered { .. }
            | ParseOutcome::ForwardedRejected => continue,
            other => *votes.entry(other.consensus_key()).or_default() += 1,
        }
    }
    votes.into_iter().max_by_key(|(_, n)| *n).map(|(k, _)| k)
}

/// Escape control bytes to visible text: `\r` `\n` `\t` `\0`, else `\xNN`. Keeps
/// a cell single-line and readable in both the table and the CSV.
pub(super) fn escape_controls(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\r' => out.push_str("\\r"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\0' => out.push_str("\\0"),
            c if c.is_control() => {
                let _ = write!(out, "\\x{:02x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

/// Escape a cell for a markdown table: control bytes plus the `|` column
/// delimiter. (The CSV path uses [`escape_controls`] and lets the `csv` writer
/// handle quoting.)
pub(super) fn esc(cell: &str) -> String {
    escape_controls(cell).replace('|', "\\|")
}

/// Wrap a cell in a markdown code span (the `—` placeholder stays bare), so an
/// escape like `\r` or a literal `"` reads unambiguously as monospace. A literal
/// backtick in the value would break a single-backtick span, so the fence is made
/// one backtick longer than the longest run inside, with a space pad when the
/// value abuts the fence — CommonMark's rule for backtick-bearing code spans. A
/// backtick-free value (every cell today) keeps the plain single-backtick span.
pub(super) fn code(s: &str) -> String {
    if s == "—" {
        return s.to_string();
    }
    let longest_run = s.split(|c| c != '`').map(str::len).max().unwrap_or(0);
    if longest_run == 0 {
        return format!("`{s}`");
    }
    let fence = "`".repeat(longest_run + 1);
    let pad = if s.starts_with('`') || s.ends_with('`') {
        " "
    } else {
        ""
    };
    format!("{fence}{pad}{s}{pad}{fence}")
}

/// Escape raw wire bytes for display: printable ASCII verbatim, the common
/// controls as `\r`/`\n`/`\t`/`\0`, every other byte (incl. non-UTF-8) as `\xNN`.
fn escape_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for &b in bytes {
        match b {
            b'\r' => out.push_str("\\r"),
            b'\n' => out.push_str("\\n"),
            b'\t' => out.push_str("\\t"),
            0 => out.push_str("\\0"),
            0x20..=0x7e => out.push(b as char),
            _ => {
                let _ = write!(out, "\\x{b:02x}");
            }
        }
    }
    out
}

/// The exact wire a scenario sends, escaped for display in full (no truncation): a
/// valid-UTF-8 wire keeps its characters (with control escapes), a non-UTF-8 wire is
/// shown byte-by-byte. Used verbatim for the HTML payload tooltip.
fn payload_full(scenario: &Scenario) -> String {
    match scenario.recipe.render_str() {
        Some(wire) => escape_controls(&wire),
        None => escape_bytes(&scenario.recipe.render()),
    }
}

/// [`payload_full`] capped to a single readable cell: a long (scale) payload
/// collapses to a head plus a length marker. The HTML report carries the full text
/// in a `title` tooltip (see [`build_section`]).
fn payload_of(scenario: &Scenario) -> String {
    let full = payload_full(scenario);
    let count = full.chars().count();
    if count > 36 {
        let head: String = full.chars().take(28).collect();
        format!("{head}…<{count}>")
    } else {
        full
    }
}

/// Whether a cell's outcome diverges from the real-world `consensus` — true only
/// for a *parse* outcome (not `n/a`/`SKIP`/`☠️`/a forwarding verdict) that rendered
/// differently from the modal consensus of its column. Drives the **bold** mark
/// in Markdown and the `.diverge` highlight in HTML. Shared so both renderers
/// judge divergence identically. A crash is deliberately not divergence-eligible:
/// it already stands out as `☠️`/red and never reads as a "parse disagreement".
fn diverges(outcome: &ParseOutcome, consensus: Option<&String>) -> bool {
    matches!(
        outcome,
        ParseOutcome::Cookies { .. }
            | ParseOutcome::Rejected { .. }
            | ParseOutcome::SetCookie { .. }
            | ParseOutcome::SetCookieRejected { .. }
    ) && consensus.is_some_and(|c| *c != outcome.consensus_key())
}

/// The CSS-class / Markdown-bold *kind* for a data cell: divergence (the key signal)
/// wins; otherwise a muted kind for the non-parse outcomes (`n/a`/`SKIP`), a tint for
/// rejections, and an emphatic crash kind for `☠️` (panic / sidecar death).
fn cell_kind(outcome: &ParseOutcome, consensus: Option<&String>) -> CellKind {
    if diverges(outcome, consensus) {
        return CellKind::Diverge;
    }
    match outcome {
        ParseOutcome::NotApplicable | ParseOutcome::Skipped => CellKind::Muted,
        ParseOutcome::Rejected { .. }
        | ParseOutcome::SetCookieRejected { .. }
        | ParseOutcome::ForwardedRejected => CellKind::Reject,
        ParseOutcome::Panicked { .. } | ParseOutcome::Crashed { .. } => CellKind::Crash,
        _ => CellKind::Plain,
    }
}

// ── section split ──────────────────────────────────────────────────────────────
// The matrix is split by `Direction` into two tables — the request-`Cookie:`
// parsers and the response-`Set-Cookie:` parsers — so each reads as a dense table
// instead of one wide grid where every request-only tool is `n/a` down the
// Set-Cookie columns (and vice-versa). `Expires`/date scenarios are response-only,
// so they live where they matter: in the Set-Cookie section.

/// Split scenario row *indices* by direction, preserving order. Indices (not the
/// scenarios) because a section still addresses `Column.cells`, which is aligned
/// to the full scenario order.
fn partition_rows(scenarios: &[Scenario]) -> (Vec<usize>, Vec<usize>) {
    let mut request = Vec::new();
    let mut response = Vec::new();
    for (i, s) in scenarios.iter().enumerate() {
        match s.direction {
            Direction::Request => request.push(i),
            Direction::Response => response.push(i),
        }
    }
    (request, response)
}

/// Whether a column belongs in a section: it must *do something* on at least one
/// of the section's rows — parse, reject, forward, or crash. A column that is only
/// `n/a` (a parser that does not handle this direction) or only `SKIP` (a tool
/// absent from this run) is dropped, so each table lists just the parsers that
/// engage that direction. In CI every tool is present, so `n/a` cleanly marks the
/// non-directions and the split is exact.
fn column_participates(column: &Column, rows: &[usize]) -> bool {
    rows.iter().any(|&r| {
        !matches!(
            column.cells[r],
            ParseOutcome::NotApplicable | ParseOutcome::Skipped
        )
    })
}

/// Build one direction's table model: a column per test in the section, the
/// payload/RFC/consensus reference rows, then one row per participating tool. `cons`
/// is indexed by the global scenario row, so it is shared verbatim across sections.
fn build_section(
    rows: &[usize],
    scenarios: &[Scenario],
    columns: &[&Column],
    cons: &[Option<String>],
) -> Table {
    let col_headers = rows
        .iter()
        .map(|&r| CellText::Code(scenarios[r].id.to_string()))
        .collect();

    let mut body = Vec::with_capacity(columns.len() + 3);

    // The cell shows the length-capped payload; the full wire rides in the HTML
    // `title` tooltip (`maud` attribute-escapes it, so a `"` cannot escape).
    body.push(Row {
        header: "payload".to_string(),
        is_ref: true,
        cells: rows
            .iter()
            .map(|&r| Cell::payload(payload_of(&scenarios[r]), payload_full(&scenarios[r])))
            .collect(),
    });
    body.push(Row {
        header: "RFC (standard)".to_string(),
        is_ref: true,
        cells: rows
            .iter()
            .map(|&r| Cell::inline(rfc_verdict(scenarios[r].id).unwrap_or("—").to_string()))
            .collect(),
    });
    body.push(Row {
        header: "consensus".to_string(),
        is_ref: true,
        cells: rows
            .iter()
            .map(|&r| {
                Cell::code(
                    cons[r].clone().unwrap_or_else(|| "—".to_string()),
                    CellKind::Plain,
                )
            })
            .collect(),
    });

    for column in columns {
        body.push(Row {
            header: column.header(),
            is_ref: false,
            cells: rows
                .iter()
                .map(|&r| {
                    let outcome = &column.cells[r];
                    Cell::code(outcome.cell(), cell_kind(outcome, cons[r].as_ref()))
                })
                .collect(),
        });
    }

    Table {
        corner: "tool".to_string(),
        col_headers,
        rows: body,
    }
}

// ── attribute fidelity ──────────────────────────────────────────────────────────
// The `resp-all-attrs` scenario sets every Set-Cookie attribute; this surfaces,
// explicitly, which parsers preserve vs silently drop each one — the information loss
// the matrix is meant to document, beyond the per-cell divergence highlight.

/// The scenario whose wire sets all six attributes (see `scenario.rs`).
const FIDELITY_SCENARIO: &str = "resp-all-attrs";
/// Those six attributes, in render order.
const FIDELITY_ATTRS: [&str; 6] = [
    "HttpOnly", "Secure", "SameSite", "Path", "Domain", "Max-Age",
];

/// Per parser, which of the six attributes it surfaced from `resp-all-attrs` (`true` =
/// kept, `false` = dropped). Only columns that parsed a cookie there are listed — one
/// that rejected it (e.g. a client jar on a domain mismatch) is omitted, not scored 0.
fn attribute_fidelity(scenarios: &[Scenario], columns: &[Column]) -> Vec<(String, [bool; 6])> {
    let Some(row) = scenarios.iter().position(|s| s.id == FIDELITY_SCENARIO) else {
        return Vec::new();
    };
    columns
        .iter()
        .filter_map(|c| match &c.cells[row] {
            ParseOutcome::SetCookie { set_cookie: sc } => Some((
                c.header(),
                [
                    sc.http_only,
                    sc.secure,
                    sc.same_site.is_some(),
                    sc.path.is_some(),
                    sc.domain.is_some(),
                    sc.max_age.is_some(),
                ],
            )),
            _ => None,
        })
        .collect()
}

/// Build the attribute-fidelity grid model (a `parser × attribute` table of ✓/✗; a
/// dropped attribute is a `Reject` cell, tinted in HTML).
fn build_fidelity(rows: &[(String, [bool; 6])]) -> Table {
    let col_headers = FIDELITY_ATTRS
        .iter()
        .map(|a| CellText::Plain(a.to_string()))
        .collect();
    let body = rows
        .iter()
        .map(|(parser, present)| Row {
            header: parser.clone(),
            is_ref: false,
            cells: present
                .iter()
                .map(|&p| {
                    if p {
                        Cell::plain("✓".to_string(), CellKind::Plain)
                    } else {
                        Cell::plain("✗".to_string(), CellKind::Reject)
                    }
                })
                .collect(),
        })
        .collect();
    Table {
        corner: "parser".to_string(),
        col_headers,
        rows: body,
    }
}

// ── divergences worth knowing ────────────────────────────────────────────────────
// The scenarios where kekse (the subject) renders a different outcome than the
// real-world consensus — surfaced as a prose list, with each subject's mode and the
// RFC note where the standard is prescriptive.

/// One "kekse diverges here" entry: the scenario, the consensus it differs from, and
/// each subject column's mode (`dep`, rendered `cell`). `cell` strings are raw — the
/// renderers escape them (Markdown `esc`, HTML via `maud`/`escape_controls`).
struct Divergence<'a> {
    id: &'a str,
    description: &'a str,
    consensus: String,
    modes: Vec<(String, String)>,
    rfc: Option<&'static str>,
}

/// Collect the scenarios where a subject (kekse) column diverges from consensus.
fn divergences<'a>(
    scenarios: &'a [Scenario],
    columns: &[Column],
    cons: &[Option<String>],
) -> Vec<Divergence<'a>> {
    let subjects: Vec<&Column> = columns.iter().filter(|c| c.is_subject()).collect();
    let mut out = Vec::new();
    for (row, scenario) in scenarios.iter().enumerate() {
        let Some(con) = cons[row].clone() else {
            continue;
        };
        if !subjects.iter().any(|c| c.cells[row].consensus_key() != con) {
            continue;
        }
        out.push(Divergence {
            id: scenario.id,
            description: scenario.description,
            consensus: con,
            modes: subjects
                .iter()
                .map(|c| (c.dep.clone(), c.cells[row].cell()))
                .collect(),
            rfc: rfc_verdict(scenario.id),
        });
    }
    out
}

/// The divergences list as Markdown bullets (no heading — that lives in the template).
fn md_divergences(divs: &[Divergence]) -> String {
    divs.iter()
        .map(|d| {
            let modes = d
                .modes
                .iter()
                .map(|(dep, cell)| format!("{} → `{}`", dep, esc(cell)))
                .collect::<Vec<_>>()
                .join(", ");
            let mut line = format!(
                "- **`{}`** — {}. Real-world consensus `{}`; {}.",
                d.id,
                d.description,
                esc(&d.consensus),
                modes
            );
            if let Some(rfc) = d.rfc {
                let _ = write!(line, " RFC: {rfc}.");
            }
            line
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// One subject's modes as the HTML run `dep → <code>cell</code>, …` (cell entity- and
/// control-escaped). Built as a string so the maud `<li>` can splice it `PreEscaped`.
fn modes_html(modes: &[(String, String)]) -> String {
    modes
        .iter()
        .map(|(dep, cell)| format!("{} → <code>{}</code>", h(dep), h(&escape_controls(cell))))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The divergences list as an HTML `<ul>` (no heading). Untrusted strings are
/// `maud`-escaped; the trusted RFC verdict is inline Markdown rendered to HTML.
fn html_divergences(divs: &[Divergence]) -> Markup {
    html! {
        ul {
            @for d in divs {
                li {
                    strong { code { (d.id) } }
                    " — "
                    (d.description)
                    ". Real-world consensus "
                    code { (escape_controls(&d.consensus)) }
                    "; "
                    (PreEscaped(modes_html(&d.modes)))
                    "."
                    @if let Some(rfc) = d.rfc {
                        " RFC: "
                        (PreEscaped(md_inline(rfc)))
                        "."
                    }
                }
            }
        }
    }
}

/// The "tested against" version banners as Markdown bullets (code-spanned, so a `|`
/// or control byte never introduces markup).
fn md_versions(versions: &[String]) -> String {
    versions
        .iter()
        .map(|line| format!("- {}", code(&esc(line))))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The "tested against" version banners as an HTML `<ul>` (each `maud`-escaped).
fn html_versions(versions: &[String]) -> Markup {
    html! {
        ul {
            @for line in versions {
                li { code { (line) } }
            }
        }
    }
}

// ── HTML escaping & inline Markdown ────────────────────────────────────────────────
// The report routes every string that originates from a parsed (corrupted) cookie
// through `maud` (in `table.rs`) or `h` here, so it lands as inert text. `md_inline`
// renders the *authored* inline Markdown of the RFC verdicts (trusted input only).

/// HTML-escape untrusted text for *element content*: encodes `&`, `<`, `>` so the
/// value renders as text and can never start a tag or an entity.
fn h(s: &str) -> Cow<'_, str> {
    html_escape::encode_text(s)
}

/// Render a span of *authored* inline Markdown to safe HTML: backtick code spans
/// become `<code>…</code>`, `**bold**`/`*italic*` become `<strong>`/`<em>`, and
/// every literal run is `h`-escaped. Not a general Markdown engine — it covers
/// only the inline features the RFC-verdict cells use, on trusted input.
pub(super) fn md_inline(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 16);
    // Backticks delimit code spans: split on them, the odd segments are the spans.
    for (i, seg) in s.split('`').enumerate() {
        if i % 2 == 1 {
            let _ = write!(out, "<code>{}</code>", h(seg));
        } else {
            out.push_str(&md_emphasis(seg));
        }
    }
    out
}

/// `h`-escape a non-code run, then turn `**bold**`/`*italic*` into `<strong>`/
/// `<em>` (bold first, so its `**` is consumed before single-`*` italics).
fn md_emphasis(text: &str) -> String {
    let escaped = h(text);
    let bold = toggle_wrap(&escaped, "**", "<strong>", "</strong>");
    toggle_wrap(&bold, "*", "<em>", "</em>")
}

/// Replace each occurrence of `marker`, alternately, with `open` then `close` —
/// turning balanced marker pairs into open/close tags. Authored prose only, so
/// markers are assumed balanced and non-nested.
fn toggle_wrap(s: &str, marker: &str, open: &str, close: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut opened = false;
    let mut rest = s;
    while let Some(pos) = rest.find(marker) {
        out.push_str(&rest[..pos]);
        out.push_str(if opened { close } else { open });
        opened = !opened;
        rest = &rest[pos + marker.len()..];
    }
    out.push_str(rest);
    out
}

// ── template plumbing ──────────────────────────────────────────────────────────────

/// Convert authored Markdown to HTML (GFM tables on, for the legend). The `{{ … }}`
/// markers are plain text to the parser, so they survive verbatim for the Tera pass.
fn md_to_html(md: &str) -> String {
    let mut opts = Options::empty();
    opts.insert(Options::ENABLE_TABLES);
    let parser = Parser::new_ext(md, opts);
    let mut out = String::with_capacity(md.len() * 3 / 2);
    cmark_html::push_html(&mut out, parser);
    out
}

/// Unwrap converter-wrapped marker paragraphs: a line that is exactly
/// `<p>{{ marker }}</p>` becomes the bare `{{ marker }}`, so the block fragment Tera
/// then substitutes (a `<div>`/`<table>`/`<ul>`) is not illegally nested inside a
/// `<p>`. Only whole-line, single-marker paragraphs are unwrapped; a marker embedded
/// in prose is left intact.
fn unwrap_marker_paragraphs(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    for line in html.lines() {
        let inner = line
            .trim()
            .strip_prefix("<p>")
            .and_then(|s| s.strip_suffix("</p>"))
            .map(str::trim);
        match inner {
            Some(body)
                if body.starts_with("{{")
                    && body.ends_with("}}")
                    && body[2..body.len() - 2].find("}}").is_none() =>
            {
                out.push_str(body);
            }
            _ => out.push_str(line),
        }
        out.push('\n');
    }
    out
}

/// The document title — the text of the template's first `# ` heading — for the HTML
/// `<head><title>`. Title text lives only in the template; the scaffold reads it back.
fn template_title(template: &str) -> &str {
    template
        .lines()
        .find_map(|l| l.strip_prefix("# "))
        .unwrap_or("keksbruch")
        .trim()
}

// ── renderers ────────────────────────────────────────────────────────────────────

/// Render the whole matrix as a Markdown document: the prose template with the
/// Markdown fragments spliced in. `versions` is the "tested against" footer — the
/// exact comparator versions of this run.
pub fn render(scenarios: &[Scenario], columns: &[Column], versions: &[String]) -> String {
    // The consensus per test, computed once over every column (n/a, SKIP and crashes
    // already abstain), so each section's filtered columns vote identically.
    let cons: Vec<Option<String>> = (0..scenarios.len())
        .map(|row| consensus(row, columns))
        .collect();
    let (req_rows, resp_rows) = partition_rows(scenarios);

    let section_md = |rows: &[usize]| {
        let cols: Vec<&Column> = columns
            .iter()
            .filter(|c| column_participates(c, rows))
            .collect();
        table::to_markdown(&build_section(rows, scenarios, &cols, &cons))
    };

    let mut ctx = Context::new();
    ctx.insert("downloads", ""); // no download links in the Markdown view
    ctx.insert("request_table", &section_md(&req_rows));
    ctx.insert("response_table", &section_md(&resp_rows));
    ctx.insert(
        "fidelity_table",
        &table::to_markdown(&build_fidelity(&attribute_fidelity(scenarios, columns))),
    );
    ctx.insert(
        "divergences",
        &md_divergences(&divergences(scenarios, columns, &cons)),
    );
    ctx.insert("versions", &md_versions(versions));

    Tera::one_off(TEMPLATE, &ctx, false).expect("matrix Markdown template renders")
}

/// Render the whole matrix as a self-contained HTML report — the GitHub Pages view.
/// The template's prose is converted to HTML, the precompiled (entity-encoded) HTML
/// fragments are spliced in, and the body is wrapped in the inlined-CSS scaffold.
pub fn render_html(scenarios: &[Scenario], columns: &[Column], versions: &[String]) -> String {
    let cons: Vec<Option<String>> = (0..scenarios.len())
        .map(|row| consensus(row, columns))
        .collect();
    let (req_rows, resp_rows) = partition_rows(scenarios);

    let section_html = |rows: &[usize]| {
        let cols: Vec<&Column> = columns
            .iter()
            .filter(|c| column_participates(c, rows))
            .collect();
        table::to_html(&build_section(rows, scenarios, &cols, &cons)).into_string()
    };

    // 1. Convert the template's prose (markers intact) to HTML, then unwrap any
    //    `<p>{{ marker }}</p>` so a block fragment is not nested inside a `<p>`.
    let converted = unwrap_marker_paragraphs(&md_to_html(TEMPLATE));

    // 2. Splice the maud-rendered HTML fragments into the converted HTML.
    let mut ctx = Context::new();
    ctx.insert("downloads", DOWNLOADS_HTML);
    ctx.insert("request_table", &section_html(&req_rows));
    ctx.insert("response_table", &section_html(&resp_rows));
    ctx.insert(
        "fidelity_table",
        &table::to_html(&build_fidelity(&attribute_fidelity(scenarios, columns))).into_string(),
    );
    ctx.insert(
        "divergences",
        &html_divergences(&divergences(scenarios, columns, &cons)).into_string(),
    );
    ctx.insert("versions", &html_versions(versions).into_string());
    let body = Tera::one_off(&converted, &ctx, false).expect("matrix HTML template renders");

    // 3. Wrap in the self-contained scaffold (doctype/head/CSS/body) — kept in Rust;
    //    `<title>` is the template's first heading, so title text stays in the template.
    let mut out = String::with_capacity(body.len() + CSS.len() + 512);
    out.push_str(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n",
    );
    let _ = writeln!(out, "<title>{}</title>", h(template_title(TEMPLATE)));
    out.push_str("<style>\n");
    out.push_str(CSS);
    out.push_str("\n</style>\n</head>\n<body>\n");
    out.push_str(&body);
    out.push_str("</body>\n</html>\n");
    out
}

/// Render the matrix **transposed** — one row per tool/library, one column per
/// test — as CSV, the orientation that makes a single tool's behaviour scan as a
/// row. Two blocks, split by direction (a `== … ==` banner separates them); within
/// each, `payload`/`RFC`/`consensus` lead as reference rows. The `csv` writer owns
/// quoting and escaping; cells only need control bytes made visible first. The
/// blocks have different widths, so the writer is `flexible`.
pub fn render_csv(scenarios: &[Scenario], columns: &[Column]) -> String {
    let cons: Vec<Option<String>> = (0..scenarios.len())
        .map(|row| consensus(row, columns))
        .collect();
    let (req_rows, resp_rows) = partition_rows(scenarios);

    let mut writer = csv::WriterBuilder::new()
        .flexible(true)
        .from_writer(Vec::new());
    {
        let mut record = |label: &str, cells: Vec<String>| {
            let mut row = Vec::with_capacity(cells.len() + 1);
            row.push(label.to_string());
            row.extend(cells);
            writer
                .write_record(&row)
                .expect("writing CSV to an in-memory buffer cannot fail");
        };
        for (label, rows) in [
            ("Request Cookie:", &req_rows),
            ("Response Set-Cookie:", &resp_rows),
        ] {
            let cols: Vec<&Column> = columns
                .iter()
                .filter(|c| column_participates(c, rows))
                .collect();
            record(&format!("== {label} parsers =="), Vec::new());
            record(
                "tool",
                rows.iter().map(|&r| scenarios[r].id.to_string()).collect(),
            );
            record(
                "payload",
                rows.iter().map(|&r| payload_of(&scenarios[r])).collect(),
            );
            record(
                "RFC (standard)",
                rows.iter()
                    .map(|&r| rfc_verdict(scenarios[r].id).unwrap_or("—").to_string())
                    .collect(),
            );
            record(
                "consensus",
                rows.iter()
                    .map(|&r| escape_controls(&cons[r].clone().unwrap_or_else(|| "—".to_string())))
                    .collect(),
            );
            for column in &cols {
                record(
                    &column.header(),
                    rows.iter()
                        .map(|&r| escape_controls(&column.cells[r].cell()))
                        .collect(),
                );
            }
            record("", Vec::new());
        }
    }
    let bytes = writer
        .into_inner()
        .expect("flushing the in-memory CSV buffer cannot fail");
    String::from_utf8(bytes).expect("CSV output is valid UTF-8")
}
