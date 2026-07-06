//! Render the differential matrix from **one prose template plus precompiled
//! fragments**. The document's English text lives in `cookie_matrix.md.tera`
//! (authored Markdown with `{{ … }}` markers); the dynamic parts — the two wide
//! matrix tables, the attribute-fidelity grid, and the scenario-index / versions lists —
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

use base64::prelude::{BASE64_STANDARD, Engine as _};
use maud::{Markup, PreEscaped, html};
use pulldown_cmark::{Options, Parser, html as cmark_html};
use serde::Serialize;
use tera::{Context, Tera};

use crate::differential::result::ParseOutcome;
use crate::differential::table::{self, Cell, CellKind, CellText, Row, Table};
use crate::probe::JarProbe;
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
     <a href=\"COOKIE_MATRIX.csv\">CSV</a> · \
     <a href=\"COOKIE_MATRIX.json\">JSON</a></p>";

/// The HTML report's stylesheet, inlined so the page is fully self-contained (no
/// CDN/fonts — it must render offline and as a static GitHub Pages file). The wide
/// matrix tables scroll horizontally inside `.matrix-scroll`; their header row and
/// first column stick so a tool/test stays identifiable across ~60 columns. The
/// dense table rules are scoped under `.matrix-scroll` so the class-less legend table
/// (converted from the template's Markdown pipe table) keeps a plain, readable grid.
const CSS: &str = r#":root{--fg:#1f2933;--muted:#9aa5b1;--line:#e1e6eb;--head:#1f2933;--head-fg:#f5f7fa;--rowhead:#f4f6f9;--ref:#eaf1f8;--diverge:#fff3bf;--accent:#1565c0}
*{box-sizing:border-box}
body{margin:0;padding:0 0 4rem;font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;color:var(--fg);background:#fff}
h1,h2,h3,p,ul{padding-left:1.5rem;padding-right:1.5rem}
h1{margin:1.6rem 0 .3rem;font-size:1.55rem}
h2{margin:2.2rem 0 .6rem;font-size:1.2rem}
h3{margin:1.6rem 0 .4rem;font-size:1.05rem}
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
.matrix-scroll td.crash{color:#c92a2a;font-weight:700;text-decoration:underline}
.tt-btn{cursor:pointer}
.tt [role=tooltip]{position:fixed;left:50%;bottom:1rem;transform:translateX(-50%);z-index:10;max-width:min(92vw,64rem);visibility:hidden;opacity:0;transition:visibility 0s .35s,opacity .12s .35s;background:#1f2933;color:#f5f7fa;border:1px solid #3e4c59;border-radius:.4rem;box-shadow:0 .4rem 1.4rem rgba(0,0,0,.35);padding:.5rem .7rem}
.tt [role=tooltip] pre{margin:0;max-height:60vh;overflow:auto;white-space:pre;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;line-height:1.45;color:#f5f7fa}
.tt-btn:hover ~ [role=tooltip],.tt-btn:focus ~ [role=tooltip],.tt [role=tooltip]:hover,.tt [role=tooltip]:focus-within{visibility:visible;opacity:1;transition-delay:0s}"#;

/// One matrix column: a parser, with one [`ParseOutcome`] per scenario (aligned
/// to the scenario order) and one per jar probe (aligned to the probe order).
/// A wire-only parser carries all-`NotApplicable` `probe_cells`, and vice versa.
pub struct Column {
    pub lang: String,
    pub dep: String,
    pub cells: Vec<ParseOutcome>,
    pub probe_cells: Vec<ParseOutcome>,
}

impl Column {
    fn header(&self) -> String {
        format!("{}/{}", self.lang, self.dep)
    }

    /// The *subjects* under test — kekse, and the rfc_6265 reference on the jar
    /// probes — excluded from the consensus vote so each is judged against the
    /// rest of the field.
    fn is_subject(&self) -> bool {
        self.dep.starts_with("kekse") || self.dep.starts_with("rfc_6265")
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
        "date-2digit-year-69" => Some("§5.1.1: 69 → 2069"),
        "date-2digit-year-70" => Some("§5.1.1: 70 → 1970"),
        "date-year-1601-boundary" => Some("§5.1.1: year ≥ 1601 is valid"),
        "date-hour-out-of-range" => Some("§5.1.1: hour > 23 fails"),
        "date-1-digit-day" => Some("§5.1.1: day is 1*2DIGIT"),
        "date-month-case" => Some("§5.1.1: month is case-insensitive"),
        "date-month-overlong" => Some("§5.1.1: month = first 3 letters"),
        "date-year-trailing-alpha" => Some("§5.1.1: non-digit year tail ignored"),
        "date-5-digit-year" => Some("§5.1.1: year is 2*4DIGIT"),
        "date-missing-year" => Some("§5.1.1: all four fields required"),
        "date-empty" => Some("no date → ignore Expires (§5.2.1)"),
        "date-zone-offset" => Some("§5.1.1: zone tokens ignored"),
        "date-tab-delims" => Some("§5.1.1: HTAB is a delimiter"),
        "date-first-token-wins" => Some("§5.1.1: first match binds each field"),
        "jar-host-only-exact" => Some("host-only: the same host attaches (§5.4)"),
        "jar-host-only-subdomain" => Some("host-only never flows to subdomains (§5.4)"),
        "jar-domain-exact" | "jar-domain-parent" => {
            Some("a Domain cookie flows to matching hosts (§5.1.3)")
        }
        "jar-domain-superset" => Some("the origin must domain-match Domain (§5.3 step 6)"),
        "jar-domain-label-boundary" => Some("a suffix counts only at a label boundary (§5.1.3)"),
        "jar-domain-case" => Some("Domain is canonicalized lower-case (§5.1.2)"),
        "jar-domain-leading-dot" => Some("a leading dot is stripped (§5.2.3)"),
        "jar-domain-ip" => Some("an IP host matches only by identity (§5.1.3)"),
        "jar-domain-supercookie" => {
            Some("rejecting a public-suffix Domain is *optional* (§5.3 step 5)")
        }
        "jar-path-prefix-boundary" => Some("a path prefix matches at a `/` boundary (§5.1.4)"),
        "jar-path-non-boundary" => Some("a prefix without a boundary never matches (§5.1.4)"),
        "jar-path-trailing-slash" => Some("`/a/` does not match its parent `/a` (§5.1.4)"),
        "jar-path-default-sibling" | "jar-path-default-outside" => {
            Some("no Path → the origin's default-path (§5.3 step 7)")
        }
        "jar-path-not-absolute" => Some("a non-`/` Path is ignored → default-path (§5.2.4)"),
        "jar-secure-on-http" => Some("Secure needs a secure channel (§5.4)"),
        "resp-crlf" => Some("CR/LF must not be smuggled"),
        "resp-ws-surrounding" => Some("trim leading/trailing WSP"),
        "resp-empty-value" => Some("empty value is valid"),
        "resp-ctl-nul" | "resp-ctl-other" => Some("CTL is not a cookie-octet"),
        "resp-quote-interior" => Some("DQUOTE is not a cookie-octet"),
        "resp-non-ascii" => Some("non-ASCII is not a cookie-octet"),
        _ => None,
    }
}

/// The modal outcome across a row's non-subject, applicable cells — the empirical
/// "expectation". `None` if every real-world parser was n/a or skipped. Shared by
/// the wire rows ([`consensus`]) and the jar-probe rows ([`probe_consensus`]), so
/// both vote by exactly the same abstention rules.
fn consensus_of<'a>(cells: impl Iterator<Item = (&'a ParseOutcome, bool)>) -> Option<String> {
    let mut votes: BTreeMap<String, usize> = BTreeMap::new();
    for (outcome, is_subject) in cells {
        if is_subject {
            continue;
        }
        match outcome {
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

/// The consensus for one wire-scenario row.
fn consensus(row: usize, columns: &[Column]) -> Option<String> {
    consensus_of(columns.iter().map(|c| (&c.cells[row], c.is_subject())))
}

/// The consensus for one jar-probe row.
fn probe_consensus(row: usize, columns: &[Column]) -> Option<String> {
    consensus_of(
        columns
            .iter()
            .map(|c| (&c.probe_cells[row], c.is_subject())),
    )
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

/// Cap an already-escaped payload to a single readable cell: a long (scale) value
/// collapses to a head plus a length marker. The HTML report carries the full text
/// in a `title` tooltip (see [`build_section`]).
fn cap_payload(full: &str) -> String {
    let count = full.chars().count();
    if count > 36 {
        let head: String = full.chars().take(28).collect();
        format!("{head}…<{count}>")
    } else {
        full.to_string()
    }
}

/// [`payload_full`], capped via [`cap_payload`].
fn payload_of(scenario: &Scenario) -> String {
    cap_payload(&payload_full(scenario))
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

/// [`column_participates`] for the jar-probe table: a column joins it only if it
/// answered at least one probe — codec-only parsers (all-`n/a` probe cells) and
/// absent tools drop out, so the table lists just the jars.
fn probe_column_participates(column: &Column) -> bool {
    column
        .probe_cells
        .iter()
        .any(|c| !matches!(c, ParseOutcome::NotApplicable | ParseOutcome::Skipped))
}

/// A document-unique, deterministic element id for a cell's tooltip — the trigger's
/// `aria-describedby` target. Built from the column identity and scenario id (both
/// unique), slugged to id-safe characters.
fn tooltip_id(column: &Column, scenario_id: &str) -> String {
    format!("tt-{}-{}-{}", column.lang, column.dep, scenario_id)
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect()
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
                    // On ❌ (reject) and ☠️ (crash) cells, carry the error / crash
                    // reason plus any captured stdout/stderr into a role="tooltip"
                    // panel, keyed by a document-unique id.
                    Cell::code(outcome.cell(), cell_kind(outcome, cons[r].as_ref()))
                        .with_detail(tooltip_id(column, scenarios[r].id), outcome.diagnostics())
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

/// Build the jar-probe table model: a column per probe; `Set-Cookie`/`origin`/`request`
/// reference rows framing the two-input experiment, then the RFC verdict and the
/// cross-jar consensus; then one row per participating jar. `cons` is indexed by
/// probe order (see [`probe_consensus`]).
fn build_probe_section(probes: &[JarProbe], columns: &[&Column], cons: &[Option<String>]) -> Table {
    let col_headers = probes
        .iter()
        .map(|p| CellText::Code(p.id.to_string()))
        .collect();

    let mut body = Vec::with_capacity(columns.len() + 5);
    body.push(Row {
        header: "Set-Cookie".to_string(),
        is_ref: true,
        cells: probes
            .iter()
            .map(|p| {
                let full = escape_controls(p.set_cookie);
                Cell::payload(cap_payload(&full), full)
            })
            .collect(),
    });
    body.push(Row {
        header: "origin".to_string(),
        is_ref: true,
        cells: probes
            .iter()
            .map(|p| Cell::code(p.origin_url.to_string(), CellKind::Plain))
            .collect(),
    });
    body.push(Row {
        header: "request".to_string(),
        is_ref: true,
        cells: probes
            .iter()
            .map(|p| Cell::code(p.request_url.to_string(), CellKind::Plain))
            .collect(),
    });
    body.push(Row {
        header: "RFC (standard)".to_string(),
        is_ref: true,
        cells: probes
            .iter()
            .map(|p| Cell::inline(rfc_verdict(p.id).unwrap_or("—").to_string()))
            .collect(),
    });
    body.push(Row {
        header: "consensus".to_string(),
        is_ref: true,
        cells: cons
            .iter()
            .map(|c| {
                Cell::code(
                    c.clone().unwrap_or_else(|| "—".to_string()),
                    CellKind::Plain,
                )
            })
            .collect(),
    });

    for column in columns {
        body.push(Row {
            header: column.header(),
            is_ref: false,
            cells: probes
                .iter()
                .enumerate()
                .map(|(r, p)| {
                    let outcome = &column.probe_cells[r];
                    Cell::code(outcome.cell(), cell_kind(outcome, cons[r].as_ref()))
                        .with_detail(tooltip_id(column, p.id), outcome.diagnostics())
                })
                .collect(),
        });
    }

    Table {
        corner: "jar".to_string(),
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

// ── tested scenarios ───────────────────────────────────────────────────────────────
// The per-direction index of every scenario — the id each matrix column is headed
// by, and what its wire probes. Outcomes stay in the tables above; this is the key.

/// One section's scenario index as Markdown bullets (no heading — that lives in the
/// template).
fn md_scenario_index(rows: &[usize], scenarios: &[Scenario]) -> String {
    rows.iter()
        .map(|&r| {
            format!(
                "- **`{}`** — {}.",
                scenarios[r].id, scenarios[r].description
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// One section's scenario index as an HTML `<ul>` (no heading). Descriptions are
/// authored inline Markdown (backtick spans), rendered via [`md_inline`].
fn html_scenario_index(rows: &[usize], scenarios: &[Scenario]) -> Markup {
    html! {
        ul {
            @for &r in rows {
                li {
                    strong { code { (scenarios[r].id) } }
                    " — "
                    (PreEscaped(md_inline(scenarios[r].description)))
                    "."
                }
            }
        }
    }
}

/// The jar-probe index as Markdown bullets — the probes' analogue of
/// [`md_scenario_index`].
fn md_probe_index(probes: &[JarProbe]) -> String {
    probes
        .iter()
        .map(|p| format!("- **`{}`** — {}.", p.id, p.description))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The jar-probe index as an HTML `<ul>` — the probes' analogue of
/// [`html_scenario_index`].
fn html_probe_index(probes: &[JarProbe]) -> Markup {
    html! {
        ul {
            @for p in probes {
                li {
                    strong { code { (p.id) } }
                    " — "
                    (PreEscaped(md_inline(p.description)))
                    "."
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
pub fn render(
    scenarios: &[Scenario],
    probes: &[JarProbe],
    columns: &[Column],
    versions: &[String],
) -> String {
    // The consensus per test, computed once over every column (n/a, SKIP and crashes
    // already abstain), so each section's filtered columns vote identically.
    let cons: Vec<Option<String>> = (0..scenarios.len())
        .map(|row| consensus(row, columns))
        .collect();
    let probe_cons: Vec<Option<String>> = (0..probes.len())
        .map(|row| probe_consensus(row, columns))
        .collect();
    let (req_rows, resp_rows) = partition_rows(scenarios);

    let section_md = |rows: &[usize]| {
        let cols: Vec<&Column> = columns
            .iter()
            .filter(|c| column_participates(c, rows))
            .collect();
        table::to_markdown(&build_section(rows, scenarios, &cols, &cons))
    };
    let jar_cols: Vec<&Column> = columns
        .iter()
        .filter(|c| probe_column_participates(c))
        .collect();

    let mut ctx = Context::new();
    ctx.insert("downloads", ""); // no download links in the Markdown view
    ctx.insert("request_table", &section_md(&req_rows));
    ctx.insert("response_table", &section_md(&resp_rows));
    ctx.insert(
        "jar_table",
        &table::to_markdown(&build_probe_section(probes, &jar_cols, &probe_cons)),
    );
    ctx.insert(
        "fidelity_table",
        &table::to_markdown(&build_fidelity(&attribute_fidelity(scenarios, columns))),
    );
    ctx.insert(
        "request_scenarios",
        &md_scenario_index(&req_rows, scenarios),
    );
    ctx.insert(
        "response_scenarios",
        &md_scenario_index(&resp_rows, scenarios),
    );
    ctx.insert("jar_scenarios", &md_probe_index(probes));
    ctx.insert("versions", &md_versions(versions));

    Tera::one_off(TEMPLATE, &ctx, false).expect("matrix Markdown template renders")
}

/// Render the whole matrix as a self-contained HTML report — the GitHub Pages view.
/// The template's prose is converted to HTML, the precompiled (entity-encoded) HTML
/// fragments are spliced in, and the body is wrapped in the inlined-CSS scaffold.
pub fn render_html(
    scenarios: &[Scenario],
    probes: &[JarProbe],
    columns: &[Column],
    versions: &[String],
) -> String {
    let cons: Vec<Option<String>> = (0..scenarios.len())
        .map(|row| consensus(row, columns))
        .collect();
    let probe_cons: Vec<Option<String>> = (0..probes.len())
        .map(|row| probe_consensus(row, columns))
        .collect();
    let (req_rows, resp_rows) = partition_rows(scenarios);

    let section_html = |rows: &[usize]| {
        let cols: Vec<&Column> = columns
            .iter()
            .filter(|c| column_participates(c, rows))
            .collect();
        table::to_html(&build_section(rows, scenarios, &cols, &cons)).into_string()
    };
    let jar_cols: Vec<&Column> = columns
        .iter()
        .filter(|c| probe_column_participates(c))
        .collect();

    // 1. Convert the template's prose (markers intact) to HTML, then unwrap any
    //    `<p>{{ marker }}</p>` so a block fragment is not nested inside a `<p>`.
    let converted = unwrap_marker_paragraphs(&md_to_html(TEMPLATE));

    // 2. Splice the maud-rendered HTML fragments into the converted HTML.
    let mut ctx = Context::new();
    ctx.insert("downloads", DOWNLOADS_HTML);
    ctx.insert("request_table", &section_html(&req_rows));
    ctx.insert("response_table", &section_html(&resp_rows));
    ctx.insert(
        "jar_table",
        &table::to_html(&build_probe_section(probes, &jar_cols, &probe_cons)).into_string(),
    );
    ctx.insert(
        "fidelity_table",
        &table::to_html(&build_fidelity(&attribute_fidelity(scenarios, columns))).into_string(),
    );
    ctx.insert(
        "request_scenarios",
        &html_scenario_index(&req_rows, scenarios).into_string(),
    );
    ctx.insert(
        "response_scenarios",
        &html_scenario_index(&resp_rows, scenarios).into_string(),
    );
    ctx.insert("jar_scenarios", &html_probe_index(probes).into_string());
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
pub fn render_csv(scenarios: &[Scenario], probes: &[JarProbe], columns: &[Column]) -> String {
    let cons: Vec<Option<String>> = (0..scenarios.len())
        .map(|row| consensus(row, columns))
        .collect();
    let probe_cons: Vec<Option<String>> = (0..probes.len())
        .map(|row| probe_consensus(row, columns))
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

        // The jar-probe block: same transposed orientation, with the two-input
        // experiment (Set-Cookie + origin + request) as reference rows.
        record(
            "== Jar probes (store from origin, attach to request) ==",
            Vec::new(),
        );
        record("jar", probes.iter().map(|p| p.id.to_string()).collect());
        record(
            "Set-Cookie",
            probes
                .iter()
                .map(|p| escape_controls(p.set_cookie))
                .collect(),
        );
        record(
            "origin",
            probes.iter().map(|p| p.origin_url.to_string()).collect(),
        );
        record(
            "request",
            probes.iter().map(|p| p.request_url.to_string()).collect(),
        );
        record(
            "RFC (standard)",
            probes
                .iter()
                .map(|p| rfc_verdict(p.id).unwrap_or("—").to_string())
                .collect(),
        );
        record(
            "consensus",
            probe_cons
                .iter()
                .map(|c| escape_controls(&c.clone().unwrap_or_else(|| "—".to_string())))
                .collect(),
        );
        for column in columns.iter().filter(|c| probe_column_participates(c)) {
            record(
                &column.header(),
                column
                    .probe_cells
                    .iter()
                    .map(|c| escape_controls(&c.cell()))
                    .collect(),
            );
        }
        record("", Vec::new());
    }
    let bytes = writer
        .into_inner()
        .expect("flushing the in-memory CSV buffer cannot fail");
    String::from_utf8(bytes).expect("CSV output is valid UTF-8")
}

/// The whole run as one machine-readable JSON document — the source of truth for
/// later statistics and probing (notably how kekse fares versus the proxy columns).
/// Keyed by scenario id; each entry carries its direction, the wire (a readable
/// lossy view plus exact base64 for faithful replay), the RFC verdict and
/// cross-parser consensus, and a `results` map of every target's full
/// [`ParseOutcome`] — the error / crash reason and captured stdout/stderr ride along
/// verbatim.
pub fn render_json(
    scenarios: &[Scenario],
    probes: &[JarProbe],
    columns: &[Column],
    versions: &[String],
) -> String {
    let mut out = BTreeMap::new();
    for (row, s) in scenarios.iter().enumerate() {
        let bytes = s.recipe.render();
        let results = columns
            .iter()
            .map(|c| (format!("{}/{}", c.lang, c.dep), &c.cells[row]))
            .collect();
        out.insert(
            s.id,
            JsonScenario {
                direction: match s.direction {
                    Direction::Request => "request",
                    Direction::Response => "response",
                },
                wire: String::from_utf8_lossy(&bytes).into_owned(),
                wire_b64: BASE64_STANDARD.encode(&bytes),
                origin_url: None,
                request_url: None,
                rfc: rfc_verdict(s.id),
                consensus: consensus(row, columns),
                results,
            },
        );
    }
    // The jar probes join the same map (ids are disjoint by the `jar-` prefix), with
    // their two extra inputs; the URL fields stay absent on wire scenarios, so those
    // entries serialize byte-identically to a probe-less run.
    for (row, p) in probes.iter().enumerate() {
        let results = columns
            .iter()
            .map(|c| (format!("{}/{}", c.lang, c.dep), &c.probe_cells[row]))
            .collect();
        out.insert(
            p.id,
            JsonScenario {
                direction: "jar",
                wire: p.set_cookie.to_string(),
                wire_b64: BASE64_STANDARD.encode(p.set_cookie.as_bytes()),
                origin_url: Some(p.origin_url),
                request_url: Some(p.request_url),
                rfc: rfc_verdict(p.id),
                consensus: probe_consensus(row, columns),
                results,
            },
        );
    }
    let report = JsonReport {
        meta: JsonMeta { versions },
        scenarios: out,
    };
    let mut json = serde_json::to_string_pretty(&report).expect("matrix JSON serializes");
    json.push('\n');
    json
}

/// The top-level JSON document: run metadata plus the scenario map.
#[derive(Serialize)]
struct JsonReport<'a> {
    meta: JsonMeta<'a>,
    scenarios: BTreeMap<&'a str, JsonScenario<'a>>,
}

#[derive(Serialize)]
struct JsonMeta<'a> {
    /// Exactly what was tested against — the Rust lockfile versions plus each
    /// sidecar's reported runtime/deps.
    versions: &'a [String],
}

/// One scenario's JSON entry: its metadata and one [`ParseOutcome`] per target.
#[derive(Serialize)]
struct JsonScenario<'a> {
    direction: &'static str,
    /// The wire as a lossy UTF-8 string — readable, but a non-UTF-8 payload shows
    /// replacement chars; use `wire_b64` for the exact bytes.
    wire: String,
    /// The exact wire bytes, base64 (standard alphabet), for faithful replay/probing.
    wire_b64: String,
    /// Jar probes only (`direction: "jar"`): the URL the Set-Cookie is stored from.
    /// Absent on wire scenarios, so their entries serialize unchanged.
    #[serde(skip_serializing_if = "Option::is_none")]
    origin_url: Option<&'a str>,
    /// Jar probes only: the URL of the later request the jar attaches cookies to.
    #[serde(skip_serializing_if = "Option::is_none")]
    request_url: Option<&'a str>,
    /// The RFC verdict, or null where 6265 is not prescriptive.
    rfc: Option<&'a str>,
    /// The modal real-world outcome (the cell string), or null when there is none.
    consensus: Option<String>,
    /// `"<lang>/<dep>"` → that target's full outcome.
    results: BTreeMap<String, &'a ParseOutcome>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::jar_probes;
    use crate::scenario::scenarios;

    #[test]
    fn render_json_is_valid_and_self_describing() {
        // Columns from the in-process comparators alone (no sidecars), so this
        // stays a fast, hermetic unit test.
        let scenarios = scenarios();
        let probes = jar_probes();
        let columns = crate::differential::in_process_columns(&scenarios, &probes);
        let versions = vec!["Rust: test".to_string()];

        let json = render_json(&scenarios, &probes, &columns, &versions);
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");

        // Run metadata is present.
        assert!(v["meta"]["versions"].is_array(), "{v}");

        // Every scenario and probe is keyed by id and carries direction + wire + results.
        let objs = v["scenarios"].as_object().expect("scenarios object");
        assert_eq!(objs.len(), scenarios.len() + probes.len());
        let first = scenarios[0].id;
        let entry = &v["scenarios"][first];
        assert!(entry["direction"].is_string(), "{entry}");
        assert!(entry["wire_b64"].is_string(), "{entry}");
        // The kekse (lenient) target reports an outcome for this scenario — and a
        // wire scenario carries no probe URLs (absent, not null).
        assert!(
            entry["results"]["rust/kekse (lenient)"]["outcome"].is_string(),
            "{entry}"
        );
        assert!(entry.get("origin_url").is_none(), "{entry}");

        // A jar probe carries its two inputs and the reference column's outcome.
        let probe_entry = &v["scenarios"][probes[0].id];
        assert_eq!(probe_entry["direction"], "jar", "{probe_entry}");
        assert!(probe_entry["origin_url"].is_string(), "{probe_entry}");
        assert!(probe_entry["request_url"].is_string(), "{probe_entry}");
        assert!(
            probe_entry["results"]["rust/rfc_6265 (reference)"]["outcome"].is_string(),
            "{probe_entry}"
        );
    }
}
