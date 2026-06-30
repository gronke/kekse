//! A small intermediate **table model**, rendered to both Markdown and HTML, so the
//! matrix's two table views are built from one source of truth (no drift between a
//! hand-written Markdown loop and a hand-written HTML loop) and the HTML view is
//! assembled by [`maud`] — which entity-encodes every interpolated value *by
//! construction*. That inverts the old foot-gun: where the string-concat renderer
//! had to remember to escape each untrusted (corrupted-cookie) cell, here a value is
//! escaped unless one deliberately opts out via [`PreEscaped`] (used only for the
//! *trusted*, authored inline Markdown of the RFC-verdict cells).
//!
//! [`matrix`](super::matrix) builds a [`Table`] from the run data and the Markdown
//! renderer reuses its `esc`/`code` helpers, so the Markdown bytes are identical to
//! the previous renderer's; only the HTML assembly changed.

use maud::{html, Markup, PreEscaped};

use super::matrix::{code, esc, escape_controls, md_inline};

/// The visual kind of a data cell — the divergence/rejection/etc. signal. Drives the
/// Markdown **bold** mark and the HTML CSS class (the old `cell_class` outputs).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CellKind {
    Plain,
    Diverge,
    Reject,
    Muted,
    Crash,
}

impl CellKind {
    /// The HTML CSS class for a cell of this kind, or `None` for no class attribute.
    fn class(self) -> Option<&'static str> {
        match self {
            CellKind::Plain => None,
            CellKind::Diverge => Some("diverge"),
            CellKind::Reject => Some("reject"),
            CellKind::Muted => Some("muted"),
            CellKind::Crash => Some("crash"),
        }
    }
}

/// How a cell's text renders into each format.
pub enum CellText {
    /// Untrusted parser output: control bytes made visible, then a Markdown code span
    /// (`code(esc(_))`) / an entity-encoded `<code>` (HTML). Used by the tool and
    /// consensus cells.
    Code(String),
    /// Trusted *authored* inline Markdown (the RFC-verdict cells): emitted verbatim
    /// (pipe-escaped) in Markdown, run through `md_inline` in HTML. Not code-wrapped.
    Inline(String),
    /// Short trusted text (the ✓/✗ fidelity marks): no code span.
    Plain(String),
    /// The payload cell: a length-capped display plus the full wire carried in an HTML
    /// `title` tooltip. Both are already control-escaped by the caller.
    Payload { capped: String, full: String },
}

impl CellText {
    /// The cell's text as a plain string (the capped form, for the payload) — used for
    /// header cells and HTML, where every variant is just entity-encoded.
    fn raw(&self) -> &str {
        match self {
            CellText::Code(s) | CellText::Inline(s) | CellText::Plain(s) => s,
            CellText::Payload { capped, .. } => capped,
        }
    }
}

/// One table cell: its text and its visual kind.
pub struct Cell {
    pub text: CellText,
    pub kind: CellKind,
}

impl Cell {
    pub fn code(text: String, kind: CellKind) -> Self {
        Cell {
            text: CellText::Code(text),
            kind,
        }
    }
    pub fn inline(text: String) -> Self {
        Cell {
            text: CellText::Inline(text),
            kind: CellKind::Plain,
        }
    }
    pub fn plain(text: String, kind: CellKind) -> Self {
        Cell {
            text: CellText::Plain(text),
            kind,
        }
    }
    pub fn payload(capped: String, full: String) -> Self {
        Cell {
            text: CellText::Payload { capped, full },
            kind: CellKind::Plain,
        }
    }
}

/// One body row: its leading `<th>` label, its data cells, and whether it is one of
/// the payload/RFC/consensus *reference* rows (a tinted band in HTML, **bold** label
/// in Markdown).
pub struct Row {
    pub header: String,
    pub cells: Vec<Cell>,
    pub is_ref: bool,
}

/// A whole matrix table: the top-left corner label (`tool`/`parser`), one column
/// header per test, and the body rows.
pub struct Table {
    pub corner: String,
    pub col_headers: Vec<CellText>,
    pub rows: Vec<Row>,
}

// ── Markdown ─────────────────────────────────────────────────────────────────────

/// A column header in Markdown: scenario ids are code-spanned (`Code`), attribute
/// names are bare (`Plain`).
fn header_md(ch: &CellText) -> String {
    match ch {
        CellText::Code(s) => code(s),
        _ => ch.raw().to_string(),
    }
}

/// One data cell in Markdown — the exact spans the previous renderer emitted.
fn cell_md(cell: &Cell) -> String {
    match &cell.text {
        CellText::Code(s) => {
            let span = code(&esc(s));
            if cell.kind == CellKind::Diverge {
                format!("**{span}**")
            } else {
                span
            }
        }
        CellText::Inline(s) => esc(s),
        CellText::Plain(s) => s.clone(),
        CellText::Payload { capped, .. } => code(capped),
    }
}

/// Render the table as a Markdown pipe table (no heading — that lives in the template).
pub fn to_markdown(t: &Table) -> String {
    let mut lines: Vec<String> = Vec::with_capacity(t.rows.len() + 2);

    let mut header = format!("| {} |", t.corner);
    for ch in &t.col_headers {
        header.push(' ');
        header.push_str(&header_md(ch));
        header.push_str(" |");
    }
    lines.push(header);

    let mut rule = String::from("| --- |");
    for _ in &t.col_headers {
        rule.push_str(" --- |");
    }
    lines.push(rule);

    for row in &t.rows {
        let label = if row.is_ref {
            format!("**{}**", row.header)
        } else {
            row.header.clone()
        };
        let mut line = format!("| {label} |");
        for cell in &row.cells {
            line.push(' ');
            line.push_str(&cell_md(cell));
            line.push_str(" |");
        }
        lines.push(line);
    }

    lines.join("\n")
}

// ── HTML (maud — escape-by-default) ────────────────────────────────────────────────

/// One data cell as HTML. `maud` entity-encodes every `(value)` and `title=(value)`,
/// so an untrusted cell can never become live markup; only the trusted RFC-verdict
/// Markdown is spliced raw via [`PreEscaped`].
fn cell_html(cell: &Cell) -> Markup {
    match &cell.text {
        CellText::Code(s) => html! {
            td class=[cell.kind.class()] { code { (escape_controls(s)) } }
        },
        CellText::Inline(s) => html! {
            td { (PreEscaped(md_inline(s))) }
        },
        CellText::Plain(s) => html! {
            td class=[cell.kind.class()] { (s) }
        },
        CellText::Payload { capped, full } => html! {
            td title=(full) { code { (capped) } }
        },
    }
}

/// Render the table as the self-contained HTML fragment (no heading): the sticky
/// `.matrix-scroll` wrapper plus the `<table>`.
pub fn to_html(t: &Table) -> Markup {
    html! {
        div class="matrix-scroll" {
            table {
                thead {
                    tr {
                        th { (t.corner) }
                        @for ch in &t.col_headers {
                            th { (ch.raw()) }
                        }
                    }
                }
                tbody {
                    @for row in &t.rows {
                        tr class=[row.is_ref.then_some("ref")] {
                            th { (row.header) }
                            @for cell in &row.cells {
                                (cell_html(cell))
                            }
                        }
                    }
                }
            }
        }
    }
}
