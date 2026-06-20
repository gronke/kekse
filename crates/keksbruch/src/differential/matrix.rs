//! Render the differential matrix to markdown — **one row per tool, one column
//! per test** — a wide table plus a prose "divergences worth knowing" section.
//! Two reference rows frame the user's question — **RFC** (the *standard*,
//! hand-authored where 6265 is prescriptive) and **consensus** (the
//! *expectation*, the modal outcome of the real-world parsers). kekse's
//! deviations are surfaced, not hidden.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::differential::result::ParseOutcome;
use crate::scenario::Scenario;

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
            // they must not sway (or read as) the parse consensus.
            ParseOutcome::NotApplicable
            | ParseOutcome::Skipped
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
fn escape_controls(s: &str) -> String {
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
fn esc(cell: &str) -> String {
    escape_controls(cell).replace('|', "\\|")
}

/// Wrap a cell in a markdown code span (the `—` placeholder stays bare), so an
/// escape like `\r` or a literal `"` reads unambiguously as monospace.
fn code(s: &str) -> String {
    if s == "—" {
        s.to_string()
    } else {
        format!("`{s}`")
    }
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

/// The exact wire a scenario sends, escaped for display and length-capped: a
/// valid-UTF-8 wire keeps its characters (with control escapes), a non-UTF-8 wire
/// is shown byte-by-byte. Long (scale) payloads collapse to a head plus a length.
fn payload_of(scenario: &Scenario) -> String {
    let full = match scenario.recipe.render_str() {
        Some(wire) => escape_controls(&wire),
        None => escape_bytes(&scenario.recipe.render()),
    };
    let count = full.chars().count();
    if count > 36 {
        let head: String = full.chars().take(28).collect();
        format!("{head}…<{count}>")
    } else {
        full
    }
}

/// Render the whole matrix as a markdown document. `versions` is the
/// "tested against" footer — the exact comparator versions of this run.
pub fn render(scenarios: &[Scenario], columns: &[Column], versions: &[String]) -> String {
    let mut out = String::new();
    out.push_str("# keksbruch — parser divergence matrix\n\n");
    out.push_str(
        "How cookie parsers across languages handle the same difficult and malformed wire — surfacing where implementations diverge. \
         Generated by `cargo test -p keksbruch --features differential -- --ignored`.\n\n",
    );
    out.push_str(
        "Legend: `[n=v, …]` parsed pairs · `∅` parsed to nothing · `❌` whole header/cookie \
         rejected (fail-hard) · `n/a` direction not handled · `SKIP` parser unavailable · \
         `PANIC` adapter panicked · `≡`/`≠` proxy forwarded the Cookie verbatim / altered. \
         **Bold** = differs from the real-world *consensus*. \
         kekse is the subject under test, excluded from the consensus vote.\n\n",
    );
    out.push_str(
        "The `cookie` crate runs in percent-decoding (`*_encoded`) mode so its values are \
         comparable to kekse's. biscotti is request-only (no Set-Cookie parser → `n/a`) and \
         exposes no general iterator, so its accepted pairs are enumerated by name. PHP's \
         `$_COOKIE` is parsed natively behind its built-in server (`php -S`), so it too is \
         request-only (no Set-Cookie parser → `n/a`) and shows PHP's own quirks — value \
         urldecoding, cookie-name mangling, and transport-layer rejection of CR/LF/NUL. Go \
         (`net/http`, since 1.23) and .NET (`Microsoft.Net.Http.Headers`) parse both \
         directions; a toolchain absent from the run shows `SKIP` (the CI matrix job has them all).\n\n",
    );
    out.push_str(
        "nginx is exercised behind a real openresty server, replayed over a socket like PHP, and \
         is request-only. Its `$cookie_<name>` column is nginx's *native* lookup: nginx exposes \
         cookies only by name, so the values and membership are nginx's, but the order is the \
         header's and duplicates collapse to nginx's first-wins. `lua-resty-cookie` is an OpenResty \
         Lua library that parses the raw header itself (pairs shown sorted — it returns an unordered \
         table). `nginx/proxy` is a different axis: it reports whether a `proxy_pass` forwarded the \
         Cookie verbatim (`≡`), altered it (`≠`), or refused it (`❌`), and is excluded from the \
         consensus vote.\n\n",
    );
    out.push_str(
        "Rows are tools, columns are tests. The `payload` row is the exact wire sent — \
         non-displayable bytes shown as `\\0` `\\r` `\\n` `\\xNN`, in code. The same matrix is \
         also written beside this file as `COOKIE_MATRIX.csv` for spreadsheets and diffing.\n\n",
    );

    // ── header: one column per test ──────────────────────────────────────────
    let mut header = String::from("| tool |");
    let mut rule = String::from("| --- |");
    for scenario in scenarios {
        let _ = write!(header, " `{}` |", scenario.id);
        rule.push_str(" --- |");
    }
    out.push_str(&header);
    out.push('\n');
    out.push_str(&rule);
    out.push('\n');

    // The consensus per test, computed once — the vote each tool row is judged
    // against.
    let cons: Vec<Option<String>> = (0..scenarios.len())
        .map(|row| consensus(row, columns))
        .collect();

    // ── reference rows: payload, RFC, consensus ───────────────────────────────
    out.push_str("| **payload** |");
    for scenario in scenarios {
        let _ = write!(out, " {} |", code(&payload_of(scenario)));
    }
    out.push('\n');
    out.push_str("| **RFC (standard)** |");
    for scenario in scenarios {
        let _ = write!(out, " {} |", esc(rfc_verdict(scenario.id).unwrap_or("—")));
    }
    out.push('\n');
    out.push_str("| **consensus** |");
    for con in &cons {
        let display = con.clone().unwrap_or_else(|| "—".to_string());
        let _ = write!(out, " {} |", code(&esc(&display)));
    }
    out.push('\n');

    // ── one row per tool/library ───────────────────────────────────────────────
    for column in columns {
        let _ = write!(out, "| {} |", column.header());
        for (row, outcome) in column.cells.iter().enumerate() {
            let cell = code(&esc(&outcome.cell()));
            let diverges = matches!(
                outcome,
                ParseOutcome::Cookies { .. }
                    | ParseOutcome::Rejected { .. }
                    | ParseOutcome::SetCookie { .. }
                    | ParseOutcome::SetCookieRejected { .. }
                    | ParseOutcome::Panicked { .. }
            ) && cons[row]
                .as_ref()
                .is_some_and(|c| *c != outcome.consensus_key());
            if diverges {
                let _ = write!(out, " **{cell}** |");
            } else {
                let _ = write!(out, " {cell} |");
            }
        }
        out.push('\n');
    }

    // ── prose: divergences worth knowing ──────────────────────────────────────
    out.push_str("\n## Divergences worth knowing\n\n");
    for (row, scenario) in scenarios.iter().enumerate() {
        let con = match consensus(row, columns) {
            Some(c) => c,
            None => continue,
        };
        let subjects: Vec<&Column> = columns.iter().filter(|c| c.is_subject()).collect();
        let kekse_diverges = subjects.iter().any(|c| c.cells[row].consensus_key() != con);
        let rfc_note = rfc_verdict(scenario.id);
        if kekse_diverges {
            let modes: Vec<String> = subjects
                .iter()
                .map(|c| format!("{} → `{}`", c.dep, esc(&c.cells[row].cell())))
                .collect();
            let _ = write!(
                out,
                "- **`{}`** — {}. Real-world consensus `{}`; {}.",
                scenario.id,
                scenario.description,
                esc(&con),
                modes.join(", ")
            );
            if let Some(rfc) = rfc_note {
                let _ = write!(out, " RFC: {rfc}.");
            }
            out.push('\n');
        }
    }

    // ── tested against (exact versions of this run) ───────────────────────────
    out.push_str("\n## Tested against\n\n");
    for line in versions {
        let _ = writeln!(out, "- {line}");
    }

    out
}

/// Render the matrix **transposed** — one row per tool/library, one column per
/// test — as CSV, the orientation that makes a single tool's behaviour scan as a
/// row. `payload`/`RFC`/`consensus` lead as reference rows. The `csv` writer owns
/// quoting and escaping; cells only need control bytes made visible first.
pub fn render_csv(scenarios: &[Scenario], columns: &[Column]) -> String {
    let mut writer = csv::Writer::from_writer(Vec::new());
    {
        let mut record = |label: &str, cells: Vec<String>| {
            let mut row = Vec::with_capacity(cells.len() + 1);
            row.push(label.to_string());
            row.extend(cells);
            writer
                .write_record(&row)
                .expect("writing CSV to an in-memory buffer cannot fail");
        };
        record("tool", scenarios.iter().map(|s| s.id.to_string()).collect());
        record("payload", scenarios.iter().map(payload_of).collect());
        record(
            "RFC (standard)",
            scenarios
                .iter()
                .map(|s| rfc_verdict(s.id).unwrap_or("—").to_string())
                .collect(),
        );
        record(
            "consensus",
            (0..scenarios.len())
                .map(|i| escape_controls(&consensus(i, columns).unwrap_or_else(|| "—".to_string())))
                .collect(),
        );
        for column in columns {
            record(
                &column.header(),
                column
                    .cells
                    .iter()
                    .map(|cell| escape_controls(&cell.cell()))
                    .collect(),
            );
        }
    }
    let bytes = writer
        .into_inner()
        .expect("flushing the in-memory CSV buffer cannot fail");
    String::from_utf8(bytes).expect("CSV output is valid UTF-8")
}
