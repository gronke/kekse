//! Calibration: grade kekse's two dials against the observed columns — the
//! generated form of "as strict as we can get, as lenient and reasonable as
//! reality". Two laws over the **response** rows (where accept/reject is a
//! whole-cookie verdict; request rows are per-pair and pinned by Layer A):
//!
//! - **Law A** — a wire kekse-strict parses *clean* is accepted by the
//!   majority of the answering parse columns: strict-clean means universally
//!   sendable, so a majority rejection would make the strict gate a false
//!   promise.
//! - **Law B** — a wire the majority of parse columns accepts, kekse-lenient
//!   accepts too — lenient is calibrated to reality — except the allowlisted
//!   deliberate deviations, each carrying its documented reason.
//!
//! Store-backed columns (the client jars, the browsers, `cookie_store`) are
//! excluded from the vote: their rejections are storage policy against the
//! probe origin, not parse verdicts. Subjects (kekse itself, the reference)
//! never vote either. A violation of either law fails the matrix run.

use serde::Serialize;

use super::matrix::Column;
use super::result::ParseOutcome;
use super::table::{Cell, CellKind, CellText, Row, Table};
use crate::scenario::Scenario;
use crate::taxonomy::Direction;

/// kekse-lenient's deliberate, documented deviations from majority acceptance:
/// wires most parsers accept and kekse refuses on purpose. Every entry is a
/// standing decision — an id here silences the law-B failure but stays visible
/// in the report with its reason.
const LENIENT_DEVIATIONS: &[(&str, &str)] = &[
    // ── injection bytes in values: the crate's core security refusal ──
    ("resp-crlf", INJECTION_REASON),
    ("resp-ctl-nul", INJECTION_REASON),
    ("resp-del-byte", INJECTION_REASON),
    // ── non-token names: kekse's name grammar, stricter than §5.2 on purpose ──
    ("resp-non-ascii-name", TOKEN_REASON),
    ("resp-space-in-name", TOKEN_REASON),
    ("resp-array-name", TOKEN_REASON),
    ("resp-quoted-pair-flag", TOKEN_REASON),
    // ── DQUOTE-bearing values: the cookie-octet alphabet ──
    ("resp-json-value", QUOTE_REASON),
    ("resp-quote-interior", QUOTE_REASON),
    (
        "resp-quoted-attr-text",
        "§5.2 splits before any unquoting, leaving a bare `\"abc` value the \
         octet rule refuses; quote-spanning parsers swallow the attribute into \
         the value instead (with the raw `;` re-emission hazard that carries)",
    ),
    (
        "resp-non-ascii",
        "a raw non-ASCII byte is outside the cookie-octet alphabet; \
         percent-encoding is the lossless carrier kekse insists on",
    ),
];

const INJECTION_REASON: &str = "a raw CR/LF, NUL, or other control byte in a value is the \
     header-injection / log-poison vector kekse refuses in every mode — the permissive \
     majority keeps it, and re-emission then splits or poisons the carrying header";
const TOKEN_REASON: &str = "kekse requires an RFC 7230 token as the cookie-name (deliberately \
     stricter than §5.2's anything-before-`=`): a non-token name has no wire form kekse's own \
     writer could emit, so the pair is refused as unusable";
const QUOTE_REASON: &str = "a bare DQUOTE is outside the cookie-octet alphabet in both \
     gradings; quote-tolerant parsers keep it and diverge on where the value ends";

/// One row where a calibration law fired (or would have, but is allowlisted).
#[derive(Serialize, Debug)]
pub struct Finding {
    /// The scenario id (a matrix column key).
    pub id: String,
    /// Answering parse columns that accepted the wire.
    pub accepting: Vec<String>,
    /// Answering parse columns that rejected it.
    pub rejecting: Vec<String>,
    /// The allowlist reason, when this deviation is deliberate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// The calibration verdict for one matrix run.
#[derive(Serialize, Debug, Default)]
pub struct Calibration {
    /// Law A violations: kekse-strict parsed the wire clean, the majority rejected it.
    pub strict_clean_majority_rejects: Vec<Finding>,
    /// Law B violations: the majority accepted, kekse-lenient rejected, not allowlisted.
    pub lenient_rejects_majority_accepts: Vec<Finding>,
    /// Law B deviations that are deliberate — informational, with their reasons.
    pub allowlisted_deviations: Vec<Finding>,
}

impl Calibration {
    /// Whether both laws hold (allowlisted deviations do not count against it).
    #[must_use]
    pub fn is_conforming(&self) -> bool {
        self.strict_clean_majority_rejects.is_empty()
            && self.lenient_rejects_majority_accepts.is_empty()
    }
}

/// Whether a column reports *stored* state rather than a parse verdict — its
/// rejections are policy against the probe origin (domain match, secure
/// channel), so it never votes on parse acceptance.
fn store_backed(column: &Column) -> bool {
    column.lang == "client" || column.lang == "browser" || column.dep == "cookie_store"
}

/// A response cell's vote: `Some(true)` accepted, `Some(false)` rejected,
/// `None` when the column did not answer (skip, n/a, crash, forwarding).
fn vote(outcome: &ParseOutcome) -> Option<bool> {
    match outcome {
        ParseOutcome::SetCookie { .. } => Some(true),
        ParseOutcome::SetCookieRejected { .. } => Some(false),
        _ => None,
    }
}

/// Grade the run: both laws over every response row.
pub fn calibrate(scenarios: &[Scenario], columns: &[Column]) -> Calibration {
    let mut calibration = Calibration::default();
    let strict = columns.iter().find(|c| c.dep == "kekse (strict)");
    let lenient = columns.iter().find(|c| c.dep == "kekse (lenient)");
    let (Some(strict), Some(lenient)) = (strict, lenient) else {
        return calibration;
    };

    for (row, scenario) in scenarios.iter().enumerate() {
        if scenario.direction != Direction::Response {
            continue;
        }
        let mut accepting = Vec::new();
        let mut rejecting = Vec::new();
        for column in columns {
            if column.is_subject() || store_backed(column) {
                continue;
            }
            match vote(&column.cells[row]) {
                Some(true) => accepting.push(column.header()),
                Some(false) => rejecting.push(column.header()),
                None => {}
            }
        }
        if accepting.is_empty() && rejecting.is_empty() {
            continue; // nobody answered (e.g. a sidecar-less local run on an odd row)
        }

        // Law A: strict-clean ⇒ no majority rejection.
        let strict_clean = matches!(
            &strict.cells[row],
            ParseOutcome::SetCookie { issues, .. } if issues.is_empty()
        );
        if strict_clean && rejecting.len() > accepting.len() {
            calibration.strict_clean_majority_rejects.push(Finding {
                id: scenario.id.to_string(),
                accepting: accepting.clone(),
                rejecting: rejecting.clone(),
                reason: None,
            });
        }

        // Law B: majority acceptance ⇒ lenient acceptance, unless deliberate.
        let lenient_rejects = matches!(&lenient.cells[row], ParseOutcome::SetCookieRejected { .. });
        if lenient_rejects && accepting.len() > rejecting.len() {
            let reason = LENIENT_DEVIATIONS
                .iter()
                .find(|(id, _)| *id == scenario.id)
                .map(|(_, reason)| (*reason).to_string());
            let finding = Finding {
                id: scenario.id.to_string(),
                accepting,
                rejecting,
                reason,
            };
            if finding.reason.is_some() {
                calibration.allowlisted_deviations.push(finding);
            } else {
                calibration.lenient_rejects_majority_accepts.push(finding);
            }
        }
    }
    calibration
}

/// The verdict sentence both output flavours lead with.
fn verdict(calibration: &Calibration) -> String {
    if calibration.is_conforming() {
        format!(
            "Both laws hold over this run's answering columns{}.",
            match calibration.allowlisted_deviations.len() {
                0 => String::new(),
                n => format!(" ({n} deliberate lenient deviation(s) listed below)"),
            }
        )
    } else {
        format!(
            "CALIBRATION VIOLATED: {} law-A and {} law-B finding(s) — kekse's dial and \
             observed reality disagree without a documented reason.",
            calibration.strict_clean_majority_rejects.len(),
            calibration.lenient_rejects_majority_accepts.len(),
        )
    }
}

/// The findings as a table model (rows exist only when there is something to show).
fn build_table(calibration: &Calibration) -> Option<Table> {
    let mut rows = Vec::new();
    let mut push = |label: &str, findings: &[Finding], kind: CellKind| {
        for f in findings {
            rows.push(Row {
                header: f.id.clone(),
                is_ref: false,
                cells: vec![
                    Cell::plain(label.to_string(), kind),
                    Cell::plain(
                        format!("{} ({})", f.accepting.len(), f.accepting.join(", ")),
                        CellKind::Plain,
                    ),
                    Cell::plain(
                        format!("{} ({})", f.rejecting.len(), f.rejecting.join(", ")),
                        CellKind::Plain,
                    ),
                    Cell::plain(
                        f.reason.clone().unwrap_or_else(|| "—".to_string()),
                        CellKind::Plain,
                    ),
                ],
            });
        }
    };
    push(
        "law A violated",
        &calibration.strict_clean_majority_rejects,
        CellKind::Reject,
    );
    push(
        "law B violated",
        &calibration.lenient_rejects_majority_accepts,
        CellKind::Reject,
    );
    push(
        "deliberate deviation",
        &calibration.allowlisted_deviations,
        CellKind::Plain,
    );
    (!rows.is_empty()).then(|| Table {
        corner: "scenario".to_string(),
        col_headers: ["verdict", "accepting", "rejecting", "reason"]
            .into_iter()
            .map(|h| CellText::Plain(h.to_string()))
            .collect(),
        rows,
    })
}

/// The Markdown fragment for the `{{ calibration }}` marker.
pub fn to_markdown(calibration: &Calibration) -> String {
    match build_table(calibration) {
        Some(table) => format!(
            "{}\n\n{}",
            verdict(calibration),
            super::table::to_markdown(&table)
        ),
        None => verdict(calibration),
    }
}

/// The HTML fragment for the `{{ calibration }}` marker.
pub fn to_html(calibration: &Calibration) -> String {
    let lead = maud::html! { p { (verdict(calibration)) } }.into_string();
    match build_table(calibration) {
        Some(table) => format!("{lead}\n{}", super::table::to_html(&table).into_string()),
        None => lead,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::differential::result::SetCookieView;

    fn column(dep: &str, cell: ParseOutcome) -> Column {
        Column {
            lang: "x".to_string(),
            dep: dep.to_string(),
            cells: vec![cell],
            probe_cells: Vec::new(),
        }
    }

    fn accepted(clean: bool) -> ParseOutcome {
        ParseOutcome::SetCookie {
            set_cookie: SetCookieView {
                name: "SID".into(),
                value: "x".into(),
                http_only: false,
                secure: false,
                partitioned: None,
                same_site: None,
                path: None,
                domain: None,
                max_age: None,
                expires: None,
            },
            issues: if clean {
                Vec::new()
            } else {
                vec!["issue".into()]
            },
        }
    }

    fn rejected() -> ParseOutcome {
        ParseOutcome::SetCookieRejected { error: "no".into() }
    }

    fn one_response_scenario() -> Vec<Scenario> {
        crate::scenario::scenarios()
            .into_iter()
            .filter(|s| s.direction == Direction::Response)
            .take(1)
            .collect()
    }

    #[test]
    fn law_a_fires_on_a_strict_clean_majority_rejection() {
        let scenarios = one_response_scenario();
        let columns = vec![
            column("kekse (strict)", accepted(true)),
            column("kekse (lenient)", accepted(true)),
            column("a", rejected()),
            column("b", rejected()),
            column("c", accepted(true)),
        ];
        let calibration = calibrate(&scenarios, &columns);
        assert_eq!(calibration.strict_clean_majority_rejects.len(), 1);
        assert!(!calibration.is_conforming());
    }

    #[test]
    fn law_b_fires_only_without_an_allowlist_reason() {
        let scenarios = one_response_scenario();
        let columns = vec![
            column("kekse (strict)", rejected()),
            column("kekse (lenient)", rejected()),
            column("a", accepted(true)),
            column("b", accepted(true)),
            column("c", rejected()),
        ];
        let calibration = calibrate(&scenarios, &columns);
        assert_eq!(calibration.lenient_rejects_majority_accepts.len(), 1);
        assert!(!calibration.is_conforming());
    }

    #[test]
    fn subjects_and_store_backed_columns_never_vote() {
        let scenarios = one_response_scenario();
        let mut store = column("cookie_store", rejected());
        store.lang = "rust".to_string();
        let mut client = column("curl", rejected());
        client.lang = "client".to_string();
        let columns = vec![
            column("kekse (strict)", accepted(true)),
            column("kekse (lenient)", accepted(true)),
            column("kekse (fail-hard)", rejected()),
            store,
            client,
            column("a", accepted(true)),
        ];
        // The only voter accepts; every rejection above is a non-voter.
        let calibration = calibrate(&scenarios, &columns);
        assert!(calibration.is_conforming(), "{calibration:#?}");
    }

    #[test]
    fn a_dirty_strict_accept_is_not_law_a_material() {
        let scenarios = one_response_scenario();
        let columns = vec![
            column("kekse (strict)", accepted(false)), // witnessed → not "clean"
            column("kekse (lenient)", accepted(false)),
            column("a", rejected()),
            column("b", rejected()),
        ];
        let calibration = calibrate(&scenarios, &columns);
        assert!(calibration.is_conforming(), "{calibration:#?}");
    }
}
