//! The opt-in differential matrix (behind the `differential` feature; run by
//! the dedicated matrix workflow, not the CI gate): feed every payload to
//! cookie parsers across languages and tabulate where they diverge — to see
//! whether kekse is *standard* (RFC) and *expectation* (real-world) compliant.

pub mod calibration;
pub mod matrix;
pub mod result;
pub mod rust_comparators;
pub mod sidecar;
pub mod table;

use std::path::Path;

use crate::probe::jar_probes;
use crate::scenario::scenarios;
use matrix::Column;
use result::ParseOutcome;
use rust_comparators::{jar_comparators, rust_comparators};

/// Run the whole matrix: every scenario through the in-process Rust comparators
/// and the language sidecars, every jar probe through the jar-capable ones;
/// grade the calibration laws over the columns; render everything to Markdown,
/// CSV, a self-contained HTML report, and a machine-readable JSON document;
/// print the Markdown; and write `COOKIE_MATRIX.{md,csv,html,json}` next to the
/// crate (the HTML report is the GitHub Pages view; the JSON is the source of
/// truth for later stats/probing). Returns the Markdown and the calibration
/// verdict — the caller decides whether a violation fails the run.
pub fn run_matrix() -> (String, calibration::Calibration) {
    let scenarios = scenarios();
    let probes = jar_probes();
    let mut columns = in_process_columns(&scenarios, &probes);

    // Language sidecars (graceful SKIP if an interpreter or dependency is absent).
    let (sidecar_cols, sidecar_versions) = sidecar::sidecar_columns(&scenarios, &probes);
    columns.extend(sidecar_cols);

    // Record exactly what was tested against: the Rust comparator versions from
    // the lockfile, plus the runtimes/deps each sidecar reported.
    let mut versions = vec![rust_versions()];
    versions.extend(sidecar_versions);

    let calibration = calibration::calibrate(&scenarios, &columns);
    let markdown = matrix::render(&scenarios, &probes, &columns, &versions, &calibration);
    println!("{markdown}");
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    if let Err(e) = std::fs::write(dir.join("COOKIE_MATRIX.md"), &markdown) {
        eprintln!("could not write COOKIE_MATRIX.md: {e}");
    }
    // The transposed CSV companion (tool rows × test columns) for analysis.
    let csv = matrix::render_csv(&scenarios, &probes, &columns);
    if let Err(e) = std::fs::write(dir.join("COOKIE_MATRIX.csv"), &csv) {
        eprintln!("could not write COOKIE_MATRIX.csv: {e}");
    }
    // The self-contained HTML report — the well-readable, publishable view (the
    // matrix's GitHub Pages page). Not printed; the Markdown is the stdout view.
    let html = matrix::render_html(&scenarios, &probes, &columns, &versions, &calibration);
    if let Err(e) = std::fs::write(dir.join("COOKIE_MATRIX.html"), &html) {
        eprintln!("could not write COOKIE_MATRIX.html: {e}");
    }
    // The machine-readable JSON — scenario → target → full ParseOutcome, plus
    // per-scenario metadata (direction, wire, RFC verdict, consensus). The source
    // of truth for later statistics and proxy-probing.
    let json = matrix::render_json(&scenarios, &probes, &columns, &versions, &calibration);
    if let Err(e) = std::fs::write(dir.join("COOKIE_MATRIX.json"), &json) {
        eprintln!("could not write COOKIE_MATRIX.json: {e}");
    }
    (markdown, calibration)
}

/// The in-process columns: every Rust wire comparator run over the scenarios, then
/// the jar comparators over the probes — filling the probe cells of an existing
/// column (the cookie_store jar is also a wire comparator) or adding a probe-only
/// column (the rfc_6265 reference, which the wire tables then drop as all-n/a).
/// Shared by [`run_matrix`] and the hermetic JSON unit test.
pub(super) fn in_process_columns(
    scenarios: &[crate::scenario::Scenario],
    probes: &[crate::probe::JarProbe],
) -> Vec<Column> {
    let mut columns: Vec<Column> = Vec::new();

    // A &str parser cannot see a non-UTF-8 wire, so those payloads are n/a for the
    // Rust side (the http layer rejects them).
    for comparator in rust_comparators() {
        let (lang, dep) = comparator.id();
        let cells = scenarios
            .iter()
            .map(|s| match s.recipe.render_str() {
                Some(wire) => comparator.run(&wire, s.direction),
                None => ParseOutcome::NotApplicable,
            })
            .collect();
        columns.push(Column {
            lang: lang.to_string(),
            dep: dep.to_string(),
            cells,
            probe_cells: vec![ParseOutcome::NotApplicable; probes.len()],
        });
    }

    for comparator in jar_comparators() {
        let (lang, dep) = comparator.id();
        let probe_cells: Vec<ParseOutcome> = probes
            .iter()
            .map(|p| comparator.run(p.set_cookie, p.origin_url, p.request_url))
            .collect();
        match columns.iter_mut().find(|c| c.lang == lang && c.dep == dep) {
            Some(column) => column.probe_cells = probe_cells,
            None => columns.push(Column {
                lang: lang.to_string(),
                dep: dep.to_string(),
                cells: vec![ParseOutcome::NotApplicable; scenarios.len()],
                probe_cells,
            }),
        }
    }
    columns
}

/// The Rust comparator versions, read from the committed workspace `Cargo.lock`
/// (the matrix only ever runs in-workspace, so the lockfile is always present).
fn rust_versions() -> String {
    let lock = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.lock");
    let text = std::fs::read_to_string(lock).unwrap_or_default();
    let v = |name: &str| lock_version(&text, name).unwrap_or_else(|| "?".to_string());
    format!(
        "Rust — kekse (this tree), cookie {}, biscotti {}, axum-extra {}",
        v("cookie"),
        v("biscotti"),
        v("axum-extra")
    )
}

/// Pull a package's version out of a `Cargo.lock`: the `version = "…"` line that
/// follows its `name = "<name>"` line.
fn lock_version(lock: &str, name: &str) -> Option<String> {
    let needle = format!("name = \"{name}\"");
    let block = &lock[lock.find(&needle)?..];
    let line = block
        .lines()
        .find(|l| l.trim_start().starts_with("version = "))?;
    line.split('"').nth(1).map(str::to_string)
}
