//! Language sidecars: small programs (`fixtures/parse_cookies.{py,js}`) that read
//! the corpus as base64-JSONL on stdin and emit a normalized [`ParseOutcome`] per
//! dependency on stdout. base64 keeps the protocol control-char-safe (the wire
//! carries CR/LF/NUL and even raw non-UTF-8). A missing interpreter or dependency
//! degrades to `Skipped` — a dev without python/node still gets the Rust columns.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use base64::prelude::{Engine as _, BASE64_STANDARD};
use serde::{Deserialize, Serialize};

use crate::differential::matrix::Column;
use crate::differential::result::ParseOutcome;
use crate::scenario::Scenario;
use crate::taxonomy::Direction;

#[derive(Serialize)]
struct InputRecord<'a> {
    id: &'a str,
    direction: &'a str,
    wire_b64: String,
}

#[derive(Deserialize)]
struct SelfcheckLine {
    available: BTreeMap<String, bool>,
    #[serde(default)]
    versions: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct ResultLine {
    id: String,
    by_dep: BTreeMap<String, ParseOutcome>,
}

/// One declared sidecar: its language label, interpreter, script, and the
/// dependency columns it reports.
struct SidecarSpec {
    lang: &'static str,
    command: &'static str,
    /// Args before the script/project path (e.g. `["run"]` for `go run`).
    args: &'static [&'static str],
    /// Args after it, before the program's own args (e.g. `["--"]` for `dotnet run`).
    post_args: &'static [&'static str],
    /// The script file, or for `dotnet` the project directory, under `fixtures/`.
    script: &'static str,
    deps: &'static [&'static str],
}

const SIDECARS: &[SidecarSpec] = &[
    SidecarSpec {
        lang: "python",
        command: "python3",
        args: &[],
        post_args: &[],
        script: "parse_cookies.py",
        deps: &["SimpleCookie", "Werkzeug"],
    },
    SidecarSpec {
        lang: "node",
        command: "node",
        args: &[],
        post_args: &[],
        script: "parse_cookies.js",
        deps: &["cookie", "tough-cookie"],
    },
    SidecarSpec {
        lang: "go",
        command: "go",
        args: &["run"],
        post_args: &[],
        script: "parse_cookies.go",
        deps: &["net/http"],
    },
    SidecarSpec {
        lang: "dotnet",
        command: "dotnet",
        args: &["run", "-v", "q", "--project"],
        post_args: &["--"],
        script: "dotnet",
        deps: &["Microsoft.Net.Http.Headers"],
    },
];

/// Build every sidecar-backed column (graceful SKIP where unavailable), plus a
/// human version line per sidecar for the matrix's "tested against" footer.
pub fn sidecar_columns(scenarios: &[Scenario]) -> (Vec<Column>, Vec<String>) {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures");
    let mut columns = Vec::new();
    let mut versions = Vec::new();
    for spec in SIDECARS {
        let script = fixtures.join(spec.script);
        let command = resolve_command(spec.command);
        let check = selfcheck(&command, spec.args, spec.post_args, &script);
        versions.push(version_line(spec, &check));
        let results = if check.is_some() {
            run_sidecar(&command, spec.args, spec.post_args, &script, scenarios)
        } else {
            None
        };
        for dep in spec.deps {
            let dep_ok = check
                .as_ref()
                .and_then(|c| c.available.get(*dep).copied())
                .unwrap_or(false);
            let cells = scenarios
                .iter()
                .map(|s| {
                    if !dep_ok {
                        return ParseOutcome::Skipped;
                    }
                    results
                        .as_ref()
                        .and_then(|m| m.get(s.id))
                        .and_then(|by_dep| by_dep.get(*dep))
                        .cloned()
                        .unwrap_or(ParseOutcome::Skipped)
                })
                .collect();
            columns.push(Column {
                lang: spec.lang.to_string(),
                dep: dep.to_string(),
                cells,
            });
        }
    }
    (columns, versions)
}

/// A `runtime — dep ver, dep ver` line for the footer (or an unavailable note).
fn version_line(spec: &SidecarSpec, check: &Option<SelfcheckLine>) -> String {
    match check {
        None => format!("{}: unavailable (SKIP)", spec.lang),
        Some(sc) => {
            let runtime = sc
                .versions
                .get("runtime")
                .cloned()
                .unwrap_or_else(|| spec.lang.to_string());
            let deps: Vec<String> = spec
                .deps
                .iter()
                .map(|d| {
                    let v = sc.versions.get(*d).map(String::as_str).unwrap_or("?");
                    format!("{d} {v}")
                })
                .collect();
            format!("{runtime} — {}", deps.join(", "))
        }
    }
}

/// Prefer a crate-local `.venv/bin/python3` (where Werkzeug is installed) over
/// the system interpreter; otherwise use the command as given.
fn resolve_command(command: &str) -> String {
    if command == "python3" {
        let venv = Path::new(env!("CARGO_MANIFEST_DIR")).join(".venv/bin/python3");
        if venv.exists() {
            return venv.to_string_lossy().into_owned();
        }
    }
    command.to_string()
}

/// Ask a sidecar which dependencies it can load. `None` if it cannot even be run.
fn selfcheck(
    command: &str,
    args: &[&str],
    post_args: &[&str],
    script: &Path,
) -> Option<SelfcheckLine> {
    let output = Command::new(command)
        .args(args)
        .arg(script)
        .args(post_args)
        .arg("--selfcheck")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    // The first line that parses — tolerating any build chatter a `dotnet run`
    // or `go run` prints before the program's own output.
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines()
        .find_map(|line| serde_json::from_str::<SelfcheckLine>(line).ok())
}

/// Send the whole corpus to a sidecar and collect `id → {dep → outcome}`.
fn run_sidecar(
    command: &str,
    args: &[&str],
    post_args: &[&str],
    script: &PathBuf,
    scenarios: &[Scenario],
) -> Option<BTreeMap<String, BTreeMap<String, ParseOutcome>>> {
    let mut child = Command::new(command)
        .args(args)
        .arg(script)
        .args(post_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    {
        let mut stdin = child.stdin.take()?;
        for s in scenarios {
            let record = InputRecord {
                id: s.id,
                direction: match s.direction {
                    Direction::Request => "request",
                    Direction::Response => "response",
                },
                wire_b64: BASE64_STANDARD.encode(s.recipe.render()),
            };
            let line = serde_json::to_string(&record).ok()?;
            writeln!(stdin, "{line}").ok()?;
        }
        // stdin dropped here → EOF; the corpus is small, so no deadlock.
    }
    let output = child.wait_with_output().ok()?;
    if !output.status.success() {
        return None;
    }
    let mut map = BTreeMap::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        if let Ok(result) = serde_json::from_str::<ResultLine>(line) {
            map.insert(result.id, result.by_dep);
        }
    }
    Some(map)
}
