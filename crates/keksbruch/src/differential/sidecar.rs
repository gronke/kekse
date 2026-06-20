//! Language sidecars: small programs (`fixtures/parse_cookies.{py,js}`) that read
//! the corpus as base64-JSONL on stdin and emit a normalized [`ParseOutcome`] per
//! dependency on stdout. base64 keeps the protocol control-char-safe (the wire
//! carries CR/LF/NUL and even raw non-UTF-8). A missing interpreter or dependency
//! degrades to `Skipped` — a dev without python/node still gets the Rust columns.

use std::collections::BTreeMap;
use std::env;
use std::io::Write;
use std::path::Path;
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

/// How to run a sidecar inside an official Docker image. The image *tag* is a
/// version (`default_version`) plus a fixed `tag_suffix`, and the version can be
/// overridden at run time via `version_env` (e.g. `NODE_VERSION=25`) — to test a
/// sidecar against another runtime without editing code. Overriding only affects
/// the Docker path; with no `docker`, [`launch`] uses the host toolchain anyway.
struct ImageSpec {
    /// Docker repository, e.g. `node`, `golang`, `php` (note: `go`'s repo is `golang`).
    repo: &'static str,
    /// The pinned default version, used when `version_env` is unset or empty.
    default_version: &'static str,
    /// Appended after the version to form the tag, e.g. `-cli` for `php:8.5-cli`.
    tag_suffix: &'static str,
    /// Env var that overrides `default_version` at run time.
    version_env: &'static str,
}

impl ImageSpec {
    /// Resolve `repo:<version><suffix>` from an explicit version override. Pure,
    /// so it is unit-tested without touching the environment; a blank override
    /// (unset, empty, or whitespace) falls back to `default_version`.
    fn resolve_with(&self, override_ver: Option<&str>) -> String {
        let version = override_ver
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .unwrap_or(self.default_version);
        format!("{}:{}{}", self.repo, version, self.tag_suffix)
    }

    /// The image reference to run, honouring the `version_env` override.
    fn resolve(&self) -> String {
        self.resolve_with(env::var(self.version_env).ok().as_deref())
    }
}

/// One declared sidecar: its language label, interpreter, script, and the
/// dependency columns it reports.
struct SidecarSpec {
    lang: &'static str,
    command: &'static str,
    /// If set, run the sidecar inside this Docker image when `docker` is
    /// available (i.e. CI), so the runner needs no toolchain install; falls back
    /// to the host `command` when docker is absent (i.e. a local dev shell). The
    /// image version can be overridden at run time via [`ImageSpec::version_env`].
    image: Option<ImageSpec>,
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
        image: None,
        args: &[],
        post_args: &[],
        script: "parse_cookies.py",
        deps: &["SimpleCookie", "Werkzeug"],
    },
    SidecarSpec {
        lang: "node",
        command: "node",
        // cookie + tough-cookie deps; CI installs them into the bind-mounted fixtures
        // with the image's npm (see matrix.yml), then runs the sidecar from the image.
        // Override the version with NODE_VERSION (Docker path only); locally, with no
        // docker, it falls back to host `node` + host node_modules.
        image: Some(ImageSpec {
            repo: "node",
            default_version: "24",
            tag_suffix: "",
            version_env: "NODE_VERSION",
        }),
        args: &[],
        post_args: &[],
        script: "parse_cookies.js",
        deps: &["cookie", "tough-cookie"],
    },
    SidecarSpec {
        lang: "go",
        command: "go",
        // stdlib-only (net/http), so the official image runs it directly. Override
        // the version with GO_VERSION (Docker path only); locally, with no docker, it
        // falls back to host `go`. Note the Docker repo is `golang`, not `go`.
        image: Some(ImageSpec {
            repo: "golang",
            default_version: "1.26",
            tag_suffix: "",
            version_env: "GO_VERSION",
        }),
        args: &["run"],
        post_args: &[],
        script: "parse_cookies.go",
        deps: &["net/http"],
    },
    SidecarSpec {
        lang: "dotnet",
        command: "dotnet",
        image: None,
        args: &["run", "-v", "q", "--project"],
        post_args: &["--"],
        script: "dotnet",
        deps: &["Microsoft.Net.Http.Headers"],
    },
    SidecarSpec {
        lang: "php",
        // Pure core: native $_COOKIE via the built-in server. Request-only; PHP
        // has no Set-Cookie parser, so the response direction is n/a. CI runs it
        // in the php:<ver>-cli image (no toolchain install); override the version
        // with PHP_VERSION (the -cli flavor is fixed — the sidecar needs php-cli).
        // Locally, with no docker, it falls back to host `php`; absent → SKIP.
        command: "php",
        image: Some(ImageSpec {
            repo: "php",
            default_version: "8.5",
            tag_suffix: "-cli",
            version_env: "PHP_VERSION",
        }),
        args: &[],
        post_args: &[],
        script: "parse_cookies.php",
        deps: &["$_COOKIE"],
    },
    SidecarSpec {
        lang: "nginx",
        // OpenResty = nginx + LuaJIT + the `resty` CLI. The sidecar is a Lua script
        // run by `resty` that boots ONE nginx (the system under test) on loopback
        // ports and replays each request wire to it over an ngx cosocket — so nginx's
        // *native* Cookie handling is tested: $cookie_<name> (a by-name lookup),
        // lua-resty-cookie (a Lua-library parser), and proxy forwarding fidelity.
        // PHP-like and request-only (no Set-Cookie parser → n/a). CI runs it in the
        // openresty image; OPENRESTY_VERSION overrides the version (the -bookworm
        // flavor is fixed). Locally, with no docker, it falls back to host `resty`;
        // absent → SKIP.
        command: "resty",
        image: Some(ImageSpec {
            repo: "openresty/openresty",
            default_version: "1.31.1.1-0",
            tag_suffix: "-bookworm",
            version_env: "OPENRESTY_VERSION",
        }),
        args: &[],
        post_args: &[],
        script: "parse_cookies_nginx.lua",
        deps: &["$cookie_<name>", "lua-resty-cookie", "proxy"],
    },
    SidecarSpec {
        lang: "java",
        // tomcat-embed-core (the Rfc6265 + Legacy cookie processors) and the
        // jakarta.ws.rs API with TWO providers (RESTEasy + Jersey, discovered via
        // ServiceLoader). A CI step shades fixtures/java into target/sidecar.jar with
        // the maven image; the harness then runs that self-contained jar from
        // eclipse-temurin:<ver>-jre (the narrow bind-mount of …/java/target is why the
        // jar must be self-contained). Keycloak is intentionally absent — it delegates
        // request parsing to the JAX-RS layer (RESTEasy), so its parsing *is* the
        // `Jakarta RESTEasy` column (see matrix.rs prose). The two Jakarta columns
        // parse both directions; the two Tomcat columns are request-only (→ n/a).
        // Override the JDK with JAVA_VERSION (the -jre flavor is fixed). Locally, with
        // no docker, it falls back to host `java` (needs a host-built jar); absent → SKIP.
        command: "java",
        image: Some(ImageSpec {
            repo: "eclipse-temurin",
            default_version: "25",
            tag_suffix: "-jre",
            version_env: "JAVA_VERSION",
        }),
        args: &["-jar"],
        post_args: &[],
        script: "java/target/sidecar.jar",
        deps: &[
            "Tomcat RFC6265",
            "Tomcat legacy",
            "Jakarta RESTEasy",
            "Jakarta Jersey",
        ],
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
        let check = selfcheck(spec, &script);
        versions.push(version_line(spec, &check));
        let results = if check.is_some() {
            run_sidecar(spec, &script, scenarios)
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

/// Whether a usable `docker` CLI is on PATH — true on the CI runner, false in a
/// plain dev shell. Decides, per spec, whether an `image` runs containerized or
/// falls back to the host toolchain.
fn docker_available() -> bool {
    Command::new("docker")
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Build the base command to launch a sidecar: directly on the host, or — when
/// the spec names a Docker `image` and `docker` is available — inside that image,
/// bind-mounting the fixtures dir at its own path so the absolute `script` path
/// resolves identically in the container. `interactive` adds `-i` so a piped
/// stdin reaches the container. The caller still sets stdio and any extra args.
fn launch(spec: &SidecarSpec, script: &Path, interactive: bool) -> Command {
    if let Some(img) = &spec.image {
        if docker_available() {
            let image_ref = img.resolve();
            let dir = script
                .parent()
                .expect("a sidecar script always has a parent (the fixtures dir)")
                .to_string_lossy()
                .into_owned();
            let mut cmd = Command::new("docker");
            cmd.arg("run").arg("--rm");
            if interactive {
                cmd.arg("-i");
            }
            cmd.arg("-v")
                .arg(format!("{dir}:{dir}"))
                .arg("-w")
                .arg(&dir)
                .arg(&image_ref)
                .arg(spec.command)
                .args(spec.args)
                .arg(script)
                .args(spec.post_args);
            return cmd;
        }
    }
    // Host invocation: no image, or docker absent (the local fallback).
    let mut cmd = Command::new(resolve_command(spec.command));
    cmd.args(spec.args).arg(script).args(spec.post_args);
    cmd
}

/// Ask a sidecar which dependencies it can load. `None` if it cannot even be run.
fn selfcheck(spec: &SidecarSpec, script: &Path) -> Option<SelfcheckLine> {
    let output = launch(spec, script, false)
        .arg("--selfcheck")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    // The first line that parses — tolerating any build chatter a `dotnet run`,
    // `go run`, or a docker image pull prints before the program's own output.
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines()
        .find_map(|line| serde_json::from_str::<SelfcheckLine>(line).ok())
}

/// Send the whole corpus to a sidecar and collect `id → {dep → outcome}`.
fn run_sidecar(
    spec: &SidecarSpec,
    script: &Path,
    scenarios: &[Scenario],
) -> Option<BTreeMap<String, BTreeMap<String, ParseOutcome>>> {
    let mut child = launch(spec, script, true)
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The declared `ImageSpec` for a sidecar language (panics if it has none).
    fn image_of(lang: &str) -> &'static ImageSpec {
        SIDECARS
            .iter()
            .find(|s| s.lang == lang)
            .and_then(|s| s.image.as_ref())
            .expect("sidecar has a declared image")
    }

    #[test]
    fn image_defaults_to_the_pinned_version() {
        assert_eq!(image_of("node").resolve_with(None), "node:24");
        assert_eq!(image_of("go").resolve_with(None), "golang:1.26");
        assert_eq!(image_of("php").resolve_with(None), "php:8.5-cli");
        assert_eq!(
            image_of("nginx").resolve_with(None),
            "openresty/openresty:1.31.1.1-0-bookworm"
        );
        assert_eq!(
            image_of("java").resolve_with(None),
            "eclipse-temurin:25-jre"
        );
    }

    #[test]
    fn image_version_override_applies() {
        assert_eq!(image_of("node").resolve_with(Some("25")), "node:25");
        assert_eq!(image_of("go").resolve_with(Some("1.25")), "golang:1.25");
        // The -cli flavor is fixed; PHP_VERSION sets only the X.Y version.
        assert_eq!(image_of("php").resolve_with(Some("8.4")), "php:8.4-cli");
        // The -bookworm flavor is fixed; OPENRESTY_VERSION sets only the version.
        assert_eq!(
            image_of("nginx").resolve_with(Some("1.25.3.2-2")),
            "openresty/openresty:1.25.3.2-2-bookworm"
        );
        // The -jre flavor is fixed; JAVA_VERSION sets only the JDK version.
        assert_eq!(
            image_of("java").resolve_with(Some("21")),
            "eclipse-temurin:21-jre"
        );
    }

    #[test]
    fn blank_override_falls_back_to_the_default() {
        assert_eq!(image_of("node").resolve_with(Some("")), "node:24");
        assert_eq!(image_of("node").resolve_with(Some("   ")), "node:24");
        assert_eq!(
            image_of("nginx").resolve_with(Some("  ")),
            "openresty/openresty:1.31.1.1-0-bookworm"
        );
        assert_eq!(
            image_of("java").resolve_with(Some("")),
            "eclipse-temurin:25-jre"
        );
    }
}
