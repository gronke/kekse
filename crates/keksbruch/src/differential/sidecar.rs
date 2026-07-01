//! Language sidecars: small programs (`fixtures/parse_cookies.{py,js}`) that read
//! the corpus as base64-JSONL on stdin and emit a normalized [`ParseOutcome`] per
//! dependency on stdout. base64 keeps the protocol control-char-safe (the wire
//! carries CR/LF/NUL and even raw non-UTF-8). A missing interpreter or dependency
//! degrades to `Skipped` — a dev without python/node still gets the Rust columns.
//!
//! A sidecar that *crashes* (a native parser segfaults, aborts, or hangs on a
//! single payload) is not swallowed: `run_sidecar` attributes the crash to the
//! exact payload (`☠️`, [`ParseOutcome::Crashed`]) and replays the rest in a fresh
//! process, so one bad input no longer voids the whole column.

use std::collections::BTreeMap;
use std::env;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

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
        // SimpleCookie is stdlib; Werkzeug + mitmproxy are installed (network on) into
        // a bind-mounted `.pydeps` by CI (`pip install --target`, in this same image so
        // the wheels match), which the sidecar adds to sys.path — so the harness runs it
        // with `--network=none` and imports resolve offline. Locally, with no docker, it
        // falls back to host `python3` (resolve_command prefers a crate-local .venv).
        image: Some(ImageSpec {
            repo: "python",
            default_version: "3.13",
            tag_suffix: "",
            version_env: "PYTHON_VERSION",
        }),
        args: &[],
        post_args: &[],
        script: "parse_cookies.py",
        deps: &["SimpleCookie", "http.cookiejar", "Werkzeug", "mitmproxy"],
    },
    SidecarSpec {
        lang: "node",
        command: "node",
        // Five npm columns: `cookie` (request) + `tough-cookie` (response), plus
        // `set-cookie-parser` (response), `universal-cookie` (request — the parser
        // behind react-cookie), and `js-cookie` (request — the browser library, via a
        // document.cookie stub). CI installs them into the bind-mounted fixtures with
        // the image's npm (see matrix.yml), then runs the sidecar from the image.
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
        deps: &[
            "cookie",
            "tough-cookie",
            "set-cookie-parser",
            "universal-cookie",
            "js-cookie",
        ],
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
        // ASP.NET Core's header parser (Cookie/SetCookieHeaderValue). CI `dotnet
        // publish`es it (network on) to a self-contained folder in the bind-mount, so
        // the harness runs the published DLL from the SDK image with `--network=none`
        // (no runtime restore, no network). Override the SDK with DOTNET_VERSION.
        // Locally, with no docker, it falls back to host `dotnet <dll>` (SKIP until the
        // project is published).
        command: "dotnet",
        image: Some(ImageSpec {
            repo: "mcr.microsoft.com/dotnet/sdk",
            default_version: "8.0",
            tag_suffix: "",
            version_env: "DOTNET_VERSION",
        }),
        args: &[],
        post_args: &[],
        script: "dotnet/publish/parse_cookies.dll",
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
        // The three request columns are PHP-like and request-only; a fourth,
        // `proxy (Set-Cookie)`, is response-only — the forwarding-fidelity verdict for
        // an upstream Set-Cookie a proxy_pass relays back (nginx exposes no parsed
        // Set-Cookie to Lua, so it is fidelity, not a parse). CI runs it in the
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
        deps: &[
            "$cookie_<name>",
            "lua-resty-cookie",
            "proxy",
            "proxy (Set-Cookie)",
        ],
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
        // It also adds two response-only Set-Cookie columns: the JDK's
        // `java.net.HttpCookie` and Apache HttpClient 5's RFC 6265 cookie spec.
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
            "java.net.HttpCookie",
            "Apache HttpClient5",
        ],
    },
    SidecarSpec {
        lang: "c",
        // A compiled libcurl program — the matrix's only native-C column, and a
        // Set-Cookie parser (libcurl's cookie engine, exercised offline). `sh` runs a
        // wrapper that execs the `parse_cookies` binary CI compiles *inside* this image
        // (`cc … -lcurl`; see matrix.yml), so it runs with `--network=none`. buildpack-deps
        // carries gcc + libcurl. Locally, with no docker, it falls back to host `sh` +
        // a host-compiled binary; absent/uncompiled → the exec fails → SKIP.
        command: "sh",
        image: Some(ImageSpec {
            repo: "buildpack-deps",
            default_version: "trixie",
            tag_suffix: "",
            version_env: "BUILDPACK_DEPS_VERSION",
        }),
        args: &[],
        post_args: &[],
        script: "parse_cookies_c.sh",
        deps: &["libcurl"],
    },
    SidecarSpec {
        lang: "client",
        // curl and wget as real HTTP clients: a Python driver boots a loopback server
        // that replies with `Set-Cookie: <wire>`, runs each client against it, and reads
        // the cookie back from the saved Netscape jar — the *transfer* view (the request
        // host supplies the domain, so host-only cookies parse, unlike c/libcurl's
        // offline injection). Runs in a small CI-built image (curl + wget + python3) with
        // `--network=none`; the loopback server/client live inside that one container.
        // Locally, with no docker, it falls back to host `python3` + host curl/wget.
        command: "python3",
        image: Some(ImageSpec {
            repo: "keksbruch-clients",
            default_version: "local",
            tag_suffix: "",
            version_env: "CLIENTS_IMAGE_VERSION",
        }),
        args: &[],
        post_args: &[],
        script: "parse_setcookie_clients.py",
        deps: &["curl", "wget"],
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
            // `--network=none`: a sidecar runs untrusted third-party parsers against
            // untrusted input, so it gets NO network — defence-in-depth against a
            // compromised dependency exfiltrating or phoning home. The container keeps
            // its loopback interface, which is all any sidecar needs (nginx and the
            // curl/wget client boot servers on 127.0.0.1 inside their own container).
            // The image must be pre-pulled/built (CI does this with network on) since a
            // no-network `docker run` cannot pull. The matrix job itself also holds no
            // push/deploy credentials — only the separate deploy-pages job does.
            cmd.arg("run").arg("--rm").arg("--network=none");
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

/// How long to wait for the *next* result line before declaring a sidecar hung.
/// Inactivity-based (it resets on every line received), so a slow cold start — a
/// `go run` compile, a docker image, a booted server — is fine, while an infinite
/// loop or quadratic blow-up on one payload is caught. A hang is recorded as a
/// `☠️` crash, exactly like a terminating signal or a non-zero exit.
const SIDECAR_INACTIVITY_TIMEOUT: Duration = Duration::from_secs(60);

/// The most stdout-diagnostic / stderr text kept per process. Enough to hold a
/// stack trace; a runaway sidecar is truncated rather than bloating the report
/// (its pipe is still fully drained, so a cap can never deadlock the child).
const STREAM_CAP: usize = 64 * 1024;

/// What one run of a sidecar process produced.
struct BatchOutcome {
    /// `id → {dep → outcome}` for the records this run answered.
    answers: BTreeMap<String, BTreeMap<String, ParseOutcome>>,
    /// `None` if the process exited 0; `Some(reason)` if it died on a signal,
    /// exited non-zero, or was killed for hanging — the crash diagnosis.
    death: Option<String>,
    /// Non-protocol text the process printed to stdout (build chatter, stray
    /// prints); the JSONL protocol lines are consumed into `answers`, not kept.
    /// `None` when it printed only protocol output.
    stdout: Option<String>,
    /// Everything the process wrote to stderr — a panic/traceback/exception or a
    /// build error, drained on its own thread. `None` when stderr was empty.
    stderr: Option<String>,
}

/// Send the whole corpus to a sidecar and collect `id → {dep → outcome}`.
///
/// The happy path is one process for the whole corpus, exactly as before. But a
/// sidecar can *crash* — segfault, abort, or hang — on a specific payload (the new
/// native C/curl/wget columns genuinely can, and that is a finding worth keeping).
/// So when a run dies with records still unanswered, the offending payload is
/// marked [`ParseOutcome::Crashed`] (`☠️`) and the **rest are replayed in a fresh
/// process**, so one crash no longer voids the whole column — the old behaviour
/// turned every cell to `SKIP`, hiding both the crash and the survivors.
fn run_sidecar(
    spec: &SidecarSpec,
    script: &Path,
    scenarios: &[Scenario],
) -> Option<BTreeMap<String, BTreeMap<String, ParseOutcome>>> {
    let mut answered: BTreeMap<String, BTreeMap<String, ParseOutcome>> = BTreeMap::new();
    let mut remaining: Vec<&Scenario> = scenarios.iter().collect();

    // Each iteration runs the pending records in one process; it either answers
    // some (progress) or pins exactly one crasher (also progress), so `remaining`
    // strictly shrinks and the loop terminates.
    while !remaining.is_empty() {
        let BatchOutcome {
            answers,
            death,
            stdout,
            stderr,
        } = run_batch(spec, script, &remaining)?;
        let made_progress = !answers.is_empty();
        for (id, by_dep) in answers {
            answered.insert(id, by_dep);
        }
        let next: Vec<&Scenario> = remaining
            .iter()
            .copied()
            .filter(|s| !answered.contains_key(s.id))
            .collect();
        if next.is_empty() {
            return Some(answered);
        }
        let Some(reason) = death else {
            // Exited cleanly yet left records unanswered: a sidecar that simply did
            // not emit them, not a crash. Leave them to default to SKIP.
            return Some(answered);
        };

        // The process died with `next` unanswered; its first record is the prime
        // suspect. When the run produced *no* output at all, the suspect is a guess
        // (a sidecar that block-buffers stdout dies before flushing any line), so
        // confirm by re-running it alone before blaming it.
        let crasher = next[0];
        // Attribute the crashing process's captured output to the crasher. When we
        // re-run it alone (below), the solo run's streams are exactly its own.
        let (crash_reason, crash_stdout, crash_stderr) = if !made_progress && next.len() > 1 {
            let solo = run_batch(spec, script, &[crasher])?;
            if let Some(by_dep) = solo.answers.get(crasher.id) {
                // Parses fine alone — the true crasher is later in the batch.
                answered.insert(crasher.id.to_string(), by_dep.clone());
                remaining = next[1..].to_vec();
                continue;
            }
            (solo.death.unwrap_or(reason), solo.stdout, solo.stderr)
        } else {
            (reason, stdout, stderr)
        };
        answered.insert(
            crasher.id.to_string(),
            crash_map(
                spec,
                &crash_reason,
                crash_stdout.as_deref(),
                crash_stderr.as_deref(),
            ),
        );
        remaining = next[1..].to_vec();
    }
    Some(answered)
}

/// Run one batch of records in a fresh sidecar process: stream the input on stdin,
/// read result lines off stdout with an inactivity timeout (a reader thread feeds
/// a channel, so a full stdout pipe can never deadlock the writer), and classify
/// how the process ended.
fn run_batch(spec: &SidecarSpec, script: &Path, batch: &[&Scenario]) -> Option<BatchOutcome> {
    let mut child = launch(spec, script, true)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        // stderr is captured (drained on its own thread below) so a panic /
        // traceback / exception survives as the crash tooltip, not just the exit
        // signal. A dedicated thread is required: draining only stdout while the
        // child fills a stderr pipe would deadlock it.
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;

    // Drain stdout on a thread *before* writing stdin, so the child can never block
    // on a full stdout pipe while we are still feeding its stdin (a pipe deadlock).
    let stdout = child.stdout.take()?;
    let (tx, rx) = mpsc::channel();
    let reader = thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            // A read error means the child died mid-line; a send error means the
            // receiver is gone. Either way, stop draining.
            match line {
                Ok(l) => {
                    if tx.send(l).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        // `tx` drops here → the receiver sees `Disconnected`, our stdout-EOF signal.
    });

    // Drain stderr concurrently on its own thread (see the `.stderr` note above),
    // keeping up to `STREAM_CAP` bytes as the crash diagnostic.
    let stderr_pipe = child.stderr.take()?;
    let err_reader = thread::spawn(move || drain_capped(stderr_pipe));

    {
        let mut stdin = child.stdin.take()?;
        for s in batch {
            let record = InputRecord {
                id: s.id,
                direction: match s.direction {
                    Direction::Request => "request",
                    Direction::Response => "response",
                },
                wire_b64: BASE64_STANDARD.encode(s.recipe.render()),
            };
            if let Ok(line) = serde_json::to_string(&record) {
                // A write error (EPIPE) means the child already died — Rust ignores
                // SIGPIPE, so this returns rather than killing us. Stop feeding it
                // and let the read loop below observe the death.
                if writeln!(stdin, "{line}").is_err() {
                    break;
                }
            }
        }
        // stdin dropped here → EOF.
    }

    let mut answers: BTreeMap<String, BTreeMap<String, ParseOutcome>> = BTreeMap::new();
    // Lines that are not protocol JSON — build chatter or a stray print — kept (up
    // to `STREAM_CAP`) as the stdout half of a crash diagnostic.
    let mut stdout_diag: Vec<String> = Vec::new();
    let mut stdout_bytes = 0usize;
    let mut stdout_truncated = false;
    let mut timed_out = false;
    loop {
        match rx.recv_timeout(SIDECAR_INACTIVITY_TIMEOUT) {
            Ok(line) => match serde_json::from_str::<ResultLine>(&line) {
                Ok(result) => {
                    answers.insert(result.id, result.by_dep);
                }
                Err(_) if stdout_bytes < STREAM_CAP => {
                    stdout_bytes += line.len() + 1;
                    stdout_diag.push(line);
                }
                Err(_) => stdout_truncated = true,
            },
            Err(mpsc::RecvTimeoutError::Timeout) => {
                timed_out = true;
                let _ = child.kill();
                break;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break, // stdout reached EOF
        }
    }
    let status = child.wait().ok();
    let _ = reader.join();
    let stderr = err_reader.join().ok().flatten();

    let death = if timed_out {
        Some("timeout".to_string())
    } else {
        match status {
            Some(s) if s.success() => None,
            Some(s) => Some(death_reason(s)),
            None => Some("abnormal exit".to_string()),
        }
    };
    let stdout = if stdout_diag.is_empty() {
        None
    } else {
        let mut s = stdout_diag.join("\n");
        if stdout_truncated {
            s.push_str("\n… (truncated)");
        }
        Some(s)
    };
    Some(BatchOutcome {
        answers,
        death,
        stdout,
        stderr,
    })
}

/// Mark every dependency column of a sidecar `Crashed` for the payload that killed
/// the process — one crash takes the whole process down, hence every dep with it.
/// The crashing process's captured `stdout`/`stderr` (a stack trace, usually) ride
/// along so the matrix can show *why* it died, not just the signal.
fn crash_map(
    spec: &SidecarSpec,
    reason: &str,
    stdout: Option<&str>,
    stderr: Option<&str>,
) -> BTreeMap<String, ParseOutcome> {
    spec.deps
        .iter()
        .map(|d| {
            (
                d.to_string(),
                ParseOutcome::Crashed {
                    reason: reason.to_string(),
                    stdout: stdout.map(str::to_string),
                    stderr: stderr.map(str::to_string),
                },
            )
        })
        .collect()
}

/// A human reason for an abnormal exit: the terminating signal where there is one
/// (a segfault is `signal 11`), else the non-zero exit code.
fn death_reason(status: ExitStatus) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            return format!("signal {sig}");
        }
    }
    match status.code() {
        Some(code) => format!("exit {code}"),
        None => "abnormal exit".to_string(),
    }
}

/// Drain a child pipe fully — so it can never fill and deadlock the child — while
/// keeping at most [`STREAM_CAP`] bytes as lossy-decoded text (a crash's stack
/// trace fits comfortably). `None` when the stream was empty.
fn drain_capped<R: Read>(mut r: R) -> Option<String> {
    let mut buf = Vec::new();
    let _ = (&mut r).take(STREAM_CAP as u64).read_to_end(&mut buf);
    // Keep reading past the cap into the void so the writer never blocks.
    let overflowed = std::io::copy(&mut r, &mut std::io::sink()).unwrap_or(0) > 0;
    if buf.is_empty() {
        return None;
    }
    let mut text = String::from_utf8_lossy(&buf).into_owned();
    if overflowed {
        text.push_str("\n… (truncated)");
    }
    Some(text)
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

    /// A throwaway python sidecar that answers every record `NotApplicable` but
    /// kills itself the instant it sees one id — modelling a native parser that
    /// crashes on a specific payload. `__CRASH_ID__` is substituted per test.
    /// SIGKILL (not `abort()`) so the test never litters the tree with core dumps,
    /// while still exercising the signal branch of `death_reason`.
    const FAUX_CRASHING_SIDECAR: &str = r#"
import sys, json, os, signal
CRASH = "__CRASH_ID__"
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    rec = json.loads(line)
    if rec["id"] == CRASH:
        sys.stderr.write("FauxTraceback: boom at %s\n" % CRASH)
        sys.stderr.flush()
        os.kill(os.getpid(), signal.SIGKILL)
    print(json.dumps({"id": rec["id"], "by_dep": {"faux": {"outcome": "NotApplicable"}}}), flush=True)
"#;

    /// A sidecar that dies mid-stream must not void the whole column: the crashing
    /// payload is pinned as `Crashed` (☠️) and the records after it are replayed in
    /// a fresh process, so the survivors still report.
    #[test]
    fn a_crashing_sidecar_is_isolated_and_the_rest_replays() {
        use crate::differential::result::ParseOutcome;

        // The differential harness assumes python3; skip cleanly if absent rather
        // than fail spuriously on a host without it.
        let have_py = std::process::Command::new("python3")
            .arg("--version")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !have_py {
            return;
        }

        let all = crate::scenario::scenarios();
        assert!(all.len() >= 6, "corpus should have at least 6 scenarios");
        let batch = &all[..6];
        let crash_id = batch[2].id; // crash on the 3rd record
        let earlier_id = batch[0].id; // answered before the crash
        let later_id = batch[5].id; // answered only if the replay runs

        let path = std::env::temp_dir().join(format!("keksbruch_faux_{}.py", std::process::id()));
        std::fs::write(
            &path,
            FAUX_CRASHING_SIDECAR.replace("__CRASH_ID__", crash_id),
        )
        .expect("write the faux sidecar script");

        let spec = SidecarSpec {
            lang: "faux",
            command: "python3",
            image: None,
            args: &[],
            post_args: &[],
            script: "unused", // run_sidecar takes the script path explicitly
            deps: &["faux"],
        };
        let result = run_sidecar(&spec, &path, batch);
        let _ = std::fs::remove_file(&path);
        let result = result.expect("run_sidecar returns Some even when a payload crashes");

        let faux = |id: &str| result.get(id).and_then(|by_dep| by_dep.get("faux"));
        // The crashing payload is pinned Crashed, and it carries the process's
        // captured stderr (its "stack trace") — the text the HTML tooltip surfaces,
        // not just the terminating signal.
        match faux(crash_id) {
            Some(ParseOutcome::Crashed { reason, stderr, .. }) => {
                assert!(reason.starts_with("signal"), "reason: {reason:?}");
                assert!(
                    stderr
                        .as_deref()
                        .unwrap_or("")
                        .contains("FauxTraceback: boom"),
                    "captured stderr should carry the trace, got {stderr:?}"
                );
            }
            other => panic!("the crashing payload should be pinned Crashed, got {other:?}"),
        }
        assert!(
            matches!(faux(earlier_id), Some(ParseOutcome::NotApplicable)),
            "a record before the crash should still be answered, got {:?}",
            faux(earlier_id)
        );
        assert!(
            matches!(faux(later_id), Some(ParseOutcome::NotApplicable)),
            "a record after the crash should be answered by the replay, got {:?}",
            faux(later_id)
        );
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
