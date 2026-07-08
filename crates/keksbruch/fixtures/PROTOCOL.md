# keksbruch sidecar protocol

A **sidecar** is a small program that parses cookie *wire* in one language/library and reports a
normalized result, so the differential matrix can diff wildly different parser APIs as table cells.
The Rust harness (`src/differential/sidecar.rs`) drives every sidecar over this contract. This file is
the single source of truth — each sidecar's header comment points here.

## Invocation

The harness declares each sidecar as a `SidecarSpec { lang, command, image, args, post_args, script,
deps }` and runs it as:

```
<command> <args…> <script> <post_args…>           # the parse run (stdin → stdout)
<command> <args…> <script> <post_args…> --selfcheck  # the availability probe
```

If the spec names a Docker `image` and `docker` is on PATH (i.e. CI), the harness runs that command
line *inside* the image, bind-mounting the `fixtures/` dir at its own absolute path (`-v dir:dir -w
dir`); otherwise it runs on the host toolchain. Either way the sidecar sees the same argv and the same
files. One process normally handles the whole run; the harness only **re-spawns** it to recover from a
*crash* — if the process dies (a signal, a non-zero exit, or no output for ~60 s), the harness blames the
payload in flight (`☠️`, `Crashed`) and replays the rest in a fresh process. So a single bad input cannot
void the whole column. For that blame to land on the right payload, **flush stdout after each result line**
(see §2) — a sidecar that block-buffers its output and then crashes gives the harness no way to see which
record it had reached.

## 1. Selfcheck (`--selfcheck`)

When any argument is `--selfcheck`, read no stdin and print **exactly one** JSON object (one line) to
stdout, then exit 0:

```json
{
  "available": { "<dep>": true, "...": false },
  "versions":  { "runtime": "<Runtime X.Y.Z>", "<dep>": "<version>", "...": "..." }
}
```

- The keys of `available` — and the keys of `versions` other than `runtime` — **must equal** the
  sidecar's declared `deps`. A dep mapped to `false` (can't load / not installed) makes that column
  `SKIP`; if the whole selfcheck fails to run or parse, every column for the sidecar is `SKIP`.
- `runtime` is the human version string for the matrix footer. Use the convention **`<Runtime>
  <X.Y.Z>`** — e.g. `Python 3.12.13`, `Node 24.17.0`, `Go 1.26.4`, `.NET 8.0.28`, `PHP 8.5.7`,
  `OpenResty 1.27.1.2`. A per-dep version may be a real version (`Werkzeug 3.1.8`) or a mechanism
  label where there is no semver (`stdlib`, `SAPI cli-server`, `ngx_http_variables`).
- The harness reads the **first line that parses**, tolerating any build/pull chatter (`go run`,
  `dotnet run`, a docker pull) printed before it.

## 2. Parse run (stdin → stdout)

Read stdin as **base64-JSONL**: one record per line, blank lines skipped, until EOF. Each record:

```json
{ "id": "<scenario-id>", "direction": "request" | "response", "wire_b64": "<base64 of the raw bytes>" }
```

or (protocol v2) a **jar probe**:

```json
{ "id": "<probe-id>", "direction": "jar", "wire_b64": "<base64 of the Set-Cookie bytes>",
  "origin_url": "https://sub.example.com/dir/page", "request_url": "https://example.com/dir/other" }
```

- `wire_b64` is base64 (standard alphabet, padded) of the **raw** wire bytes — which may include
  `;`, CR, LF, NUL, and non-UTF-8 bytes. Decode it, then view the bytes as **latin-1** (each byte → one
  codepoint). Output JSON must be valid UTF-8, so widen latin-1 → UTF-8; a non-UTF-8 wire then renders
  as the *same* mojibake across every sidecar.
- `direction` is `"request"` (a `Cookie:` request-header value, possibly many pairs), `"response"` (a
  single `Set-Cookie:` header value, one cookie), or `"jar"` (below). A dep that does not handle a
  direction returns `NotApplicable` for it — and a sidecar **must** answer any record whose
  `direction` it does not recognize with `NotApplicable` for every dep, so a stale checkout degrades
  gracefully instead of misreading a new record kind as a response.

### `direction: "jar"` — the store-then-retrieve probe

A two-input experiment for client *jars* (RFC 6265 §5.3 storage + §5.4 retrieval): store the decoded
`Set-Cookie` as if it was received in a response from `origin_url`, then answer with the cookies the
dep's jar would attach to a request to `request_url`, as `{"outcome":"Cookies","cookies":[…]}`.

- An **empty list** (`∅`) means "would not be sent" — whether the jar refused storage (a domain
  mismatch, a public-suffix `Domain`) or the match failed. One observable, so the consensus vote
  works unchanged.
- A dep with no jar semantics (a pure codec) answers `NotApplicable`.
- The URLs are harness-authored ASCII of the shape `scheme://host/path` (no port, userinfo, or
  query); only `wire_b64` is adversarial.

For each input record print **one** result line to stdout:

```json
{ "id": "<scenario-id>", "by_dep": { "<dep>": <ParseOutcome>, "...": <ParseOutcome> } }
```

`by_dep` carries one `ParseOutcome` per declared dep. Order of output lines is irrelevant (the harness
keys by `id`). Exit 0 at EOF. **Flush stdout after each line** (e.g. `print(flush=True)`, `fflush(stdout)`)
so that, if a later record crashes the process, the harness can tell which records were already handled and
blame the right one — a fully buffered sidecar that dies looks like it crashed on its *first* record.

## ParseOutcome

Internally tagged by `"outcome"`. Matrix rendering shown in parentheses.

| `outcome` | extra fields | meaning | cell |
|---|---|---|---|
| `Cookies` | `cookies: [{name, value, shape?}, …]` | request parsed to pairs, in order | `[n=v, …]` / `∅` if empty |
| `Rejected` | `error: string` | request parser rejected the whole header | `❌` |
| `SetCookie` | `set_cookie: {…}` (below) | a `Set-Cookie` parsed | `name=value ;Attr;…` |
| `SetCookieRejected` | `error: string` | `Set-Cookie` parser rejected the input | `❌` |
| `NotApplicable` | — | this dep doesn't handle this direction | `n/a` |
| `Panicked` | `message: string` | an unexpected in-language failure (a finding, not a clean reject) | `☠️` |
| `Crashed` | `reason: string`, `stdout?`, `stderr?` | the parser **crashed** on this payload (signal / non-zero exit / hang) — usually synthesized by the harness on process death, which captures the crashing process's `stdout`/`stderr`; a sidecar may also emit it (and then may omit the streams) | `☠️` |
| `Skipped` | — | comparator unavailable (dep/interpreter missing) | `SKIP` |
| `ForwardedVerbatim` | — | *proxy* target forwarded the Cookie byte-for-byte | `≡` |
| `ForwardedAltered` | `forwarded: string` | proxy forwarded a Cookie, but altered it | `≠ …` |
| `ForwardedRejected` | — | proxy did not forward the Cookie (rejected/dropped) | `❌` |

`set_cookie` fields: `name`, `value` (strings); `http_only`, `secure` (bool, default false, may be
omitted); `partitioned` (CHIPS' flag, **tri-state**: `true`/`false` from a driver whose library and
protocol can observe the attribute — kept vs dropped — and omitted/`null` from one whose channel has
no field for it, e.g. classic WebDriver or the Netscape jar format; the harness renders the omitted
form as "not observable" and never scores it as a drop);
`same_site`, `path`,
`domain` (string or null); `max_age` (integer or null — kept as `i64` so a negative delta survives);
`expires` (integer Unix timestamp or null — the parsed `Expires` attribute).
A parser that folds `Expires` and `Max-Age` into one effective (possibly now-relative) expiry reports
`expires` as null, so a cell never depends on when the matrix ran.

A cookie's optional `shape` is `"scalar"` (the default — omit it), `"array"`, or `"object"`. A parser
that builds a *rich type* from a bracketed name — only PHP's `$_COOKIE`, via `name[]=`/`name[k]=` — sets
it and puts the JSON-encoded structure in `value`; the matrix then displays the type name
(`⟨array⟩`/`⟨object⟩`). Every other sidecar omits `shape`, and the harness defaults a missing `shape` to scalar.

The `error`, `Panicked` `message`, and `Crashed` `reason` strings — plus the harness-captured `stdout` /
`stderr` on a `Crashed` — are free-form, human-facing debug text. They never change a cell's glyph (a
rejection always shows `❌`, a crash always `☠️`) or the consensus vote, but the **HTML** matrix surfaces
them in a hover tooltip on the cell (a scrollable `<pre>`), so give the best available detail:
`<kind>: <detail>` where the parser provides one (an exception type + message, or a library error string),
or a clear `<what failed>` where the API is opaque (e.g. a bool `TryParse` that yields no reason). Like
`NotApplicable` and `Skipped`, both crash outcomes (`Panicked`/`Crashed`) are excluded from the
cross-parser consensus vote.

The three `Forwarded*` outcomes are a **forwarding-fidelity** axis (currently only the `nginx/proxy`
column), not a parse, so the harness excludes them from the cross-parser consensus vote.

## Worked example

```
→ {"id":"delim-semicolon","direction":"request","wire_b64":"bj1hO2V2aWw9MQ=="}
← {"id":"delim-semicolon","by_dep":{"cookie":{"outcome":"Cookies","cookies":[{"name":"n","value":"a"},{"name":"evil","value":"1"}]}}}

→ {"id":"resp-crlf","direction":"response","wire_b64":"..."}
← {"id":"resp-crlf","by_dep":{"cookie":{"outcome":"NotApplicable"}}}
```

## Adding a sidecar

1. Append a `SidecarSpec` to `SIDECARS` in `src/differential/sidecar.rs` (set `image` to run it
   containerized in CI; declare `deps` = the column keys).
2. Add the driver under `fixtures/` implementing the two modes above. `parse_cookies.php` (a server it
   boots and replays raw requests to) and `parse_cookies.py` (an in-process parser) are good templates.
3. If it needs deps, vendor them under `fixtures/` or install them in CI (`.github/workflows/matrix.yml`),
   the way node's `npm ci` and the vendored `lua/resty/cookie.lua` do. A compiled, dep-bearing sidecar can
   be built once in CI into the bind-mounted `fixtures/` with its own toolchain image and then run from a
   runtime image — see Java (`fixtures/java/`): a maven image shades `target/sidecar.jar`, which the harness
   runs with `java -jar` from a JRE image. A sidecar may also carry everything inside one CI-built image
   and keep the whole experiment on loopback under `--network=none` — see the browser driver
   (`parse_setcookie_browsers.py` + `fixtures/browsers/Dockerfile`): loopback origin servers on 80/443
   plus three WebDriver-driven engines in a single container.
