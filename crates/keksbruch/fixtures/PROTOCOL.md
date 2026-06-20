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
files. One process handles the whole run (it is **not** re-spawned per scenario).

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

- `wire_b64` is base64 (standard alphabet, padded) of the **raw** wire bytes — which may include
  `;`, CR, LF, NUL, and non-UTF-8 bytes. Decode it, then view the bytes as **latin-1** (each byte → one
  codepoint). Output JSON must be valid UTF-8, so widen latin-1 → UTF-8; a non-UTF-8 wire then renders
  as the *same* mojibake across every sidecar.
- `direction` is `"request"` (a `Cookie:` request-header value, possibly many pairs) or `"response"` (a
  single `Set-Cookie:` header value, one cookie). A dep that does not handle a direction returns
  `NotApplicable` for it.

For each input record print **one** result line to stdout:

```json
{ "id": "<scenario-id>", "by_dep": { "<dep>": <ParseOutcome>, "...": <ParseOutcome> } }
```

`by_dep` carries one `ParseOutcome` per declared dep. Order of output lines is irrelevant (the harness
keys by `id`). Exit 0 at EOF.

## ParseOutcome

Internally tagged by `"outcome"`. Matrix rendering shown in parentheses.

| `outcome` | extra fields | meaning | cell |
|---|---|---|---|
| `Cookies` | `cookies: [{name, value}, …]` | request parsed to pairs, in order | `[n=v, …]` / `∅` if empty |
| `Rejected` | `error: string` | request parser rejected the whole header | `❌` |
| `SetCookie` | `set_cookie: {…}` (below) | a `Set-Cookie` parsed | `name=value ;Attr;…` |
| `SetCookieRejected` | `error: string` | `Set-Cookie` parser rejected the input | `❌` |
| `NotApplicable` | — | this dep doesn't handle this direction | `n/a` |
| `Panicked` | `message: string` | the adapter panicked (a finding, not a crash) | `PANIC` |
| `Skipped` | — | comparator unavailable (dep/interpreter missing) | `SKIP` |
| `ForwardedVerbatim` | — | *proxy* target forwarded the Cookie byte-for-byte | `≡` |
| `ForwardedAltered` | `forwarded: string` | proxy forwarded a Cookie, but altered it | `≠ …` |
| `ForwardedRejected` | — | proxy did not forward the Cookie (rejected/dropped) | `❌` |

`set_cookie` fields: `name`, `value` (strings); `http_only`, `secure` (bool); `same_site`, `path`,
`domain` (string or null); `max_age` (integer or null — kept as `i64` so a negative delta survives).

The `error` (and `Panicked` `message`) strings are free-form, human-facing debug text — they are
**not** rendered in the matrix (a rejection always shows `❌`), so they never affect a cell or the
consensus vote. Give the best available reason, consistently: `<kind>: <detail>` where the parser
provides one (an exception type + message, or a library error string), or a clear `<what failed>`
where the API is opaque (e.g. a bool `TryParse` that yields no reason).

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
   the way node's `npm ci` and the vendored `lua/resty/cookie.lua` do.
