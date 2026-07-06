#!/usr/bin/env python3
"""keksbruch browser sidecar (Chromium, Firefox, Edge — the engine transfer view).

Three columns driven as real headless browsers over classic W3C WebDriver
(JSON over HTTP via urllib — no client library). Like the curl/wget sidecar,
a raw-socket loopback server replies `Set-Cookie: <wire>` verbatim, so each
engine's real header parser and cookie pipeline is what answers — including
RFC 6265bis policy (size caps, prefixes, the public-suffix list, SameSite
defaults) that pure parsers don't apply. The browsers run RELEASE DEFAULTS;
the only interventions are transport plumbing (DNS-to-loopback, self-signed
TLS acceptance, headless, sandbox, quieting, HTTPS-upgrade opt-outs), never
cookie policy — a divergent cell is a finding, not a harness artifact.

Transport: the server binds 127.0.0.1:80 and :443 (TLS, throwaway self-signed
cert — the container runs as root; on a host shell the bind fails and the
selfcheck honestly reports unavailable). Chromium/Edge reach it via
`--host-resolver-rules=MAP * 127.0.0.1`; Firefox via the
`network.dns.forceResolve` pref. Both keep the URL's hostname, so Domain
matching, the PSL, and default-path logic see realistic multi-label hosts.

Directions: `response` navigates to a fixed https origin and reads the stored
cookie back through the driver (the jar folds Expires/Max-Age into a run-time
expiry, so both report null — cells stay deterministic). `jar` navigates to
`origin_url`, then to `request_url`, and answers with the `Cookie` header the
server actually received (∅ = nothing attached). `request` is n/a — browsers
emit Cookie headers, they never parse them. Protocol: ./PROTOCOL.md.

Attribute reporting is wire-token-gated: the jar can only hand back effective
state (a defaulted path, an enforced SameSite), so a field is reported only
when the wire engaged that attribute. An unlabeled cookie therefore shows no
SameSite even though the engine enforces one, while a degenerate engaged value
(`SameSite=`, `Path=relative`) deliberately reveals the engine's fallback —
`Path=/r` in a cell means the request's default-path (the harness's reserved
`/r` prefix) replaced an unusable Path attribute.

Two path-scoping consequences of the W3C cookie commands (they only see the
current document's cookies): the stored-cookie readback and the post-record
cleanup both visit every engaged absolute Path in addition to the page that
set the cookie — otherwise a `Path=/b` cookie reads back as a phantom
rejection, and a jar probe's path-scoped cookie leaks into later records.
"""
import sys
import os
import json
import base64
import socket
import ssl
import threading
import subprocess
import tempfile
import shutil
import time
import urllib.request
import urllib.error

# The response-direction origin: multi-label, under the RFC 2606-reserved
# `.example` TLD (no PSL entry), so registrable-domain logic engages and a
# Domain attribute naming an unrelated host is refused at storage — the same
# complementary transfer-view semantics as the curl/wget columns on 127.0.0.1.
WIRE_HOST = "wire.keksbruch.example"
HTTP_PORT = 80
TLS_PORT = 443
PAGELOAD_MS = 10_000
# One wall-clock guard per WebDriver call, above the browser's own pageLoad
# timeout so the driver answers first and a wedged navigation surfaces as a
# WebDriver error on that one record, never as a harness inactivity timeout.
HTTP_TIMEOUT_S = PAGELOAD_MS / 1000 + 15

ENGINES = ("chromium", "firefox", "edge")


def find(candidates):
    for c in candidates:
        path = shutil.which(c)
        if path:
            return path
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return None


def chromium_like_caps(browser_name, options_key, binary, tmp):
    # --headless=new is the real browser code path; --no-sandbox because the
    # container runs as root; the resolver rule and cert-error flag are the
    # transport plumbing described in the module docstring; HttpsUpgrades is
    # disabled so a probe's http:// request really travels over http (a
    # transport choice, not cookie policy). The rest quiets first-run and
    # background-service noise so the loopback server sees only the harness.
    args = [
        "--headless=new",
        "--no-sandbox",
        "--disable-dev-shm-usage",
        "--ignore-certificate-errors",
        "--host-resolver-rules=MAP * 127.0.0.1,EXCLUDE localhost",
        "--disable-features=HttpsUpgrades",
        "--user-data-dir=" + os.path.join(tmp, "profile"),
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-background-networking",
        "--disable-component-update",
        "--disable-sync",
        "--metrics-recording-only",
        "--disable-default-apps",
    ]
    return {
        "browserName": browser_name,
        "acceptInsecureCerts": True,
        "timeouts": {"implicit": 0, "pageLoad": PAGELOAD_MS, "script": PAGELOAD_MS},
        options_key: {"binary": binary, "args": args},
    }


def firefox_caps(binary, tmp):
    prefs = {
        # All non-localhost DNS (hostnames and IP literals alike) resolves to
        # loopback — the pref exists exactly for fake-server test setups.
        "network.dns.forceResolve": "127.0.0.1",
        # Keep a probe's http:// request on http (transport, not cookie policy).
        "dom.security.https_first": False,
    }
    return {
        "browserName": "firefox",
        "acceptInsecureCerts": True,
        "timeouts": {"implicit": 0, "pageLoad": PAGELOAD_MS, "script": PAGELOAD_MS},
        "moz:firefoxOptions": {"binary": binary, "args": ["-headless"], "prefs": prefs},
    }


# Driver/browser lookup order: the image's pinned installs first (symlinked
# into /usr/local/bin by the Dockerfile), then common host names so a local
# shell with the binaries present can still run the column.
SPEC = {
    "chromium": {
        "driver": ("chromedriver",),
        "browser": ("chrome", "chromium", "chromium-browser", "google-chrome"),
        "port": 9515,
        "caps": lambda binary, tmp: chromium_like_caps("chrome", "goog:chromeOptions", binary, tmp),
    },
    "firefox": {
        "driver": ("geckodriver",),
        "browser": ("firefox", "firefox-esr"),
        "port": 9516,
        "caps": firefox_caps,
    },
    "edge": {
        "driver": ("msedgedriver",),
        "browser": ("microsoft-edge", "microsoft-edge-stable"),
        "port": 9517,
        "caps": lambda binary, tmp: chromium_like_caps("MicrosoftEdge", "ms:edgeOptions", binary, tmp),
    },
}

# stdout carries the JSONL protocol; the notes below share it, so one lock.
PRINT_LOCK = threading.Lock()


def emit(obj):
    with PRINT_LOCK:
        print(json.dumps(obj))
        sys.stdout.flush()


def note(text):
    # Not a protocol line: the harness ignores it (keeping it only as crash
    # diagnostics), but receiving it resets the 60 s inactivity timeout — so a
    # slow engine segment inside one record can never look like a hang.
    emit({"note": text})


# ── loopback origin servers: HTTP on :80, TLS on :443 ─────────────────────────
# Raw sockets (never http.server) so the Set-Cookie bytes go out verbatim,
# including CR/LF/NUL/controls — the engine meets the exact malformed wire.
# One armed expectation at a time (records run one engine × one record), keyed
# by exact host+path so favicon fetches and background chatter fall through to
# the inert `UNARMED` page — no Set-Cookie, no capture.

ARM_LOCK = threading.Lock()
ARMED = None


def arm(mode, host, path, wire=None):
    global ARMED
    state = {
        "mode": mode,  # "setcookie" (response + jar-origin) | "capture"
        "host": host.lower(),
        "path": path,
        "wire": wire,
        "cookie": None,  # the captured Cookie header (capture mode)
        "event": threading.Event(),
    }
    with ARM_LOCK:
        ARMED = state
    return state


def disarm():
    global ARMED
    with ARM_LOCK:
        ARMED = None


def http_response(extra_headers):
    body = b"ok"
    head = [
        b"HTTP/1.1 200 OK",
        b"Content-Length: " + str(len(body)).encode(),
        # Never let a jar probe's second navigation be served from cache — the
        # captured Cookie header is the observable (transport, not policy).
        b"Cache-Control: no-store",
    ]
    head += extra_headers
    head += [b"Connection: close", b"", body]
    return b"\r\n".join(head)


# Unmatched requests (favicon fetches, background chatter, the post-record
# cleanup navigation) get a plain 200 with no Set-Cookie and no capture. Not an
# error status on purpose: Chromium replaces small error responses with its own
# error page, whose internal document hides the host's cookies from the
# driver's cookie calls — which would silently break the post-record delete.
UNARMED = (
    b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n"
    b"Cache-Control: no-store\r\nConnection: close\r\n\r\nunarmed"
)


def handle(conn):
    try:
        conn.settimeout(5.0)
        head = b""
        while b"\r\n\r\n" not in head and len(head) < 262144:
            chunk = conn.recv(4096)
            if not chunk:
                break
            head += chunk
        lines = head.split(b"\r\n")
        parts = lines[0].split(b" ")
        path = parts[1].decode("latin-1") if len(parts) >= 2 else "/"
        host = ""
        cookie = None
        for raw in lines[1:]:
            if b":" not in raw:
                continue
            name, _, value = raw.partition(b":")
            name = name.strip().lower()
            if name == b"host" and not host:
                # Probe URLs carry no port; strip one anyway for safety.
                host = value.strip().decode("latin-1").split(":")[0].lower()
            elif name == b"cookie" and cookie is None:
                cookie = value.strip().decode("latin-1")
        with ARM_LOCK:
            state = ARMED
        if state is not None and host == state["host"] and path == state["path"]:
            if state["mode"] == "setcookie":
                conn.sendall(http_response([b"Set-Cookie: " + state["wire"]]))
            else:
                state["cookie"] = cookie
                conn.sendall(http_response([]))
            state["event"].set()
        else:
            conn.sendall(UNARMED)
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def serve(srv, tls_ctx):
    while True:
        try:
            conn, _ = srv.accept()
        except OSError:
            return
        if tls_ctx is not None:
            try:
                conn = tls_ctx.wrap_socket(conn, server_side=True)
            except Exception:
                # A failed handshake (a preconnect probe, an ALPN mismatch)
                # is the browser's business, not a harness error.
                try:
                    conn.close()
                except Exception:
                    pass
                continue
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


def mint_cert(tmp):
    cert = os.path.join(tmp, "cert.pem")
    key = os.path.join(tmp, "key.pem")
    # Contents are irrelevant: every engine runs with acceptInsecureCerts /
    # --ignore-certificate-errors, so any self-signed cert is accepted.
    run = subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key,
         "-out", cert, "-days", "90", "-nodes", "-subj", "/CN=keksbruch harness"],
        capture_output=True, timeout=60,
    )
    if run.returncode != 0:
        raise RuntimeError("openssl failed")
    return cert, key


def bind(port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(32)
    return srv


def start_servers(tmp):
    try:
        cert, key = mint_cert(tmp)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        plain = bind(HTTP_PORT)
        tls = bind(TLS_PORT)
    except Exception:
        return False
    threading.Thread(target=serve, args=(plain, None), daemon=True).start()
    threading.Thread(target=serve, args=(tls, ctx), daemon=True).start()
    return True


def can_bind(port):
    try:
        bind(port).close()
        return True
    except OSError:
        return False


# ── a classic-WebDriver client and the engine lifecycle ───────────────────────


class WdError(Exception):
    """A WebDriver-level failure: a driver error reply or an unreachable driver."""


class Engine:
    def __init__(self, name):
        self.name = name
        self.spec = SPEC[name]
        self.base = "http://127.0.0.1:%d" % self.spec["port"]
        self.proc = None
        self.session = None
        self.tmp = None
        self.taint = False  # a failed cleanup: relaunch before the next record

    def launch(self):
        driver = find(self.spec["driver"])
        browser = find(self.spec["browser"])
        if not driver or not browser:
            raise WdError("driver or browser binary missing")
        self.tmp = tempfile.mkdtemp(prefix="kb-%s-" % self.name)
        env = dict(
            os.environ,
            HOME=self.tmp,
            TMPDIR=self.tmp,
            XDG_CONFIG_HOME=os.path.join(self.tmp, ".config"),
            XDG_CACHE_HOME=os.path.join(self.tmp, ".cache"),
        )
        # The driver's own stdout/stderr must never reach ours: stdout is the
        # result protocol.
        self.proc = subprocess.Popen(
            [driver, "--port=%d" % self.spec["port"]],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env,
        )
        deadline = time.monotonic() + 15
        while True:
            try:
                if self.cmd("GET", "/status", timeout=2)["value"].get("ready"):
                    break
            except WdError:
                pass
            if time.monotonic() > deadline:
                raise WdError("driver did not become ready")
            time.sleep(0.2)
        caps = self.spec["caps"](browser, self.tmp)
        reply = self.cmd("POST", "/session", {"capabilities": {"alwaysMatch": caps}})
        self.session = reply["value"]["sessionId"]

    def cmd(self, method, path, body=None, timeout=HTTP_TIMEOUT_S):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            self.base + path, data=data, method=method,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            try:
                value = json.loads(e.read().decode("utf-8", "replace"))["value"]
                message = "%s: %s" % (value.get("error"), value.get("message", ""))
            except Exception:
                message = "HTTP %d" % e.code
            raise WdError(message[:300]) from None
        except Exception as e:
            raise WdError("driver unreachable: %s" % e) from None

    def sess(self, method, path, body=None):
        return self.cmd(method, "/session/%s%s" % (self.session, path), body)

    def navigate(self, url):
        self.sess("POST", "/url", {"url": url})

    def cookies(self):
        return self.sess("GET", "/cookie")["value"]

    def delete_cookies(self):
        self.sess("DELETE", "/cookie")

    def kill(self):
        if self.session:
            try:
                self.cmd("DELETE", "/session/%s" % self.session, timeout=5)
            except WdError:
                pass
        if self.proc:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        if self.tmp:
            shutil.rmtree(self.tmp, ignore_errors=True)


# ── record handling ───────────────────────────────────────────────────────────

COUNTER = iter(range(1, 1 << 30))


def split_url(url):
    scheme, _, rest = url.partition("://")
    host, slash, path = rest.partition("/")
    return scheme, host.lower(), (slash + path) if slash else "/"


def attribute_tokens(wire):
    # The engaged-attribute names: everything after the first `;` (the
    # cookie-pair itself is not an attribute), split and trimmed like §5.2.
    names = set()
    for segment in wire.split(b";")[1:]:
        name = segment.partition(b"=")[0].strip(b" \t")
        names.add(name.decode("latin-1").lower())
    return names


def engaged_paths(wire):
    # Every distinct engaged `Path` value that is absolute and clean ASCII —
    # the candidate cookie-paths a stored cookie may be scoped to (engines may
    # honor the first or the last duplicate, so keep them all). Values with
    # controls/spaces/non-ASCII are left out: engines default those to the
    # request's default-path, which the setting page already covers.
    paths = []
    for segment in wire.split(b";")[1:]:
        name, _, value = segment.partition(b"=")
        if name.strip(b" \t").decode("latin-1").lower() != "path":
            continue
        value = value.strip(b" \t")
        if value.startswith(b"/") and all(0x21 <= b <= 0x7E for b in value):
            decoded = value.decode("ascii")
            if decoded not in paths:
                paths.append(decoded)
    return paths


def await_hit(state, what):
    if not state["event"].wait(8):
        raise WdError("server never saw the %s request" % what)


def set_cookie_view(cookies, engaged):
    if not cookies:
        return None
    # A single Set-Cookie stores at most one cookie in practice; if an engine
    # ever reports more, pick deterministically rather than by driver order.
    c = sorted(cookies, key=lambda c: (c.get("name", ""), c.get("value", "")))[0]
    domain = c.get("domain") or ""
    same_site = c.get("sameSite")
    return {
        "name": c.get("name", ""),
        "value": c.get("value", ""),
        "http_only": bool(c.get("httpOnly")),
        "secure": bool(c.get("secure")),
        # Wire-token-gated (module docstring): the jar holds the ENFORCED
        # SameSite and the EFFECTIVE path, so both report null unless the wire
        # engaged the attribute — an engaged one shows the engine's reading,
        # defaults included. Only Strict/Lax/None are attribute-shaped.
        "same_site": same_site
        if "samesite" in engaged and same_site in ("Strict", "Lax", "None")
        else None,
        "path": (c.get("path") or None) if "path" in engaged else None,
        # The leading-dot convention marks a Domain cookie, exactly like the
        # Netscape-jar mapping in the curl/wget sidecar; host-only → null.
        "domain": domain if domain.startswith(".") else None,
        # The jar folds Expires/Max-Age into one absolute run-time expiry, so
        # both report null and cells never depend on when the matrix ran.
        "max_age": None,
    }


def response_record(engine, wire):
    engaged = attribute_tokens(wire)
    path = "/r/%d" % next(COUNTER)
    state = arm("setcookie", WIRE_HOST, path, wire)
    nav_err = None
    try:
        engine.navigate("https://%s%s" % (WIRE_HOST, path))
        await_hit(state, "origin")
    except WdError as e:
        # An engine may refuse the whole response (e.g. a NUL in the header
        # block) — the navigation error IS the transfer-view finding.
        nav_err = str(e)
    disarm()
    # Readback + cleanup, page by page: the W3C cookie commands see only the
    # current document's cookies, so a cookie the engine scoped to an engaged
    # absolute Path is invisible on the setting page — visit each candidate
    # path too (disarmed → the inert page on the same host), reading and
    # deleting as we go.
    pages = [None] + (engaged_paths(wire) if nav_err is None else [])
    stored, seen = [], set()
    for page in pages:
        try:
            if page is not None:
                engine.navigate("https://%s%s" % (WIRE_HOST, page))
            for c in engine.cookies():
                key = (c.get("name"), c.get("domain"), c.get("path"))
                if key not in seen:
                    seen.add(key)
                    stored.append(c)
            engine.delete_cookies()
        except WdError:
            if nav_err is None and page is None:
                raise  # readback on the setting page must work — engine fault
            engine.taint = True  # never leak state into the next record
    view = set_cookie_view(stored, engaged)
    if view is None:
        return {"outcome": "SetCookieRejected", "error": nav_err or "no cookie accepted"}
    return {"outcome": "SetCookie", "set_cookie": view}


def cookie_pairs(header):
    pairs = []
    for token in header.split(";"):
        token = token.strip(" ")
        if not token:
            continue
        name, _, value = token.partition("=")
        pairs.append({"name": name, "value": value})
    return pairs


def jar_record(engine, wire, origin_url, request_url):
    _, origin_host, origin_path = split_url(origin_url)
    _, request_host, request_path = split_url(request_url)
    # Store: the origin's response carries the wire. Probe wires are clean, so
    # a failed origin navigation is an engine fault, not a finding — let it
    # propagate to a ☠️ on this record.
    state = arm("setcookie", origin_host, origin_path, wire)
    engine.navigate(origin_url)
    await_hit(state, "origin")
    # Retrieve: what the engine attaches is read off the wire by the server.
    state = arm("capture", request_host, request_path)
    engine.navigate(request_url)
    await_hit(state, "request")
    disarm()
    attached = cookie_pairs(state["cookie"]) if state["cookie"] is not None else []
    # Cleanup: the W3C delete is scoped to the current document — for EVERY
    # driver here (chromedriver 149 included, observed; the "deletes all
    # domains" folklore does not hold), and scoped by PATH as well as host.
    # Everything a probe can store is visible from the origin document
    # (host-only on its host, a Domain cookie on a parent) EXCEPT a cookie the
    # engine scoped to an engaged absolute Path — visit each candidate path on
    # the origin host too, deleting as we go (disarmed → the inert page).
    scheme, origin_host, _ = split_url(origin_url)
    cleanup = [origin_url] + [
        "%s://%s%s" % (scheme, origin_host, p) for p in engaged_paths(wire)
    ]
    for url in cleanup:
        try:
            engine.navigate(url)
            engine.delete_cookies()
        except WdError:
            engine.taint = True
    return {"outcome": "Cookies", "cookies": attached}


# ── per-engine dispatch with launch, crash isolation, and relaunch ────────────

LIVE = {}  # name → Engine
DEAD = {}  # name → launch-failure reason (fail fast on later records)


def with_engine(name, fn):
    if name in DEAD:
        return {"outcome": "Crashed", "reason": DEAD[name]}
    engine = LIVE.get(name)
    if engine is None:
        note("launching " + name)
        engine = Engine(name)
        try:
            engine.launch()
        except WdError as e:
            engine.kill()
            # A failed launch on a fresh engine will fail identically on every
            # later record; pin the reason once instead of stalling per record.
            DEAD[name] = "launch failed: %s" % e
            return {"outcome": "Crashed", "reason": DEAD[name]}
        LIVE[name] = engine
    try:
        outcome = fn(engine)
    except Exception as e:
        engine.kill()
        LIVE.pop(name, None)  # a fresh launch (and profile) on the next record
        reason = "%s: %s" % (type(e).__name__, str(e)[:300])
        return {"outcome": "Crashed", "reason": reason}
    if engine.taint:
        engine.kill()
        LIVE.pop(name, None)
    return outcome


# ── selfcheck + main ──────────────────────────────────────────────────────────


def version_of(candidates):
    binary = find(candidates)
    if not binary:
        return "absent"
    try:
        with tempfile.TemporaryDirectory(prefix="kb-ver-") as tmp:
            out = subprocess.run(
                [binary, "--version"], capture_output=True, timeout=20,
                env=dict(os.environ, HOME=tmp),
            )
        first = out.stdout.decode("utf-8", "replace").splitlines()
        return (first[0].strip() if first else "") or "?"
    except Exception:
        return "?"


def selfcheck():
    # The loopback servers need the privileged ports (the DNS remaps carry no
    # port), plus openssl for the throwaway cert — root inside the container;
    # an unprivileged host shell honestly reports every column unavailable.
    servers_ok = (
        shutil.which("openssl") is not None and can_bind(HTTP_PORT) and can_bind(TLS_PORT)
    )
    available = {}
    versions = {"runtime": "browser webdriver driver"}
    for name in ENGINES:
        spec = SPEC[name]
        # `--version` loads the browser's shared libraries, so an install with
        # a missing runtime dependency reports unavailable here — loudly, in
        # the CI smoke step — rather than as per-record crashes in the matrix.
        version = version_of(spec["browser"])
        available[name] = bool(
            servers_ok and find(spec["driver"]) and version not in ("absent", "?")
        )
        versions[name] = version
    print(json.dumps({"available": available, "versions": versions}))
    sys.stdout.flush()


def main():
    if "--selfcheck" in sys.argv:
        selfcheck()
        return
    tmp = tempfile.mkdtemp(prefix="kb-browsers-")
    ready = start_servers(tmp)
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        record = json.loads(line)
        rid = record["id"]
        wire = base64.b64decode(record["wire_b64"])
        direction = record.get("direction")
        by_dep = {}
        if direction not in ("response", "jar"):
            # Requests (browsers emit Cookie headers, they never parse them)
            # and any unrecognized record kind are NotApplicable (PROTOCOL.md).
            by_dep = {name: {"outcome": "NotApplicable"} for name in ENGINES}
        elif not ready:
            by_dep = {name: {"outcome": "Skipped"} for name in ENGINES}
        else:
            for name in ENGINES:
                if direction == "response":
                    by_dep[name] = with_engine(name, lambda e: response_record(e, wire))
                else:
                    by_dep[name] = with_engine(
                        name,
                        lambda e: jar_record(
                            e, wire, record["origin_url"], record["request_url"]
                        ),
                    )
                if name != ENGINES[-1]:
                    # Keep the harness's inactivity timer fed between engine
                    # segments; the note also documents progress on a crash.
                    note("%s: %s done" % (rid, name))
        emit({"id": rid, "by_dep": by_dep})
    for engine in LIVE.values():
        engine.kill()


if __name__ == "__main__":
    main()
