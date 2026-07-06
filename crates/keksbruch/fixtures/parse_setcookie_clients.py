#!/usr/bin/env python3
"""keksbruch HTTP-client Set-Cookie sidecar (curl + wget, the transfer view).

Two columns — the real `curl` and `wget` command-line clients. Unlike the offline
c/libcurl injection column, these see a cookie the way a client does on the wire: a
tiny loopback server replies `Set-Cookie: <wire>`, the client fetches it and writes
the accepted cookie to a Netscape cookie jar, which we read back.

Because the response comes from 127.0.0.1, a host-only Set-Cookie (no Domain) is
accepted and attached to that host — so these columns parse host-only cookies that
c/libcurl's injection drops. Conversely a `Domain=` that does not match 127.0.0.1
(e.g. a public-suffix supercookie probe) is refused by the client's domain-match,
so those rows show a rejection here while c/libcurl parses them. The two views are
complementary on purpose.

Request direction is n/a (these parse Set-Cookie responses, not Cookie requests).
Protocol: ./PROTOCOL.md. One result line per record, stdout flushed each line.
"""
import sys
import json
import base64
import socket
import threading
import subprocess
import tempfile
import os
import shutil


def have(cmd):
    return shutil.which(cmd) is not None


def version_of(cmd):
    try:
        out = subprocess.run([cmd, "--version"], capture_output=True, timeout=5)
        first = out.stdout.decode("utf-8", "replace").splitlines()[0].strip()
        return first or "?"
    except Exception:
        return "?"


def selfcheck():
    available = {"curl": have("curl"), "wget": have("wget")}
    versions = {
        "runtime": "shell client driver",
        "curl": version_of("curl") if available["curl"] else "absent",
        "wget": version_of("wget") if available["wget"] else "absent",
    }
    print(json.dumps({"available": available, "versions": versions}))
    sys.stdout.flush()


# ── loopback server: GET /<urlsafe-b64 of wire> → reply `Set-Cookie: <wire>` ──
# A raw socket server (not http.server) so the Set-Cookie bytes go out verbatim,
# including CR/LF/NUL/controls — the client then meets the exact malformed wire.
def start_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(16)
    port = srv.getsockname()[1]

    def handle(conn):
        try:
            conn.settimeout(2.0)
            req = b""
            while b"\r\n\r\n" not in req:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                req += chunk
            line = req.split(b"\r\n", 1)[0]
            parts = line.split(b" ")
            path = parts[1] if len(parts) >= 2 else b"/"
            b64 = path.lstrip(b"/")
            try:
                wire = base64.urlsafe_b64decode(b64 + b"=" * (-len(b64) % 4))
            except Exception:
                wire = b""
            body = b"ok"
            resp = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                b"Set-Cookie: " + wire + b"\r\n"
                b"Connection: close\r\n\r\n" + body
            )
            conn.sendall(resp)
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def serve():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=handle, args=(conn,), daemon=True).start()

    threading.Thread(target=serve, daemon=True).start()
    return srv, port


def url_for(port, wire):
    token = base64.urlsafe_b64encode(wire).rstrip(b"=").decode("ascii")
    return "http://127.0.0.1:%d/%s" % (port, token)


# Parse a Netscape cookie jar: return the first cookie as a SetCookieView dict, or
# None if the jar holds no cookie (the client accepted nothing). Fields:
# domain, includeSubdomains, path, secure, expiry, name, value; a `#HttpOnly_`
# prefix marks HttpOnly. The includeSubdomains flag is TRUE exactly when a `Domain`
# attribute was present, so a host-only cookie (FALSE) reports domain=null — the
# Domain *attribute*, comparable to the pure parsers (not the effective host).
def parse_jar(path):
    try:
        with open(path, "r", encoding="latin-1") as f:
            lines = f.read().splitlines()
    except Exception:
        return None
    for raw in lines:
        line = raw
        http_only = False
        if line.startswith("#HttpOnly_"):
            http_only = True
            line = line[len("#HttpOnly_"):]
        elif line.startswith("#") or line.strip() == "":
            continue
        f = line.split("\t")
        if len(f) < 7:
            continue
        domain_attr = (f[1] == "TRUE")
        return {
            "name": f[5],
            "value": f[6],
            "http_only": http_only,
            "secure": (f[3] == "TRUE"),
            "same_site": None,  # not represented in the Netscape format
            "path": f[2] if f[2] else None,
            "domain": f[0] if domain_attr else None,
            "max_age": None,  # the jar keeps an absolute expiry, not the raw Max-Age
        }
    return None


def run_client(argv, jar):
    try:
        subprocess.run(argv, capture_output=True, timeout=10)
    except subprocess.TimeoutExpired:
        return {"outcome": "SetCookieRejected", "error": "client timed out"}
    except Exception as e:
        return {"outcome": "SetCookieRejected", "error": type(e).__name__ + ": " + str(e)}
    cookie = parse_jar(jar)
    if cookie is None:
        return {"outcome": "SetCookieRejected", "error": "no cookie accepted"}
    return {"outcome": "SetCookie", "set_cookie": cookie}


def curl_response(port, wire, have_curl):
    if not have_curl:
        return {"outcome": "Skipped"}
    jar = tempfile.mktemp(prefix="kb-curl-", suffix=".jar")
    try:
        return run_client(
            ["curl", "-s", "-o", os.devnull, "--cookie-jar", jar, url_for(port, wire)], jar
        )
    finally:
        _rm(jar)


def wget_response(port, wire, have_wget):
    if not have_wget:
        return {"outcome": "Skipped"}
    jar = tempfile.mktemp(prefix="kb-wget-", suffix=".jar")
    try:
        # --keep-session-cookies so a session cookie (expiry 0) is still written.
        return run_client(
            ["wget", "-q", "-O", os.devnull, "--save-cookies", jar,
             "--keep-session-cookies", url_for(port, wire)], jar
        )
    finally:
        _rm(jar)


def _rm(path):
    try:
        os.remove(path)
    except OSError:
        pass


def main():
    if "--selfcheck" in sys.argv:
        selfcheck()
        return
    have_curl, have_wget = have("curl"), have("wget")
    _srv, port = start_server()
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        record = json.loads(line)
        wire = base64.b64decode(record["wire_b64"])
        if record["direction"] == "response":
            by_dep = {"curl": curl_response(port, wire, have_curl),
                      "wget": wget_response(port, wire, have_wget)}
        else:
            # Requests — and any unrecognized record kind, e.g. protocol v2 "jar"
            # probes (no jar-replay mode here yet) — are NotApplicable (PROTOCOL.md).
            by_dep = {"curl": {"outcome": "NotApplicable"},
                      "wget": {"outcome": "NotApplicable"}}
        print(json.dumps({"id": record["id"], "by_dep": by_dep}))
        sys.stdout.flush()


main()
