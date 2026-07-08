#!/usr/bin/env python3
"""keksbruch Python sidecar.

Reads base64-JSONL payload records on stdin, parses each with the stdlib
``http.cookies.SimpleCookie``, the stdlib client jar ``http.cookiejar.CookieJar``
(Set-Cookie only), Werkzeug (request only), and mitmproxy's
``mitmproxy.net.http.cookies`` (both directions — the proxy's own Set-Cookie
parser), and emits one normalized JSONL result per line. ``--selfcheck`` reports
which comparators can be loaded, then exits.

Protocol in:  {"id","direction":"request"|"response","wire_b64"}
Protocol out: {"id","by_dep":{"<dep>":{"outcome":...}}}
Full contract: ./PROTOCOL.md.
"""
import sys
import os
import json
import base64

# CI installs Werkzeug + mitmproxy into a bind-mounted `.pydeps` next to this script
# (`pip install --target`, in the same python image), so the sidecar can run under
# `--network=none` and still import them. Prepend it to the path; harmless when absent
# (local runs resolve from the host interpreter / a crate-local .venv instead).
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".pydeps"))


def have_werkzeug():
    try:
        from werkzeug.http import parse_cookie  # noqa: F401
        return True
    except Exception:
        return False


def werkzeug_version():
    try:
        from importlib.metadata import version
        return version("werkzeug")
    except Exception:
        return None


def have_mitmproxy():
    try:
        from mitmproxy.net.http import cookies  # noqa: F401
        return True
    except Exception:
        return False


def mitmproxy_version():
    try:
        from importlib.metadata import version
        return version("mitmproxy")
    except Exception:
        return None


def have_cookiejar():
    try:
        import http.cookiejar  # noqa: F401
        return True
    except Exception:
        return False


def selfcheck():
    available = {
        "SimpleCookie": True,
        "http.cookiejar": have_cookiejar(),
        "Werkzeug": have_werkzeug(),
        "mitmproxy": have_mitmproxy(),
    }
    runtime = "Python %d.%d.%d" % (
        sys.version_info.major,
        sys.version_info.minor,
        sys.version_info.micro,
    )
    versions = {
        "runtime": runtime,
        "SimpleCookie": "stdlib",
        "http.cookiejar": "stdlib",
        "Werkzeug": werkzeug_version() or "?",
        "mitmproxy": mitmproxy_version() or "?",
    }
    print(json.dumps({"available": available, "versions": versions}))


def simplecookie_request(wire):
    from http.cookies import SimpleCookie, CookieError
    jar = SimpleCookie()
    try:
        jar.load(wire.decode("latin-1"))
    except CookieError as e:
        # load() applies morsels one by one and raises at the first illegal
        # key, keeping what it had already accepted — report that salvage on
        # the issue channel; reject only when nothing landed. (The *silent*
        # abort on an unknown bare flag discards everything before this point
        # and raises nothing, so it stays a bare rejection below.)
        cookies = [{"name": k, "value": m.value} for k, m in jar.items()]
        if cookies:
            return {"outcome": "Cookies", "cookies": cookies,
                    "issues": ["CookieError: " + str(e)]}
        return {"outcome": "Rejected", "error": "CookieError: " + str(e)}
    except Exception as e:
        return {"outcome": "Rejected", "error": type(e).__name__ + ": " + str(e)}
    return {"outcome": "Cookies",
            "cookies": [{"name": k, "value": m.value} for k, m in jar.items()]}


def _flag(morsel, key):
    # SimpleCookie stores valueless flags as "" when absent, the token when present.
    return bool(morsel[key])


def _opt(morsel, key):
    value = morsel[key]
    return value if value else None


def _simplecookie_view(name, morsel):
    raw_max_age = str(morsel["max-age"])
    max_age = int(raw_max_age) if raw_max_age.lstrip("-").isdigit() else None
    return {
        "name": name,
        "value": morsel.value,
        "http_only": _flag(morsel, "httponly"),
        "secure": _flag(morsel, "secure"),
        "same_site": _opt(morsel, "samesite"),
        "path": _opt(morsel, "path"),
        "domain": _opt(morsel, "domain"),
        "max_age": max_age,
    }


def simplecookie_response(wire):
    from http.cookies import SimpleCookie, CookieError
    jar = SimpleCookie()
    issues = []
    try:
        jar.load(wire.decode("latin-1"))
    except CookieError as e:
        # Same salvage stance as the request side: keep what load() had
        # already applied, witness the failure.
        issues = ["CookieError: " + str(e)]
    except Exception as e:
        return {"outcome": "SetCookieRejected", "error": type(e).__name__ + ": " + str(e)}
    items = list(jar.items())
    if not items:
        if issues:
            return {"outcome": "SetCookieRejected", "error": issues[0]}
        return {"outcome": "SetCookieRejected", "error": "no cookie parsed"}
    name, morsel = items[0]
    out = {"outcome": "SetCookie", "set_cookie": _simplecookie_view(name, morsel)}
    if issues:
        out["issues"] = issues
    return out


def cookiejar_response(wire):
    # http.cookiejar is a client jar: extract_cookies(response, request) needs response- and
    # request-like objects, so build a fake response carrying the Set-Cookie header and parse
    # it against https://example.com/. The jar then applies its domain-match policy (a
    # public-suffix or mismatched Domain is refused, like a browser). Report the Domain/Path
    # *attributes* (domain_specified/path_specified) — not the effective host — to compare
    # with the other columns. It keeps an absolute expiry, not a raw Max-Age, so max_age=null.
    try:
        import http.cookiejar
        import urllib.request
        import email.message
        jar = http.cookiejar.CookieJar()
        req = urllib.request.Request("https://example.com/")
        msg = email.message.Message()
        msg["Set-Cookie"] = wire.decode("latin-1")

        class FakeResponse:
            def info(self_inner):
                return msg

        jar.extract_cookies(FakeResponse(), req)
        cookies = list(jar)
        if not cookies:
            return {"outcome": "SetCookieRejected", "error": "no cookie accepted"}
        c = cookies[0]
        return {"outcome": "SetCookie", "set_cookie": {
            "name": c.name,
            "value": c.value if c.value is not None else "",
            "http_only": bool(c.has_nonstandard_attr("HttpOnly") or c.has_nonstandard_attr("httponly")),
            "secure": bool(c.secure),
            "partitioned": bool(c.has_nonstandard_attr("Partitioned") or c.has_nonstandard_attr("partitioned")),
            "same_site": c.get_nonstandard_attr("SameSite") or c.get_nonstandard_attr("samesite"),
            "path": c.path if c.path_specified else None,
            "domain": c.domain if c.domain_specified else None,
            "max_age": None,
        }}
    except Exception as e:
        return {"outcome": "SetCookieRejected", "error": type(e).__name__ + ": " + str(e)}


def cookiejar_probe(wire, origin_url, request_url):
    # Protocol v2 "jar": store the Set-Cookie as if received from origin_url, then report
    # the cookies the jar would attach to a request to request_url (see PROTOCOL.md). An
    # empty list means "not sent" — a storage refusal and a match failure read the same.
    try:
        import http.cookiejar
        import urllib.request
        import email.message
        jar = http.cookiejar.CookieJar()
        origin = urllib.request.Request(origin_url)
        msg = email.message.Message()
        msg["Set-Cookie"] = wire.decode("latin-1")

        class FakeResponse:
            def info(self_inner):
                return msg

        jar.extract_cookies(FakeResponse(), origin)
        request = urllib.request.Request(request_url)
        jar.add_cookie_header(request)
        header = request.get_header("Cookie")
        cookies = []
        if header:
            for part in header.split("; "):
                name, _, value = part.partition("=")
                cookies.append({"name": name, "value": value})
        return {"outcome": "Cookies", "cookies": cookies}
    except Exception as e:
        return {"outcome": "Rejected", "error": type(e).__name__ + ": " + str(e)}


def werkzeug_request(wire):
    try:
        from werkzeug.http import parse_cookie
        parsed = parse_cookie(wire.decode("latin-1"))
        try:
            items = list(parsed.items(multi=True))
        except TypeError:
            items = list(parsed.items())
        return {"outcome": "Cookies",
                "cookies": [{"name": k, "value": v} for k, v in items]}
    except Exception as e:
        return {"outcome": "Rejected", "error": type(e).__name__ + ": " + str(e)}


def mitmproxy_request(wire):
    # mitmproxy.net.http.cookies.parse_cookie_header(str) -> [(name, value|None), ...]
    try:
        from mitmproxy.net.http import cookies
        pairs = cookies.parse_cookie_header(wire.decode("latin-1"))
        return {"outcome": "Cookies",
                "cookies": [{"name": n, "value": v or ""} for (n, v) in pairs]}
    except Exception as e:
        return {"outcome": "Rejected", "error": type(e).__name__ + ": " + str(e)}


def mitmproxy_response(wire):
    # parse_set_cookie_header(str) -> [(name, value|None, CookieAttrs)] (a list; one
    # entry per cookie). CookieAttrs is a case-insensitive multidict: valueless flags
    # (Secure/HttpOnly) are present with a None value, valued attrs carry a string.
    try:
        from mitmproxy.net.http import cookies
        parsed = cookies.parse_set_cookie_header(wire.decode("latin-1"))
        if isinstance(parsed, list):
            parsed = parsed[0] if parsed else None
        if parsed is None:
            return {"outcome": "SetCookieRejected", "error": "no cookie parsed"}
        name, value, attrs = parsed
        raw_max_age = attrs.get("max-age")
        try:
            max_age = int(raw_max_age) if raw_max_age is not None else None
        except (TypeError, ValueError):
            max_age = None
        return {"outcome": "SetCookie", "set_cookie": {
            "name": name,
            "value": value or "",
            "http_only": "httponly" in attrs,
            "secure": "secure" in attrs,
            "partitioned": "partitioned" in attrs,
            "same_site": attrs.get("samesite"),
            "path": attrs.get("path"),
            "domain": attrs.get("domain"),
            "max_age": max_age,
        }}
    except Exception as e:
        return {"outcome": "SetCookieRejected", "error": type(e).__name__ + ": " + str(e)}


def main():
    if "--selfcheck" in sys.argv:
        selfcheck()
        return
    werkzeug = have_werkzeug()
    mitmproxy = have_mitmproxy()
    cookiejar = have_cookiejar()
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        record = json.loads(line)
        wire = base64.b64decode(record["wire_b64"])
        na = {"outcome": "NotApplicable"}
        if record["direction"] == "request":
            by_dep = {
                "SimpleCookie": simplecookie_request(wire),
                "http.cookiejar": na,
                "Werkzeug": werkzeug_request(wire) if werkzeug else {"outcome": "Skipped"},
                "mitmproxy": mitmproxy_request(wire) if mitmproxy else {"outcome": "Skipped"},
            }
        elif record["direction"] == "response":
            by_dep = {
                "SimpleCookie": simplecookie_response(wire),
                "http.cookiejar": cookiejar_response(wire) if cookiejar else {"outcome": "Skipped"},
                "Werkzeug": na,
                "mitmproxy": mitmproxy_response(wire) if mitmproxy else {"outcome": "Skipped"},
            }
        elif record["direction"] == "jar":
            by_dep = {
                "SimpleCookie": na,
                "http.cookiejar": cookiejar_probe(wire, record["origin_url"], record["request_url"])
                if cookiejar
                else {"outcome": "Skipped"},
                "Werkzeug": na,
                "mitmproxy": na,
            }
        else:
            # An unrecognized record kind (a newer protocol than this checkout):
            # NotApplicable across the board, per PROTOCOL.md.
            by_dep = {d: na for d in ("SimpleCookie", "http.cookiejar", "Werkzeug", "mitmproxy")}
        print(json.dumps({"id": record["id"], "by_dep": by_dep}))
        sys.stdout.flush()


main()
