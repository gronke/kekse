#!/usr/bin/env python3
"""keksbruch Python sidecar.

Reads base64-JSONL payload records on stdin, parses each with the stdlib
``http.cookies.SimpleCookie`` and (when available) Werkzeug, and emits one
normalized JSONL result per line. ``--selfcheck`` reports which comparators
can be loaded, then exits.

Protocol in:  {"id","direction":"request"|"response","wire_b64"}
Protocol out: {"id","by_dep":{"<dep>":{"outcome":...}}}
"""
import sys
import json
import base64


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


def selfcheck():
    available = {"SimpleCookie": True, "Werkzeug": have_werkzeug()}
    runtime = "Python %d.%d.%d" % (
        sys.version_info.major,
        sys.version_info.minor,
        sys.version_info.micro,
    )
    versions = {
        "runtime": runtime,
        "SimpleCookie": "stdlib",
        "Werkzeug": werkzeug_version() or "?",
    }
    print(json.dumps({"available": available, "versions": versions}))


def simplecookie_request(wire):
    from http.cookies import SimpleCookie, CookieError
    try:
        jar = SimpleCookie()
        jar.load(wire.decode("latin-1"))
        return {"outcome": "Cookies",
                "cookies": [{"name": k, "value": m.value} for k, m in jar.items()]}
    except CookieError as e:
        return {"outcome": "Rejected", "error": "CookieError: " + str(e)}
    except Exception as e:
        return {"outcome": "Rejected", "error": type(e).__name__ + ": " + str(e)}


def _flag(morsel, key):
    # SimpleCookie stores valueless flags as "" when absent, the token when present.
    return bool(morsel[key])


def _opt(morsel, key):
    value = morsel[key]
    return value if value else None


def simplecookie_response(wire):
    from http.cookies import SimpleCookie, CookieError
    try:
        jar = SimpleCookie()
        jar.load(wire.decode("latin-1"))
        items = list(jar.items())
        if not items:
            return {"outcome": "SetCookieRejected", "error": "no cookie parsed"}
        name, morsel = items[0]
        raw_max_age = str(morsel["max-age"])
        max_age = int(raw_max_age) if raw_max_age.lstrip("-").isdigit() else None
        return {"outcome": "SetCookie", "set_cookie": {
            "name": name,
            "value": morsel.value,
            "http_only": _flag(morsel, "httponly"),
            "secure": _flag(morsel, "secure"),
            "same_site": _opt(morsel, "samesite"),
            "path": _opt(morsel, "path"),
            "domain": _opt(morsel, "domain"),
            "max_age": max_age,
        }}
    except CookieError as e:
        return {"outcome": "SetCookieRejected", "error": "CookieError: " + str(e)}
    except Exception as e:
        return {"outcome": "SetCookieRejected", "error": type(e).__name__}


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
        return {"outcome": "Rejected", "error": type(e).__name__}


def main():
    if "--selfcheck" in sys.argv:
        selfcheck()
        return
    werkzeug = have_werkzeug()
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        record = json.loads(line)
        wire = base64.b64decode(record["wire_b64"])
        if record["direction"] == "request":
            by_dep = {
                "SimpleCookie": simplecookie_request(wire),
                "Werkzeug": werkzeug_request(wire) if werkzeug else {"outcome": "Skipped"},
            }
        else:
            by_dep = {
                "SimpleCookie": simplecookie_response(wire),
                "Werkzeug": {"outcome": "NotApplicable"},
            }
        print(json.dumps({"id": record["id"], "by_dep": by_dep}))
        sys.stdout.flush()


main()
