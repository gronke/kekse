#!/usr/bin/env node
// keksbruch Node sidecar.
//
// Reads base64-JSONL payload records on stdin and parses each with five npm cookie
// libraries, emitting one normalized JSONL result per line. The columns:
//   - cookie (request): jshttp's `cookie` — request Cookie-header parsing.
//   - tough-cookie (response): RFC 6265 client Set-Cookie parsing.
//   - set-cookie-parser (response): a dedicated Set-Cookie parser.
//   - universal-cookie (request): the parser behind react-cookie (SPA stacks); a
//     header string in, `getAll` out (doNotParse, so values stay raw strings).
//   - js-cookie (request): the popular browser library, driven headless via a
//     `document.cookie` stub.
// `--selfcheck` reports which comparators can be required, then exits.
//
// Protocol in:  {"id","direction":"request"|"response","wire_b64"}
// Protocol out: {"id","by_dep":{"<dep>":{"outcome":...}}}
// Full contract: ./PROTOCOL.md.
"use strict";

const readline = require("readline");

function have(mod) {
  try {
    require.resolve(mod);
    return true;
  } catch (e) {
    return false;
  }
}

function ver(mod) {
  try {
    return require(mod + "/package.json").version;
  } catch (e) {
    // Some packages' `exports` map blocks the `./package.json` subpath (e.g.
    // set-cookie-parser v3); fall back to locating the package's own package.json
    // by walking up from its resolved entry point.
    try {
      const fs = require("fs");
      const path = require("path");
      let dir = path.dirname(require.resolve(mod));
      for (let i = 0; i < 10; i++) {
        const pj = path.join(dir, "package.json");
        if (fs.existsSync(pj)) {
          const meta = JSON.parse(fs.readFileSync(pj, "utf8"));
          if (meta.name === mod) return meta.version;
        }
        const parent = path.dirname(dir);
        if (parent === dir) break;
        dir = parent;
      }
    } catch (e2) {
      // fall through
    }
    return null;
  }
}

// Column order matches the SidecarSpec deps in src/differential/sidecar.rs.
const DEPS = ["cookie", "tough-cookie", "set-cookie-parser", "universal-cookie", "js-cookie"];

function selfcheck() {
  const available = {};
  const versions = { runtime: "Node " + process.version.replace(/^v/, "") };
  for (const d of DEPS) {
    available[d] = have(d);
    versions[d] = ver(d) || "?";
  }
  process.stdout.write(JSON.stringify({ available, versions }) + "\n");
}

// `cookie` parses a request Cookie header into name=value pairs.
function cookieRequest(wire) {
  try {
    const cookie = require("cookie");
    const obj = cookie.parse(wire.toString("latin1"));
    const cookies = Object.keys(obj).map((k) => ({ name: k, value: obj[k] }));
    return { outcome: "Cookies", cookies };
  } catch (e) {
    return { outcome: "Rejected", error: String((e && e.message) || e) };
  }
}

// `tough-cookie` parses one Set-Cookie line (RFC 6265 client semantics).
function toughResponse(wire) {
  try {
    const { Cookie } = require("tough-cookie");
    const c = Cookie.parse(wire.toString("latin1"));
    if (!c) return { outcome: "SetCookieRejected", error: "parse returned undefined" };
    return {
      outcome: "SetCookie",
      set_cookie: {
        name: c.key,
        value: c.value,
        http_only: !!c.httpOnly,
        secure: !!c.secure,
        // tough-cookie keeps unrecognized attributes verbatim in `.extensions`
        // (["Partitioned"], ["pArTiTiOnEd=false"]) — scan bare-or-valued,
        // case-insensitively, the way engines match attribute names.
        partitioned: Array.isArray(c.extensions)
          ? c.extensions.some((e) => /^partitioned($|=)/i.test(String(e)))
          : false,
        same_site: c.sameSite || null,
        path: c.path || null,
        domain: c.domain || null,
        max_age: typeof c.maxAge === "number" && isFinite(c.maxAge) ? c.maxAge : null,
        // tough-cookie keeps `.expires` as the parsed Expires date (distinct from maxAge).
        expires: c.expires instanceof Date ? Math.floor(c.expires.getTime() / 1000) : null,
      },
    };
  } catch (e) {
    return { outcome: "SetCookieRejected", error: String((e && e.message) || e) };
  }
}

// tough-cookie as a *jar* (protocol v2 "jar" records): store the Set-Cookie as if
// received from origin_url, then report the cookies the jar would attach to a
// request to request_url. An empty list means "not sent" — a storage refusal
// (domain mismatch, public suffix) and a match failure read the same, per PROTOCOL.md.
function toughJarProbe(wire, originUrl, requestUrl) {
  try {
    const { CookieJar } = require("tough-cookie");
    const jar = new CookieJar();
    try {
      jar.setCookieSync(wire.toString("latin1"), originUrl);
    } catch (e) {
      return { outcome: "Cookies", cookies: [] };
    }
    const cookies = jar
      .getCookiesSync(requestUrl)
      .map((c) => ({ name: c.key, value: c.value }));
    return { outcome: "Cookies", cookies };
  } catch (e) {
    return { outcome: "Rejected", error: String((e && e.message) || e) };
  }
}

// `set-cookie-parser` parses one Set-Cookie string; absent attributes are omitted.
function setCookieParserResponse(wire) {
  try {
    const scp = require("set-cookie-parser");
    const c = scp.parseString(wire.toString("latin1"));
    if (!c || !c.name) {
      return { outcome: "SetCookieRejected", error: "no cookie parsed" };
    }
    return {
      outcome: "SetCookie",
      set_cookie: {
        name: c.name,
        value: c.value == null ? "" : c.value,
        http_only: !!c.httpOnly,
        secure: !!c.secure,
        // set-cookie-parser models the flag natively (case-insensitive, presence-only).
        partitioned: !!c.partitioned,
        same_site: c.sameSite || null,
        path: c.path || null,
        domain: c.domain || null,
        max_age: typeof c.maxAge === "number" && isFinite(c.maxAge) ? c.maxAge : null,
        // set-cookie-parser exposes `.expires` as the parsed Expires date, when present.
        expires: c.expires instanceof Date ? Math.floor(c.expires.getTime() / 1000) : null,
      },
    };
  } catch (e) {
    return { outcome: "SetCookieRejected", error: String((e && e.message) || e) };
  }
}

// `universal-cookie` (the engine behind react-cookie) parses a request Cookie
// header string. doNotParse keeps values as raw strings (it otherwise JSON-decodes
// `a=1` to the number 1), so the column is comparable to the others.
function universalCookieRequest(wire) {
  try {
    const UniversalCookie = require("universal-cookie");
    const uc = new UniversalCookie(wire.toString("latin1"));
    const all = uc.getAll({ doNotParse: true });
    const cookies = Object.keys(all).map((k) => ({ name: k, value: String(all[k]) }));
    return { outcome: "Cookies", cookies };
  } catch (e) {
    return { outcome: "Rejected", error: String((e && e.message) || e) };
  }
}

// `js-cookie` is a browser library that reads `document.cookie`; drive it headless
// by stubbing that global with the request wire, then reading all cookies back.
function jsCookieRequest(wire) {
  try {
    global.document = { cookie: wire.toString("latin1") };
    const Cookies = require("js-cookie");
    const obj = Cookies.get();
    const cookies = Object.keys(obj).map((k) => ({ name: k, value: obj[k] }));
    return { outcome: "Cookies", cookies };
  } catch (e) {
    return { outcome: "Rejected", error: String((e && e.message) || e) };
  }
}

function main() {
  if (process.argv.includes("--selfcheck")) {
    selfcheck();
    return;
  }
  const avail = {};
  for (const d of DEPS) avail[d] = have(d);
  const skip = { outcome: "Skipped" };
  const na = { outcome: "NotApplicable" };
  const rl = readline.createInterface({ input: process.stdin, terminal: false });
  rl.on("line", (line) => {
    line = line.trim();
    if (!line) return;
    const record = JSON.parse(line);
    const wire = Buffer.from(record.wire_b64, "base64");
    let by_dep;
    if (record.direction === "request") {
      by_dep = {
        cookie: avail["cookie"] ? cookieRequest(wire) : skip,
        "tough-cookie": na,
        "set-cookie-parser": na,
        "universal-cookie": avail["universal-cookie"] ? universalCookieRequest(wire) : skip,
        "js-cookie": avail["js-cookie"] ? jsCookieRequest(wire) : skip,
      };
    } else if (record.direction === "response") {
      by_dep = {
        cookie: na,
        "tough-cookie": avail["tough-cookie"] ? toughResponse(wire) : skip,
        "set-cookie-parser": avail["set-cookie-parser"] ? setCookieParserResponse(wire) : skip,
        "universal-cookie": na,
        "js-cookie": na,
      };
    } else if (record.direction === "jar") {
      by_dep = {
        cookie: na,
        "tough-cookie": avail["tough-cookie"]
          ? toughJarProbe(wire, record.origin_url, record.request_url)
          : skip,
        "set-cookie-parser": na,
        "universal-cookie": na,
        "js-cookie": na,
      };
    } else {
      // An unrecognized record kind (a newer protocol than this checkout):
      // NotApplicable across the board, per PROTOCOL.md.
      by_dep = {};
      for (const d of DEPS) by_dep[d] = na;
    }
    process.stdout.write(JSON.stringify({ id: record.id, by_dep }) + "\n");
  });
}

main();
