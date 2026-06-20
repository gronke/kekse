#!/usr/bin/env node
// keksbruch Node sidecar.
//
// Reads base64-JSONL payload records on stdin, parses each request header with
// the `cookie` package and each Set-Cookie with `tough-cookie`, and emits one
// normalized JSONL result per line. `--selfcheck` reports which comparators can
// be required, then exits.
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
    return null;
  }
}

function selfcheck() {
  const available = { cookie: have("cookie"), "tough-cookie": have("tough-cookie") };
  const versions = {
    runtime: "Node " + process.version.replace(/^v/, ""),
    cookie: ver("cookie") || "?",
    "tough-cookie": ver("tough-cookie") || "?",
  };
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
        same_site: c.sameSite || null,
        path: c.path || null,
        domain: c.domain || null,
        max_age: typeof c.maxAge === "number" && isFinite(c.maxAge) ? c.maxAge : null,
      },
    };
  } catch (e) {
    return { outcome: "SetCookieRejected", error: String((e && e.message) || e) };
  }
}

function main() {
  if (process.argv.includes("--selfcheck")) {
    selfcheck();
    return;
  }
  const haveCookie = have("cookie");
  const haveTough = have("tough-cookie");
  const rl = readline.createInterface({ input: process.stdin, terminal: false });
  rl.on("line", (line) => {
    line = line.trim();
    if (!line) return;
    const record = JSON.parse(line);
    const wire = Buffer.from(record.wire_b64, "base64");
    let by_dep;
    if (record.direction === "request") {
      by_dep = {
        cookie: haveCookie ? cookieRequest(wire) : { outcome: "Skipped" },
        "tough-cookie": { outcome: "NotApplicable" },
      };
    } else {
      by_dep = {
        cookie: { outcome: "NotApplicable" },
        "tough-cookie": haveTough ? toughResponse(wire) : { outcome: "Skipped" },
      };
    }
    process.stdout.write(JSON.stringify({ id: record.id, by_dep }) + "\n");
  });
}

main();
