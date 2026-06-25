-- keksbruch nginx sidecar (run by the OpenResty `resty` CLI).
--
-- Mirrors parse_cookies.php: it boots a real server — here one openresty nginx on
-- two loopback ports — and replays each wire to it over a raw cosocket, so nginx's
-- *native* handling is what is tested. Four columns:
--   $cookie_<name>   (request) nginx's native by-name lookup (ngx.var.cookie_<name>).
--   lua-resty-cookie (request) the vendored Lua library's parse (resty.cookie:get_all()).
--   proxy            (request) forwarding fidelity: did `proxy_pass` forward the Cookie
--                    verbatim (≡), altered (≠), or refuse it (❌)?
--   proxy (Set-Cookie) (response) the same fidelity question for an upstream Set-Cookie
--                    a proxy_pass forwards back — nginx exposes no *parsed* Set-Cookie to
--                    Lua, so this is a forwarding verdict, not a parse. The first three
--                    are request-only (→ n/a on responses); this one is response-only.
--
-- This is a driver: it speaks the sidecar protocol on stdin/stdout, while the
-- nginx it boots does the parsing/forwarding. See ./PROTOCOL.md for the contract.
--
-- Protocol in:  {"id","direction":"request"|"response","wire_b64"}
-- Protocol out: {"id","by_dep":{"$cookie_<name>":…,"lua-resty-cookie":…,"proxy":…,"proxy (Set-Cookie)":…}}

local cjson = require "cjson"
-- cjson encodes an empty Lua table as `{}`; the `cookies` field must be a JSON
-- array even when empty, so an empty parse deserializes as `Cookies{cookies:[]}`.
pcall(function() cjson.encode_empty_table_as_object(false) end)

local byte, char, floor = string.byte, string.char, math.floor

-- Raw bytes → a latin-1 string widened to UTF-8 (each byte one codepoint), so a
-- non-UTF-8 wire renders as the same mojibake as the py/node/php sidecars and the
-- output is always valid UTF-8 for JSON. Mirrors parse_cookies.php's latin1_to_utf8.
local function l1_to_utf8(s)
    local out = {}
    for i = 1, #s do
        local b = byte(s, i)
        if b < 0x80 then
            out[#out + 1] = char(b)
        else
            out[#out + 1] = char(0xC0 + floor(b / 0x40)) .. char(0x80 + (b % 0x40))
        end
    end
    return table.concat(out)
end

-- Where the fixtures live (for the vendored lib's package path and the scratch
-- prefix): the dir of this script (resty sets arg[0] to the file path), else cwd.
local function detect_fixtures_dir()
    local p = arg and arg[0]
    if type(p) == "string" and p:find("/") then
        return (p:gsub("/[^/]*$", ""))
    end
    local pwd = os.getenv("PWD")
    if pwd and #pwd > 0 then
        return pwd
    end
    return "."
end

local FIXTURES = detect_fixtures_dir()
local PREFIX = FIXTURES .. "/.nginx-run"
local CONF = PREFIX .. "/conf/nginx.conf"

-- Read the vendored lua-resty-cookie's _VERSION for the footer (loading it here is
-- harmless — it only binds ngx.* upvalues; get_all is exercised inside nginx).
package.path = FIXTURES .. "/lua/?.lua;" .. package.path
local ck_ok, ck_lib = pcall(require, "resty.cookie")
local RESTY_VERSION = (ck_ok and ck_lib and ck_lib._VERSION) or "?"

-- Locate the openresty nginx binary. Prefer the openresty-named binaries over a
-- bare `nginx` — a plain distro nginx (no lua-nginx-module) would start but reject
-- the content_by_lua config. In the official image `openresty` is on PATH; a host
-- with both a plain nginx and openresty installed still resolves to openresty.
local function find_nginx()
    local candidates = { "openresty", "/usr/local/openresty/nginx/sbin/nginx", "nginx" }
    for _, c in ipairs(candidates) do
        local ok = os.execute(c .. " -v >/dev/null 2>&1")
        if ok == true or ok == 0 then
            return c
        end
    end
    return nil
end

local NGINX = find_nginx()

local function openresty_version()
    if not NGINX then
        return "OpenResty (absent)"
    end
    local h = io.popen(NGINX .. " -v 2>&1")
    local out = h and h:read("*a") or ""
    if h then h:close() end
    local v = out:match("openresty/([%w%.]+)")
    if v then
        return "OpenResty " .. v
    end
    local n = out:match("nginx/([%w%.]+)")
    return n and ("nginx " .. n) or "OpenResty ?"
end

-- The generated nginx.conf: a /parse + /proxy server, and an upstream /reflect that
-- echoes the raw forwarded Cookie. Inline content_by_lua_block bodies are brace-
-- balanced (no `{`/`}` inside strings) so nginx's block parser counts them cleanly.
local function nginx_conf(port_p, port_u)
    return table.concat({
        "worker_processes 1;",
        "daemon on;",
        "error_log " .. PREFIX .. "/logs/error.log warn;",
        "pid " .. PREFIX .. "/logs/nginx.pid;",
        "events { worker_connections 64; }",
        "http {",
        '    lua_package_path "' .. FIXTURES .. '/lua/?.lua;;";',
        "    access_log off;",
        "    client_body_temp_path " .. PREFIX .. "/temp/client;",
        "    proxy_temp_path " .. PREFIX .. "/temp/proxy;",
        "    fastcgi_temp_path " .. PREFIX .. "/temp/fastcgi;",
        "    uwsgi_temp_path " .. PREFIX .. "/temp/uwsgi;",
        "    scgi_temp_path " .. PREFIX .. "/temp/scgi;",
        "    server {",
        "        listen 127.0.0.1:" .. port_p .. ";",
        "        location = /parse {",
        "            content_by_lua_block {",
        '                local cjson = require "cjson"',
        '                local raw = ngx.var.http_cookie or ""',
        "                local seen, native = {}, {}",
        '                for tok in (raw .. ";"):gmatch("([^;]*);") do',
        '                    local nm = tok:match("^%s*([^=%s]+)")',
        "                    if nm and not seen[nm] then",
        "                        seen[nm] = true",
        '                        local v = ngx.var["cookie_" .. nm]',
        "                        if v ~= nil then",
        "                            native[#native + 1] = { n = ngx.encode_base64(nm), v = ngx.encode_base64(v) }",
        "                        end",
        "                    end",
        "                end",
        "                local resty = {}",
        '                local ok, ck = pcall(function() return require("resty.cookie"):new() end)',
        "                if ok and ck then",
        "                    local all = ck:get_all()",
        '                    if type(all) == "table" then',
        "                        local names = {}",
        "                        for k in pairs(all) do names[#names + 1] = k end",
        "                        table.sort(names)",
        "                        for i = 1, #names do",
        "                            resty[#resty + 1] = { n = ngx.encode_base64(names[i]), v = ngx.encode_base64(all[names[i]]) }",
        "                        end",
        "                    end",
        "                end",
        '                ngx.header["Content-Type"] = "application/json"',
        "                ngx.print(cjson.encode({ native = native, resty = resty }))",
        "            }",
        "        }",
        "        location = /proxy {",
        "            proxy_pass http://127.0.0.1:" .. port_u .. "/reflect;",
        "        }",
        "        location = /proxy-sc {",
        "            proxy_pass http://127.0.0.1:" .. port_u .. "/emit-sc;",
        "        }",
        "    }",
        "    server {",
        "        listen 127.0.0.1:" .. port_u .. ";",
        "        location = /reflect {",
        "            content_by_lua_block {",
        '                ngx.header["Content-Type"] = "text/plain"',
        '                ngx.print(ngx.encode_base64(ngx.var.http_cookie or ""))',
        "            }",
        "        }",
        "        location = /emit-sc {",
        "            content_by_lua_block {",
        '                local wire = ngx.decode_base64(ngx.var.http_x_wire_b64 or "") or ""',
        '                pcall(function() ngx.header["Set-Cookie"] = wire end)',
        '                ngx.header["Content-Type"] = "text/plain"',
        '                ngx.print("ok")',
        "            }",
        "        }",
        "    }",
        "}",
        "",
    }, "\n")
end

local function write_file(path, text)
    local f = io.open(path, "w")
    if not f then return false end
    f:write(text)
    f:close()
    return true
end

-- One HTTP/1.1 request to the booted nginx over a cosocket, the Cookie bytes placed
-- on the wire verbatim (a CR/LF/NUL among them hits nginx's real header parser).
-- Returns status_code, body — or nil, err on a transport failure.
local function http_get(port, path, cookie_bytes)
    local sock = ngx.socket.tcp()
    sock:settimeout(3000)
    local ok, cerr = sock:connect("127.0.0.1", port)
    if not ok then
        return nil, "connect: " .. tostring(cerr)
    end
    -- HTTP/1.0: nginx then replies close-delimited (no Transfer-Encoding: chunked,
    -- which it would use for an HTTP/1.1 reply with no Content-Length), so the body
    -- read below is the verbatim payload, not chunk-framed.
    local req = "GET " .. path .. " HTTP/1.0\r\nHost: 127.0.0.1\r\n"
        .. "Cookie: " .. cookie_bytes .. "\r\nConnection: close\r\n\r\n"
    local _, serr = sock:send(req)
    if serr then
        sock:close()
        return nil, "send: " .. tostring(serr)
    end
    local status_line = sock:receive("*l")
    if not status_line then
        sock:close()
        return nil, "no status line"
    end
    local code = tonumber(status_line:match("(%d%d%d)"))
    while true do
        local h = sock:receive("*l")
        if not h or h == "" then break end
    end
    -- Connection: close → the body arrives as the `partial` on the closing read.
    local b, _, partial = sock:receive("*a")
    sock:close()
    return code, (b or partial or "")
end

-- One request that carries the Set-Cookie wire (base64) in X-Wire-B64; the proxied
-- upstream emits it as a `Set-Cookie` response header, nginx forwards it, and we
-- read back what the client received. Returns status_code, set_cookie_value (or nil
-- if nginx forwarded none) — the forwarding-fidelity probe for the response path.
local function http_get_setcookie(port, path, wire_b64)
    local sock = ngx.socket.tcp()
    sock:settimeout(3000)
    local ok, cerr = sock:connect("127.0.0.1", port)
    if not ok then
        return nil, "connect: " .. tostring(cerr)
    end
    local req = "GET " .. path .. " HTTP/1.0\r\nHost: 127.0.0.1\r\n"
        .. "X-Wire-B64: " .. wire_b64 .. "\r\nConnection: close\r\n\r\n"
    local _, serr = sock:send(req)
    if serr then
        sock:close()
        return nil, "send: " .. tostring(serr)
    end
    local status_line = sock:receive("*l")
    if not status_line then
        sock:close()
        return nil, "no status line"
    end
    local code = tonumber(status_line:match("(%d%d%d)"))
    local set_cookie = nil
    while true do
        local h = sock:receive("*l")
        if not h or h == "" then break end
        local name, val = h:match("^([^:]+):%s*(.*)$")
        if name and name:lower() == "set-cookie" then
            set_cookie = val
        end
    end
    sock:close()
    return code, set_cookie
end

local BOOTED = false
local PORT_P, PORT_U

local function stop()
    if NGINX then
        os.execute(NGINX .. " -p " .. PREFIX .. "/ -c " .. CONF .. " -s stop >/dev/null 2>&1")
    end
    BOOTED = false
end

-- Boot one nginx on a free (port, port+1) pair, lazily and once. Scans a small band
-- and confirms readiness with a cosocket connect (like parse_cookies.php's probe).
local function boot()
    if BOOTED then return true end
    if not NGINX then return false end
    os.execute("rm -rf " .. PREFIX .. " && mkdir -p " .. PREFIX .. "/conf " .. PREFIX
        .. "/logs " .. PREFIX .. "/temp")
    for base = 8744, 8762, 2 do
        local p, u = base, base + 1
        if write_file(CONF, nginx_conf(p, u)) then
            os.execute(NGINX .. " -p " .. PREFIX .. "/ -c " .. CONF .. " >/dev/null 2>&1")
            for _ = 1, 40 do
                local s = ngx.socket.tcp()
                s:settimeout(100)
                local ok = s:connect("127.0.0.1", p)
                s:close()
                if ok then
                    PORT_P, PORT_U, BOOTED = p, u, true
                    return true
                end
                ngx.sleep(0.02)
            end
            stop()
        end
    end
    return false
end

local NA = { outcome = "NotApplicable" }
local SKIP = { outcome = "Skipped" }

local function rejected(msg)
    return { outcome = "Rejected", error = msg }
end

-- A reflected [{n=base64, v=base64}, …] → a Cookies outcome (bytes widened to UTF-8).
local function cookies_from(arr)
    local cookies = {}
    if type(arr) == "table" then
        for i = 1, #arr do
            cookies[i] = {
                name = l1_to_utf8(ngx.decode_base64(arr[i].n) or ""),
                value = l1_to_utf8(ngx.decode_base64(arr[i].v) or ""),
            }
        end
    end
    return { outcome = "Cookies", cookies = cookies }
end

-- Does a reflected array contain exactly this (name, value)? (selfcheck probe.)
local function has_pair(arr, name, value)
    if type(arr) ~= "table" then return false end
    for i = 1, #arr do
        if ngx.decode_base64(arr[i].n) == name and ngx.decode_base64(arr[i].v) == value then
            return true
        end
    end
    return false
end

local function parse_record(rec)
    if rec.direction ~= "request" then
        -- Response: only the Set-Cookie forwarding-fidelity column applies; the three
        -- request columns are n/a. nginx exposes no *parsed* Set-Cookie to Lua, so this
        -- measures whether a proxy_pass forwards the upstream's Set-Cookie verbatim (≡),
        -- alters it (≠), or drops/refuses it (❌).
        if not boot() then
            return { ["$cookie_<name>"] = NA, ["lua-resty-cookie"] = NA, ["proxy"] = NA,
                     ["proxy (Set-Cookie)"] = SKIP }
        end
        local want = ngx.decode_base64(rec.wire_b64) or ""
        local code, set_cookie = http_get_setcookie(PORT_P, "/proxy-sc", rec.wire_b64)
        local sc_out
        if not code or set_cookie == nil or set_cookie == "" then
            sc_out = { outcome = "ForwardedRejected" }
        elseif set_cookie == want then
            sc_out = { outcome = "ForwardedVerbatim" }
        else
            sc_out = { outcome = "ForwardedAltered", forwarded = l1_to_utf8(set_cookie) }
        end
        return { ["$cookie_<name>"] = NA, ["lua-resty-cookie"] = NA, ["proxy"] = NA,
                 ["proxy (Set-Cookie)"] = sc_out }
    end
    if not boot() then
        return { ["$cookie_<name>"] = SKIP, ["lua-resty-cookie"] = SKIP, ["proxy"] = SKIP,
                 ["proxy (Set-Cookie)"] = NA }
    end
    local wire = ngx.decode_base64(rec.wire_b64) or ""

    -- /parse → native $cookie_<name> and lua-resty-cookie.
    local nat_out, rst_out
    local status, body = http_get(PORT_P, "/parse", wire)
    if status == 200 and body then
        local ok, p = pcall(cjson.decode, body)
        if ok and type(p) == "table" then
            nat_out, rst_out = cookies_from(p.native), cookies_from(p.resty)
        else
            nat_out = rejected("reflect body not JSON")
            rst_out = rejected("reflect body not JSON")
        end
    elseif status then
        nat_out = rejected("nginx HTTP " .. status)
        rst_out = rejected("nginx HTTP " .. status)
    else
        nat_out = rejected("no response from nginx")
        rst_out = rejected("no response from nginx")
    end

    -- /proxy → forwarding fidelity (sent wire vs the Cookie the upstream received).
    local prx_out
    local pstatus, pbody = http_get(PORT_P, "/proxy", wire)
    if pstatus == 200 and pbody then
        local fwd = ngx.decode_base64(pbody) or ""
        if fwd == wire then
            prx_out = { outcome = "ForwardedVerbatim" }
        elseif fwd == "" then
            prx_out = { outcome = "ForwardedRejected" }
        else
            prx_out = { outcome = "ForwardedAltered", forwarded = l1_to_utf8(fwd) }
        end
    else
        prx_out = { outcome = "ForwardedRejected" }
    end

    return { ["$cookie_<name>"] = nat_out, ["lua-resty-cookie"] = rst_out, ["proxy"] = prx_out,
             ["proxy (Set-Cookie)"] = NA }
end

-- --selfcheck: boot once, probe all three deps end-to-end with a known cookie, tear
-- down, and report availability + versions. A dep that the round-trip can't confirm
-- is reported false → that column degrades to SKIP.
local function selfcheck()
    local nat, rst, prx, sc = false, false, false, false
    if boot() then
        local s, b = http_get(PORT_P, "/parse", "probe=1")
        if s == 200 and b then
            local ok, p = pcall(cjson.decode, b)
            if ok and type(p) == "table" then
                nat = has_pair(p.native, "probe", "1")
                rst = has_pair(p.resty, "probe", "1")
            end
        end
        local ps, pb = http_get(PORT_P, "/proxy", "probe=1")
        if ps == 200 and pb then
            prx = (ngx.decode_base64(pb) == "probe=1")
        end
        local scode, sval = http_get_setcookie(PORT_P, "/proxy-sc", ngx.encode_base64("probe=1"))
        if scode and sval == "probe=1" then
            sc = true
        end
    end
    stop()
    io.write(cjson.encode({
        available = {
            ["$cookie_<name>"] = nat,
            ["lua-resty-cookie"] = rst,
            ["proxy"] = prx,
            ["proxy (Set-Cookie)"] = sc,
        },
        versions = {
            runtime = openresty_version(),
            ["$cookie_<name>"] = "ngx_http_variables",
            ["lua-resty-cookie"] = RESTY_VERSION,
            ["proxy"] = "ngx_http_proxy_module",
            ["proxy (Set-Cookie)"] = "ngx_http_proxy_module",
        },
    }) .. "\n")
    io.flush()
end

local function main()
    if arg then
        for _, v in pairs(arg) do
            if v == "--selfcheck" then
                selfcheck()
                return
            end
        end
    end
    -- The corpus is small and stdin closes at EOF; read it whole, so no blocking
    -- stdin read is ever interleaved with a pending cosocket op.
    local data = io.read("*a") or ""
    for line in data:gmatch("[^\n]+") do
        local ok, rec = pcall(cjson.decode, line)
        if ok and type(rec) == "table" and rec.id then
            io.write(cjson.encode({ id = rec.id, by_dep = parse_record(rec) }) .. "\n")
        end
    end
    io.flush()
    stop()
end

main()
