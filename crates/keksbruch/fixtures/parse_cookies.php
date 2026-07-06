<?php
/**
 * keksbruch PHP sidecar (pure core — no Composer, no non-core extensions).
 *
 * Captures PHP's *native* request-cookie parsing: $_COOKIE, as the SAPI populates
 * it from a real Cookie header. PHP CLI has no $_COOKIE, so we run PHP's built-in
 * server (`php -S`) with router.php and replay each request wire to it over a raw
 * loopback socket — so the server's own header parser plus PHP's cookie treatment
 * (urldecode, name-mangling, leniency) are what is tested, exactly like
 * rust/axum-extra tests parsing behind a real request layer. PHP has no
 * Set-Cookie *parser* (setcookie() only emits), so the response direction is n/a.
 *
 * Protocol in:  {"id","direction":"request"|"response","wire_b64"}
 * Protocol out: {"id","by_dep":{"$_COOKIE":{"outcome":...}}}
 * Full contract: ./PROTOCOL.md.
 */

const DEP = '$_COOKIE';

// [resource $proc, int $port] once booted, false if booting failed, null if not
// yet attempted. Booted lazily on the first request scenario, reused, killed at EOF.
$GLOBALS['server'] = null;

/** Boot `php -S` on the first free loopback port; return [proc, port] or null. */
function boot_server()
{
    $router = __DIR__ . '/router.php';
    $quiet = ['file', '/dev/null', 'w'];
    $spec = [0 => ['file', '/dev/null', 'r'], 1 => $quiet, 2 => $quiet];
    for ($port = 8723; $port < 8743; $port++) {
        $cmd = [PHP_BINARY, '-S', "127.0.0.1:$port", '-t', __DIR__, $router];
        $proc = @proc_open($cmd, $spec, $pipes);
        if (!is_resource($proc)) {
            continue;
        }
        // Wait for the listener; a quick exit means the port was taken → next one.
        for ($i = 0; $i < 40; $i++) {
            if (!proc_get_status($proc)['running']) {
                break;
            }
            $sock = @fsockopen('127.0.0.1', $port, $errno, $errstr, 0.2);
            if ($sock) {
                fclose($sock);
                return [$proc, $port];
            }
            usleep(50000); // 50ms
        }
        proc_terminate($proc);
        proc_close($proc);
    }
    return null;
}

function ensure_server()
{
    if ($GLOBALS['server'] === null) {
        $GLOBALS['server'] = boot_server() ?: false;
    }
    return $GLOBALS['server'] ?: null;
}

function shutdown_server()
{
    if (is_array($GLOBALS['server'])) {
        proc_terminate($GLOBALS['server'][0]);
        proc_close($GLOBALS['server'][0]);
        $GLOBALS['server'] = false;
    }
}

/**
 * Raw bytes → a latin-1 string (each byte becomes one codepoint), matching the
 * node/python sidecars so non-UTF-8 renders as the same mojibake and the result
 * is always valid UTF-8 for JSON.
 */
function latin1_to_utf8($s)
{
    $out = '';
    $len = strlen($s);
    for ($i = 0; $i < $len; $i++) {
        $c = ord($s[$i]);
        $out .= ($c < 0x80) ? chr($c) : (chr(0xC0 | ($c >> 6)) . chr(0x80 | ($c & 0x3F)));
    }
    return $out;
}

/** Replay one request wire to the built-in server and read back $_COOKIE. */
function parse_request($wire)
{
    $srv = ensure_server();
    if ($srv === null) {
        return ['outcome' => 'Rejected', 'error' => 'could not start php -S'];
    }
    [$proc, $port] = $srv;
    $sock = @fsockopen('127.0.0.1', $port, $errno, $errstr, 2.0);
    if (!$sock) {
        return ['outcome' => 'Rejected', 'error' => "connect failed: $errstr"];
    }
    stream_set_timeout($sock, 2);
    // A raw, binary-safe request: the cookie bytes go on the wire verbatim, so a
    // CR/LF/NUL among them hits the server's real header parser (the realistic path).
    $req = "GET / HTTP/1.1\r\nHost: 127.0.0.1:$port\r\nCookie: " . $wire
        . "\r\nConnection: close\r\n\r\n";
    fwrite($sock, $req);
    $resp = stream_get_contents($sock);
    fclose($sock);
    if ($resp === false || $resp === '') {
        return ['outcome' => 'Rejected', 'error' => 'empty response'];
    }
    $split = strpos($resp, "\r\n\r\n");
    if ($split === false) {
        return ['outcome' => 'Rejected', 'error' => 'no header/body split'];
    }
    $status_line = strtok(substr($resp, 0, $split), "\r\n");
    if (strpos($status_line, ' 200 ') === false) {
        return ['outcome' => 'Rejected', 'error' => "non-200: $status_line"];
    }
    $decoded = json_decode(substr($resp, $split + 4), true);
    if (!is_array($decoded)) {
        return ['outcome' => 'Rejected', 'error' => 'router body not JSON'];
    }
    $cookies = [];
    foreach ($decoded as $pair) {
        $cookie = [
            'name' => latin1_to_utf8(base64_decode($pair['n'] ?? '')),
            'value' => latin1_to_utf8(base64_decode($pair['v'] ?? '')),
        ];
        // PHP is the lone parser that builds a rich type (array/map) from a
        // bracketed name; carry its `shape` through so the matrix can badge it.
        if (isset($pair['shape'])) {
            $cookie['shape'] = $pair['shape'];
        }
        $cookies[] = $cookie;
    }
    return ['outcome' => 'Cookies', 'cookies' => $cookies];
}

function selfcheck()
{
    $ok = ensure_server() !== null;
    shutdown_server();
    // Plain semver (drop Ubuntu's packaging suffix) to match the other rows.
    $ver = PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION . '.' . PHP_RELEASE_VERSION;
    echo json_encode([
        'available' => [DEP => $ok],
        'versions' => ['runtime' => "PHP $ver", DEP => 'SAPI cli-server'],
    ]) . "\n";
}

function main($argv)
{
    if (in_array('--selfcheck', $argv, true)) {
        selfcheck();
        return;
    }
    register_shutdown_function('shutdown_server');
    $in = fopen('php://stdin', 'r');
    while (($line = fgets($in)) !== false) {
        $line = trim($line);
        if ($line === '') {
            continue;
        }
        $rec = json_decode($line, true);
        if (!is_array($rec) || !isset($rec['wire_b64'], $rec['direction'], $rec['id'])) {
            continue;
        }
        $wire = base64_decode($rec['wire_b64']);
        // Only the request direction parses here; responses — and any unrecognized
        // record kind, e.g. protocol v2 "jar" probes — are NotApplicable (PROTOCOL.md).
        $outcome = $rec['direction'] === 'request'
            ? parse_request($wire)
            : ['outcome' => 'NotApplicable'];
        echo json_encode(['id' => $rec['id'], 'by_dep' => [DEP => $outcome]]) . "\n";
    }
    shutdown_server();
}

main($argv);
