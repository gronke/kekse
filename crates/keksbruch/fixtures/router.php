<?php
// keksbruch PHP built-in-server router.
//
// The SAPI populates $_COOKIE from the request's Cookie header before this runs
// — that *is* PHP's native cookie parse (urldecode, name-mangling, leniency and
// all). Names and values are base64-encoded so non-UTF-8 / control bytes survive
// JSON transport back to the sidecar, which re-decodes and renders them latin-1.
$out = [];
foreach ($_COOKIE as $name => $value) {
    // A bracketed name (`n[a]=`) makes PHP build a nested array; the current
    // corpus has none, but encode it defensively so this never warns or fails.
    $v = is_array($value) ? json_encode($value) : (string) $value;
    $out[] = ['n' => base64_encode((string) $name), 'v' => base64_encode($v)];
}
header('Content-Type: application/json');
echo json_encode($out);
