<?php
// keksbruch PHP built-in-server router.
//
// The SAPI populates $_COOKIE from the request's Cookie header before this runs
// — that *is* PHP's native cookie parse (urldecode, name-mangling, leniency and
// all). Names and values are base64-encoded so non-UTF-8 / control bytes survive
// JSON transport back to the sidecar, which re-decodes and renders them latin-1.
// Whether $a is a list (consecutive 0-based int keys) vs an associative map.
// Hand-rolled rather than array_is_list() (PHP 8.1+) so this runs on any image.
function kekse_is_list(array $a): bool
{
    $i = 0;
    foreach ($a as $k => $_) {
        if ($k !== $i++) {
            return false;
        }
    }
    return true;
}

$out = [];
foreach ($_COOKIE as $name => $value) {
    // A bracketed name (`n[]=`/`n[k]=`) makes PHP build a rich type: an indexed
    // array or an associative map. JSON-encode it for `value` and flag its
    // `shape` so the matrix badges a genuine structure distinctly from a string.
    if (is_array($value)) {
        $shape = kekse_is_list($value) ? 'array' : 'object';
        $v = json_encode($value);
    } else {
        $shape = 'scalar';
        $v = (string) $value;
    }
    $pair = ['n' => base64_encode((string) $name), 'v' => base64_encode($v)];
    if ($shape !== 'scalar') {
        $pair['shape'] = $shape;
    }
    $out[] = $pair;
}
header('Content-Type: application/json');
echo json_encode($out);
