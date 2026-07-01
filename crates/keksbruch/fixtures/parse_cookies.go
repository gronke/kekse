// keksbruch Go sidecar.
//
// Reads base64-JSONL payload records on stdin and parses each with the standard
// library net/http (http.ParseCookie for a request Cookie header, since Go 1.23;
// http.ParseSetCookie for a Set-Cookie line). Emits one normalized JSONL result
// per line. `--selfcheck` reports availability + version, then exits.
//
// stdlib-only, so `go run parse_cookies.go` needs no go.mod.
// Full contract: ./PROTOCOL.md.
package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"runtime"
	"strings"
)

func selfcheck() {
	out := map[string]any{
		"available": map[string]bool{"net/http": true},
		"versions": map[string]string{
			// "go1.26.4" → "Go 1.26.4", matching the other sidecars' "<Runtime> <X.Y.Z>".
			"runtime":  "Go " + strings.TrimPrefix(runtime.Version(), "go"),
			"net/http": "stdlib",
		},
	}
	_ = json.NewEncoder(os.Stdout).Encode(out)
}

func parseRequest(wire string) map[string]any {
	cookies, err := http.ParseCookie(wire)
	if err != nil {
		return map[string]any{"outcome": "Rejected", "error": err.Error()}
	}
	pairs := make([]map[string]string, 0, len(cookies))
	for _, c := range cookies {
		pairs = append(pairs, map[string]string{"name": c.Name, "value": c.Value})
	}
	return map[string]any{"outcome": "Cookies", "cookies": pairs}
}

func sameSite(s http.SameSite) any {
	switch s {
	case http.SameSiteStrictMode:
		return "Strict"
	case http.SameSiteLaxMode:
		return "Lax"
	case http.SameSiteNoneMode:
		return "None"
	default:
		return nil
	}
}

func optString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func parseResponse(wire string) map[string]any {
	c, err := http.ParseSetCookie(wire)
	if err != nil {
		return map[string]any{"outcome": "SetCookieRejected", "error": err.Error()}
	}
	sc := map[string]any{
		"name":      c.Name,
		"value":     c.Value,
		"http_only": c.HttpOnly,
		"secure":    c.Secure,
		"same_site": sameSite(c.SameSite),
		"path":      optString(c.Path),
		"domain":    optString(c.Domain),
		"max_age":   nil,
	}
	// Go: MaxAge == 0 means "no Max-Age attribute"; non-zero (incl. negative) is set.
	if c.MaxAge != 0 {
		sc["max_age"] = c.MaxAge
	}
	// Go keeps Expires (the parsed attribute) distinct from Max-Age; the zero time means absent.
	if !c.Expires.IsZero() {
		sc["expires"] = c.Expires.Unix()
	}
	return map[string]any{"outcome": "SetCookie", "set_cookie": sc}
}

func main() {
	for _, a := range os.Args[1:] {
		if a == "--selfcheck" {
			selfcheck()
			return
		}
	}
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	enc := json.NewEncoder(os.Stdout)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec struct {
			ID        string `json:"id"`
			Direction string `json:"direction"`
			WireB64   string `json:"wire_b64"`
		}
		if err := json.Unmarshal(line, &rec); err != nil {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(rec.WireB64)
		if err != nil {
			continue
		}
		// Latin-1 view of the bytes, matching the py/node sidecars.
		runes := make([]rune, len(raw))
		for i, b := range raw {
			runes[i] = rune(b)
		}
		wire := string(runes)

		var outcome map[string]any
		if rec.Direction == "request" {
			outcome = parseRequest(wire)
		} else {
			outcome = parseResponse(wire)
		}
		_ = enc.Encode(map[string]any{
			"id":     rec.ID,
			"by_dep": map[string]any{"net/http": outcome},
		})
	}
}
