/* keksbruch C sidecar (libcurl).
 *
 * Exercises libcurl's cookie engine as a Set-Cookie parser, in C — the matrix's
 * only native-C column. It works entirely offline: enable the cookie engine
 * (CURLOPT_COOKIEFILE=""), inject the wire via CURLOPT_COOKIELIST as a
 * "Set-Cookie: <wire>" line, then read the parsed cookie back as Netscape-format
 * lines via CURLINFO_COOKIELIST. No network transfer happens.
 *
 * Quirk worth knowing: libcurl will NOT export (via CURLINFO_COOKIELIST) a cookie
 * that was injected without a Domain attribute — with no transfer there is no
 * request host to attach it to. So a host-only Set-Cookie yields no cookie here and
 * is reported as a rejection. The curl-CLI loopback column
 * (parse_setcookie_clients.py) shows the transfer view, where the request host
 * supplies the domain and host-only cookies parse fully — the two columns together
 * contrast libcurl's injection API with a real transfer.
 *
 * Also: CURLOPT_COOKIELIST takes a C string, so a NUL byte in the wire truncates it
 * (an honest reflection of the C API). Request direction is n/a. The protocol
 * contract is ../PROTOCOL.md; stdout is flushed per line so a crash is attributed
 * to the right payload.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

/* ---- a small growable output string ---- */
typedef struct {
    char *p;
    size_t len, cap;
} str_t;

static void s_init(str_t *s) {
    s->cap = 256;
    s->len = 0;
    s->p = malloc(s->cap);
    s->p[0] = '\0';
}
static void s_ensure(str_t *s, size_t add) {
    if (s->len + add + 1 > s->cap) {
        while (s->len + add + 1 > s->cap) {
            s->cap *= 2;
        }
        s->p = realloc(s->p, s->cap);
    }
}
static void s_putc_raw(str_t *s, char c) {
    s_ensure(s, 1);
    s->p[s->len++] = c;
    s->p[s->len] = '\0';
}
static void s_puts(str_t *s, const char *t) {
    size_t n = strlen(t);
    s_ensure(s, n);
    memcpy(s->p + s->len, t, n);
    s->len += n;
    s->p[s->len] = '\0';
}

/* Append `n` raw bytes as a JSON string *body* (no surrounding quotes): escape the
 * JSON metacharacters and C0 control bytes, and widen bytes >= 0x80 to two-byte
 * UTF-8 (a latin-1 view of the wire), so the output is always valid UTF-8 — the
 * same mojibake the other sidecars show for a non-UTF-8 wire. */
static void s_put_json(str_t *s, const char *bytes, size_t n) {
    for (size_t i = 0; i < n; i++) {
        unsigned char b = (unsigned char)bytes[i];
        if (b == '"') {
            s_puts(s, "\\\"");
        } else if (b == '\\') {
            s_puts(s, "\\\\");
        } else if (b == '\n') {
            s_puts(s, "\\n");
        } else if (b == '\r') {
            s_puts(s, "\\r");
        } else if (b == '\t') {
            s_puts(s, "\\t");
        } else if (b < 0x20) {
            char u[8];
            snprintf(u, sizeof u, "\\u%04x", b);
            s_puts(s, u);
        } else if (b < 0x80) {
            s_putc_raw(s, (char)b);
        } else {
            s_putc_raw(s, (char)(0xC0 | (b >> 6)));
            s_putc_raw(s, (char)(0x80 | (b & 0x3F)));
        }
    }
}

/* ---- base64 decode (standard alphabet, padded; skips whitespace) ---- */
static int b64val(int c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}
static unsigned char *b64decode(const char *in, size_t len, size_t *out_len) {
    unsigned char *out = malloc(len / 4 * 3 + 4);
    if (!out) return NULL;
    size_t o = 0;
    int quad[4], qn = 0;
    for (size_t i = 0; i < len; i++) {
        int c = (unsigned char)in[i];
        if (c == '=') break;
        int v = b64val(c);
        if (v < 0) continue;
        quad[qn++] = v;
        if (qn == 4) {
            out[o++] = (unsigned char)((quad[0] << 2) | (quad[1] >> 4));
            out[o++] = (unsigned char)(((quad[1] & 0xF) << 4) | (quad[2] >> 2));
            out[o++] = (unsigned char)(((quad[2] & 0x3) << 6) | quad[3]);
            qn = 0;
        }
    }
    if (qn == 2) {
        out[o++] = (unsigned char)((quad[0] << 2) | (quad[1] >> 4));
    } else if (qn == 3) {
        out[o++] = (unsigned char)((quad[0] << 2) | (quad[1] >> 4));
        out[o++] = (unsigned char)(((quad[1] & 0xF) << 4) | (quad[2] >> 2));
    }
    *out_len = o;
    return out;
}

/* Extract the string value of "key" from a flat JSON object line. The harness
 * emits compact JSON whose id/direction/wire_b64 values never contain an escaped
 * quote (ids are kebab-case, base64 has no quote), so a plain scan suffices. */
static char *json_str(const char *line, const char *key, size_t *out_len) {
    char pat[64];
    snprintf(pat, sizeof pat, "\"%s\"", key);
    const char *p = strstr(line, pat);
    if (!p) return NULL;
    p += strlen(pat);
    while (*p && *p != ':') p++;
    if (*p != ':') return NULL;
    p++;
    while (*p == ' ' || *p == '\t') p++;
    if (*p != '"') return NULL;
    p++;
    const char *start = p;
    while (*p && *p != '"') p++;
    size_t n = (size_t)(p - start);
    char *s = malloc(n + 1);
    if (!s) return NULL;
    memcpy(s, start, n);
    s[n] = '\0';
    if (out_len) *out_len = n;
    return s;
}

/* Emit one cookie parsed from a Netscape-format line into `out` as a SetCookie
 * ParseOutcome. Fields: domain, includeSubdomains, path, secure, expiry, name,
 * value; a leading "#HttpOnly_" prefix on the domain marks HttpOnly. libcurl keeps
 * only an absolute expiry (not the raw Max-Age), so max_age is reported null —
 * comparable to the other parsers, which surface the Max-Age attribute, not a
 * derived expiry. SameSite is not present in the Netscape format → null. */
static void emit_set_cookie(str_t *out, const char *line) {
    int http_only = 0;
    const char *d = line;
    if (strncmp(d, "#HttpOnly_", 10) == 0) {
        http_only = 1;
        d += 10;
    }
    /* Split into 7 fields on TAB; field 6 (value) is the remainder. */
    const char *f[7];
    size_t flen[7];
    int nf = 0;
    const char *cur = d;
    while (nf < 6) {
        const char *tab = strchr(cur, '\t');
        if (!tab) break;
        f[nf] = cur;
        flen[nf] = (size_t)(tab - cur);
        nf++;
        cur = tab + 1;
    }
    if (nf < 6) {
        /* Not a cookie line we can read (a stray comment slipped through). */
        s_puts(out, "{\"outcome\":\"SetCookieRejected\",\"error\":\"unparsable cookie line\"}");
        return;
    }
    f[6] = cur;
    flen[6] = strlen(cur);
    /* strip a trailing CR/LF on the value field, if any */
    while (flen[6] > 0 && (f[6][flen[6] - 1] == '\n' || f[6][flen[6] - 1] == '\r')) {
        flen[6]--;
    }
    int secure = (flen[3] == 4 && strncmp(f[3], "TRUE", 4) == 0);

    s_puts(out, "{\"outcome\":\"SetCookie\",\"set_cookie\":{\"name\":\"");
    s_put_json(out, f[5], flen[5]);
    s_puts(out, "\",\"value\":\"");
    s_put_json(out, f[6], flen[6]);
    s_puts(out, "\",\"http_only\":");
    s_puts(out, http_only ? "true" : "false");
    s_puts(out, ",\"secure\":");
    s_puts(out, secure ? "true" : "false");
    s_puts(out, ",\"same_site\":null,\"path\":\"");
    s_put_json(out, f[2], flen[2]);
    s_puts(out, "\",\"domain\":\"");
    s_put_json(out, f[0], flen[0]);
    s_puts(out, "\",\"max_age\":null}}");
}

/* Parse a Set-Cookie wire with libcurl's cookie engine and append the outcome. */
static void parse_response(str_t *out, const char *wire, size_t wire_len) {
    CURL *h = curl_easy_init();
    if (!h) {
        s_puts(out, "{\"outcome\":\"SetCookieRejected\",\"error\":\"curl_easy_init failed\"}");
        return;
    }
    curl_easy_setopt(h, CURLOPT_COOKIEFILE, ""); /* enable the in-memory cookie engine */

    char *inject = malloc(wire_len + 16);
    memcpy(inject, "Set-Cookie: ", 12);
    memcpy(inject + 12, wire, wire_len);
    inject[12 + wire_len] = '\0'; /* a NUL in the wire truncates here — the C-API reality */
    curl_easy_setopt(h, CURLOPT_COOKIELIST, inject);

    struct curl_slist *cookies = NULL;
    curl_easy_getinfo(h, CURLINFO_COOKIELIST, &cookies);

    const char *line = NULL;
    for (struct curl_slist *e = cookies; e; e = e->next) {
        if (e->data[0] == '#' && strncmp(e->data, "#HttpOnly_", 10) != 0) {
            continue; /* a plain comment line */
        }
        line = e->data;
        break;
    }
    if (line) {
        emit_set_cookie(out, line);
    } else {
        s_puts(out,
               "{\"outcome\":\"SetCookieRejected\",\"error\":\"libcurl exported no cookie "
               "(injection drops a Set-Cookie with no Domain)\"}");
    }

    curl_slist_free_all(cookies);
    curl_easy_cleanup(h);
    free(inject);
}

static void selfcheck(void) {
    curl_version_info_data *info = curl_version_info(CURLVERSION_NOW);
    const char *ver = (info && info->version) ? info->version : "?";
    printf("{\"available\":{\"libcurl\":true},"
           "\"versions\":{\"runtime\":\"libcurl %s\",\"libcurl\":\"%s\"}}\n",
           ver, ver);
    fflush(stdout);
}

int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--selfcheck") == 0) {
            curl_global_init(CURL_GLOBAL_DEFAULT);
            selfcheck();
            curl_global_cleanup();
            return 0;
        }
    }
    curl_global_init(CURL_GLOBAL_DEFAULT);

    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    while ((n = getline(&line, &cap, stdin)) != -1) {
        /* trim trailing newline */
        while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r')) {
            line[--n] = '\0';
        }
        if (n == 0) continue;

        char *id = json_str(line, "id", NULL);
        char *dir = json_str(line, "direction", NULL);
        size_t b64len = 0;
        char *b64 = json_str(line, "wire_b64", &b64len);
        if (!id || !dir || !b64) {
            free(id);
            free(dir);
            free(b64);
            continue;
        }

        str_t out;
        s_init(&out);
        s_puts(&out, "{\"id\":\"");
        s_put_json(&out, id, strlen(id));
        s_puts(&out, "\",\"by_dep\":{\"libcurl\":");
        if (strcmp(dir, "response") == 0) {
            size_t wire_len = 0;
            unsigned char *wire = b64decode(b64, b64len, &wire_len);
            if (wire) {
                parse_response(&out, (const char *)wire, wire_len);
                free(wire);
            } else {
                s_puts(&out, "{\"outcome\":\"SetCookieRejected\",\"error\":\"base64 decode failed\"}");
            }
        } else {
            s_puts(&out, "{\"outcome\":\"NotApplicable\"}");
        }
        s_puts(&out, "}}");

        printf("%s\n", out.p);
        fflush(stdout); /* per-line flush: precise crash attribution (PROTOCOL.md) */

        free(out.p);
        free(id);
        free(dir);
        free(b64);
    }
    free(line);
    curl_global_cleanup();
    return 0;
}
