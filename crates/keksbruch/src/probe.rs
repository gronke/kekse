//! The jar-probe corpus: a [`JarProbe`] is one *store-then-retrieve* experiment for RFC 6265
//! §5.3/§5.4 — a `Set-Cookie` wire, the origin it is received from, and a later request URL —
//! pinned to what the [`reference`](crate::reference) retrieval attaches. Domain- and
//! path-matching are two-input relations, so they cannot ride the single-wire scenarios;
//! this is their corpus. Static and deterministic, like [`scenarios`](crate::scenarios).

/// One §5.3-storage / §5.4-retrieval experiment. The wire is a *clean* `Set-Cookie` (the
/// probes vary the matching inputs, not the wire syntax — that is the scenarios' job), so it
/// is a plain literal rather than a `KeksbruchRecipe`. URLs are harness-authored ASCII of the
/// shape `scheme://host/path` — no port, userinfo, or query.
#[derive(Clone, Debug)]
pub struct JarProbe {
    /// Stable id (the matrix row key), `jar-*`.
    pub id: &'static str,
    pub description: &'static str,
    /// The `Set-Cookie` header value to store.
    pub set_cookie: &'static str,
    /// The URL the `Set-Cookie` is received from (§5.3's request-uri).
    pub origin_url: &'static str,
    /// The URL of the later request the jar is asked to attach cookies to (§5.4).
    pub request_url: &'static str,
    /// The `(name, value)` pairs the reference attaches in the default build — the bare
    /// RFC 6265 algorithm, without the optional §5.3-step-5 public-suffix policy.
    pub expect_attached: &'static [(&'static str, &'static str)],
    /// The pairs under the `hardened` feature, where §5.3 step 5 rejects a public-suffix
    /// `Domain` (the supercookie defense). Identical to `expect_attached` for every probe
    /// that carries no public-suffix `Domain`.
    pub expect_attached_hardened: &'static [(&'static str, &'static str)],
}

/// Assemble one probe whose expectation is the same in both builds.
const fn p(
    id: &'static str,
    description: &'static str,
    set_cookie: &'static str,
    origin_url: &'static str,
    request_url: &'static str,
    expect_attached: &'static [(&'static str, &'static str)],
) -> JarProbe {
    JarProbe {
        id,
        description,
        set_cookie,
        origin_url,
        request_url,
        expect_attached,
        expect_attached_hardened: expect_attached,
    }
}

const SID: &[(&str, &str)] = &[("SID", "abc")];
const NONE: &[(&str, &str)] = &[];

/// The jar-probe corpus, covering §5.1.3 domain-match, §5.1.4 path-match, §5.2.3/§5.2.4
/// attribute normalization, §5.3 storage steps 4–7, and §5.4 step 1's host-only and Secure
/// rules. One cookie per probe, so retrieval order (§5.4's sort) never comes into play.
pub fn jar_probes() -> Vec<JarProbe> {
    vec![
        // ── host-only vs Domain cookies (§5.3 step 6, §5.4 step 1) ─────────
        p(
            "jar-host-only-exact",
            "no Domain attribute → a host-only cookie; the identical host gets it back",
            "SID=abc",
            "https://example.com/",
            "https://example.com/",
            SID,
        ),
        p(
            "jar-host-only-subdomain",
            "a host-only cookie never flows to a subdomain — only a Domain cookie widens",
            "SID=abc",
            "https://example.com/",
            "https://sub.example.com/",
            NONE,
        ),
        p(
            "jar-domain-exact",
            "Domain equal to the origin host attaches on that host",
            "SID=abc; Domain=example.com",
            "https://example.com/",
            "https://example.com/",
            SID,
        ),
        p(
            "jar-domain-parent",
            "a parent Domain set from one subdomain attaches on a sibling subdomain",
            "SID=abc; Domain=example.com",
            "https://sub.example.com/",
            "https://other.example.com/",
            SID,
        ),
        p(
            "jar-domain-superset",
            "a Domain *below* the origin host is refused at storage — the origin must domain-match it",
            "SID=abc; Domain=sub.example.com",
            "https://example.com/",
            "https://sub.example.com/",
            NONE,
        ),
        p(
            "jar-domain-label-boundary",
            "badexample.com does not domain-match example.com — a suffix only counts at a label boundary",
            "SID=abc; Domain=example.com",
            "https://badexample.com/",
            "https://example.com/",
            NONE,
        ),
        p(
            "jar-domain-case",
            "an upper-cased Domain is canonicalized (§5.1.2) before matching",
            "SID=abc; Domain=EXAMPLE.COM",
            "https://example.com/",
            "https://example.com/",
            SID,
        ),
        p(
            "jar-domain-leading-dot",
            "a leading dot on Domain is stripped (§5.2.3); the cookie then flows like a dotless one",
            "SID=abc; Domain=.example.com",
            "https://sub.example.com/",
            "https://example.com/",
            SID,
        ),
        p(
            "jar-domain-ip",
            "an IP-literal host matches a Domain only by identity — never by suffix",
            "SID=abc; Domain=127.0.0.1",
            "http://127.0.0.1/",
            "http://127.0.0.1/",
            SID,
        ),
        // The row that showcases the optional supercookie defense: the bare RFC algorithm
        // *attaches* it (rejecting a public suffix is §5.3 step 5, marked optional), the
        // hardened build refuses it at storage. Real jars diverge on exactly this line.
        JarProbe {
            id: "jar-domain-supercookie",
            description: "Domain=com is a public suffix: the bare RFC algorithm attaches it \
                          across registrable domains; the hardened build (and PSL-aware jars) \
                          refuse it at storage",
            set_cookie: "SID=abc; Domain=com",
            origin_url: "https://example.com/",
            request_url: "https://not-example.com/",
            expect_attached: SID,
            expect_attached_hardened: NONE,
        },
        // ── path-match (§5.1.4) and default-path (§5.2.4, §5.3 step 7) ─────
        p(
            "jar-path-prefix-boundary",
            "Path=/a matches /a/b — a prefix at a `/` boundary",
            "SID=abc; Path=/a",
            "https://example.com/",
            "https://example.com/a/b",
            SID,
        ),
        p(
            "jar-path-non-boundary",
            "Path=/a does not match /ab — a prefix without a boundary never matches",
            "SID=abc; Path=/a",
            "https://example.com/",
            "https://example.com/ab",
            NONE,
        ),
        p(
            "jar-path-trailing-slash",
            "Path=/a/ does not match its parent /a — the longer cookie-path is never a prefix",
            "SID=abc; Path=/a/",
            "https://example.com/",
            "https://example.com/a",
            NONE,
        ),
        p(
            "jar-path-default-sibling",
            "no Path → the origin's default-path (/dir); a sibling under it gets the cookie",
            "SID=abc",
            "https://example.com/dir/page",
            "https://example.com/dir/other",
            SID,
        ),
        p(
            "jar-path-default-outside",
            "no Path → the origin's default-path (/dir); a request outside it does not",
            "SID=abc",
            "https://example.com/dir/page",
            "https://example.com/elsewhere",
            NONE,
        ),
        p(
            "jar-path-not-absolute",
            "a Path not starting with `/` is ignored (§5.2.4) — the default-path applies instead",
            "SID=abc; Path=name",
            "https://example.com/dir/page",
            "https://example.com/dir/other",
            SID,
        ),
        // ── Secure (§5.4 step 1) ────────────────────────────────────────────
        p(
            "jar-secure-on-http",
            "a Secure cookie set over https is not attached to a plain-http request",
            "SID=abc; Secure",
            "https://example.com/",
            "http://example.com/",
            NONE,
        ),
    ]
}
