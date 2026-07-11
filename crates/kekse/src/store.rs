//! An opt-in, stateful client-side cookie store (`store` feature): RFC 6265
//! §5.3 storage and §5.4 retrieval on top of the codec and `rfc_6265`'s
//! matchers.
//!
//! [`CookieStore`] is the stateful concept above the codec's two directions:
//! it **ingests** response `Set-Cookie` lines (keeping the `Domain`, `Path`,
//! `Secure`, and expiry that drive matching), holds the attributed cookies
//! across many origins over time, and **emits** a request `Cookie:` header by
//! matching a request against what it holds. Origins and requests are
//! `url::Url`s — the URL an HTTP stack already holds — so the host arrives
//! lowercased and IDNA-encoded (the RFC 6265 §5.1.2 canonical form), and the
//! secure bit is the URL's own: a TLS scheme (`https`/`wss`), or a loopback
//! destination (an IPv4/IPv6 loopback address, `localhost`, `*.localhost`) —
//! the trustworthy-origin convention user agents apply. The request-side
//! [`CookieJar`](crate::CookieJar) stays the *output* container — retrieval
//! renders through it — never the store itself: a jar carries attribute-less
//! pairs for one header, while the store's whole job is the attributes.
//!
//! Storage applies the gates user agents apply. Beyond RFC 6265 §5.3 — the
//! anti-planting `Domain` rule, default-path, `Max-Age` over `Expires` — the
//! store also rejects, per RFC 6265bis §5.5, a `Secure` cookie set over an
//! insecure origin and any cookie whose parse witnessed an unmet
//! [`CookieConstraint`](crate::CookieConstraint) (the `__Host-`/`__Secure-`
//! prefix requirements and CHIPS' `Partitioned`/`Secure` pairing). The one
//! deliberate exception is
//! [`NonCanonicalPrefixCase`](crate::CookieConstraint::NonCanonicalPrefixCase):
//! engines enforce the prefix *requirements* case-insensitively but store a
//! case-variant spelling whose requirements are met, and the store does the
//! same — the casing note stays a witness for the codec's callers. Every
//! refusal is a typed [`Insertion::Rejected`], never a silent drop.
//!
//! The lenient parse feeds the store, and its issue report carries the two
//! wire shapes the typed attributes cannot: a **refused `Domain`** (under the
//! `psl`/`idna` hardening its witness value drives the exact §5.3 step 5
//! public-suffix decision — reject for a foreign host, degrade to host-only
//! when the origin *is* the suffix) and a **negative `Max-Age`** (valid
//! §5.2.2 syntax meaning "expire now", which
//! [`CookieAttributes::max_age`](crate::CookieAttributes::max_age) — a `u64`
//! — cannot hold; the store honors the deletion instead of degrading the
//! cookie to a session cookie).
//!
//! Time is data: every time-sensitive method takes `now: OffsetDateTime`, and
//! the store never reads a clock — the caller owns time, which keeps expiry
//! deterministic and testable. `SameSite`, `HttpOnly`, and `Partitioned` are
//! stored and surfaced ([`StoredRef`]), never enforced on send: a store knows
//! neither the request's site-for-cookies nor its partition key, so those
//! calls belong to the caller. (`HttpOnly` governs script visibility, not
//! sending — an HTTP client sends such cookies normally.)
//!
//! ```
//! use kekse::{CookieStore, Insertion, OffsetDateTime};
//!
//! let now = OffsetDateTime::from_unix_timestamp(1_752_000_000)?;
//! let origin = url::Url::parse("https://shop.example.test/")?;
//!
//! let mut store = CookieStore::new();
//! let sid = store.insert(&origin, "SID=deadbeef; Secure; HttpOnly; Path=/", now);
//! let theme = store.insert(&origin, "theme=dark mode; Max-Age=3600", now);
//! assert_eq!((sid, theme), (Insertion::Stored, Insertion::Stored));
//!
//! // The same origin gets both back, percent-encoded canonically…
//! let header = store.cookie_header(&origin, now).unwrap();
//! assert_eq!(header, "SID=deadbeef; theme=dark%20mode");
//!
//! // …a sibling host gets neither (host-only isolation, §5.4)…
//! let sibling = url::Url::parse("https://blog.example.test/")?;
//! assert_eq!(store.cookie_header(&sibling, now), None);
//!
//! // …and two hours later the session cookie is the only survivor.
//! let later = OffsetDateTime::from_unix_timestamp(1_752_007_200)?;
//! let header = store.cookie_header(&origin, later).unwrap();
//! assert_eq!(header, "SID=deadbeef");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use std::collections::HashMap;

use rfc_6265::OffsetDateTime;
use rfc_6265::domain::{canonicalize, domain_matches};
use rfc_6265::path::{default_path, path_matches};

use crate::cookie::Cookie;
use crate::encoding::ValueEncoding;
use crate::jar::CookieJar;
use crate::report::Reported;
use crate::same_site::SameSite;
use crate::set_cookie::{CookieConstraint, KnownAttribute, SetCookie, SetCookieIssue};

/// 9999-12-31T23:59:59 UTC in unix seconds — the top of `OffsetDateTime`'s
/// default range. A `Max-Age` reaching past it saturates here, so a stored
/// expiry always converts back into an `OffsetDateTime` ([`StoredRef::expires`]).
const MAX_EXPIRY_TS: i64 = 253_402_300_799;

/// The pieces of a request URL the cookie algorithms read — the host (the
/// `url` crate delivers it lowercased and IDNA-encoded at parse, so it is
/// already the RFC 6265 §5.1.2 canonical form), the path, and the secure bit
/// per [`is_secure_url`] — or `None` for a URL without a host (`mailto:`,
/// `data:`), which no cookie can be keyed to or match.
fn url_parts(url: &url::Url) -> Option<(&str, &str, bool)> {
    Some((url.host_str()?, url.path(), is_secure_url(url)))
}

/// The store's secure-channel notion, applied to both the RFC 6265bis §5.5
/// ingest gate and the §5.4 send gate: a TLS scheme (`https` / `wss`), or a
/// loopback destination — an IPv4/IPv6 loopback address, `localhost`, or a
/// `*.localhost` name — the trustworthy-origin convention user agents apply
/// to `Secure` cookies in local development.
fn is_secure_url(url: &url::Url) -> bool {
    match url.scheme() {
        "https" | "wss" => true,
        _ => match url.host() {
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            Some(url::Host::Domain(host)) => {
                host.eq_ignore_ascii_case("localhost")
                    || host.to_ascii_lowercase().ends_with(".localhost")
            }
            None => false,
        },
    }
}

/// Capacity limits for a [`CookieStore`]. When an insert pushes past a limit,
/// eviction removes expired cookies first, then the oldest-by-creation
/// cookies of the over-cap domain (and, for the global limit, of the whole
/// store) — the freshly stored cookie is the newest, so it survives.
///
/// The defaults are RFC 6265 §6.1's minimum capabilities: 3000 cookies total,
/// 50 per domain (the effective domain — the `Domain` attribute, or the
/// setting host for a host-only cookie).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StoreConfig {
    /// The store-wide cookie limit.
    pub max_cookies: usize,
    /// The per-effective-domain cookie limit.
    pub max_cookies_per_domain: usize,
}

impl Default for StoreConfig {
    /// RFC 6265 §6.1: 3000 cookies, 50 per domain.
    fn default() -> Self {
        Self {
            max_cookies: 3000,
            max_cookies_per_domain: 50,
        }
    }
}

/// What [`CookieStore::insert`] did with one `Set-Cookie` line — every
/// outcome is reported, never silent, so a caller (or a test) can tell a
/// fresh cookie from a replacement, a deletion, and each refusal.
#[must_use = "an unchecked insertion can hide a rejected or deleted cookie"]
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Insertion {
    /// A new cookie was stored.
    Stored,
    /// An existing cookie with the same `(name, domain, path)` identity was
    /// replaced — keeping its creation order (RFC 6265 §5.3 step 11.3).
    Replaced,
    /// The line was the deletion idiom — already expired at `now` via
    /// `Max-Age=0`, a negative `Max-Age`, or a past `Expires` — so any
    /// existing cookie with the same identity was removed and nothing stored.
    Deleted,
    /// The cookie was refused, for the carried [`RejectionReason`].
    Rejected(RejectionReason),
}

/// Why [`CookieStore::insert`] refused a `Set-Cookie` line.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RejectionReason {
    /// No usable `name=value` pair (the parse's fatal
    /// [`PairIssue`](crate::PairIssue)), or an origin URL without a host
    /// (`mailto:`, `data:`) — nothing a cookie can be keyed to.
    Malformed,
    /// The `Domain` attribute was refused by the codec's gates
    /// ([`Domain::new`](crate::Domain::new)) and names a host other than the
    /// origin — under the `psl` hardening this is the RFC 6265 §5.3 step 5
    /// public-suffix rejection. (A refused `Domain` naming the origin itself
    /// degrades to host-only instead — step 5's exception.)
    InvalidDomain,
    /// The `Domain` attribute does not cover the origin host (§5.3 step 6) —
    /// the anti-planting rule: `evil.test` cannot set a cookie for
    /// `victim.test`.
    DomainMismatch,
    /// The parse witnessed an unmet cross-field requirement — an RFC 6265bis
    /// §4.1.3 `__Host-`/`__Secure-` prefix rule or CHIPS'
    /// `Partitioned`/`Secure` pairing. A merely non-canonical prefix *case*
    /// with its requirements met is stored, as user agents do.
    ConstraintViolation,
    /// A `Secure` cookie arriving over an insecure origin (RFC 6265bis §5.5).
    InsecureOrigin,
}

impl std::fmt::Display for RejectionReason {
    /// Static, control-free text — a reason names no wire bytes.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Malformed => "no usable name=value pair (or no origin host)",
            Self::InvalidDomain => "the Domain attribute was refused and names a foreign host",
            Self::DomainMismatch => "the Domain attribute does not cover the origin host",
            Self::ConstraintViolation => "an unmet prefix or Partitioned/Secure requirement",
            Self::InsecureOrigin => "a Secure cookie set over an insecure origin",
        })
    }
}

/// One cookie as the store holds it. Everything is owned: a stored cookie
/// outlives the header line it arrived on.
#[derive(Clone, Debug)]
struct StoredCookie {
    name: String,
    /// The decoded logical value (retrieval re-encodes canonically).
    value: String,
    /// The effective domain, canonicalized: the `Domain` attribute
    /// (dot-stripped) or the setting host when `host_only`.
    domain: String,
    host_only: bool,
    /// The cookie path — the `Path` attribute, or the origin's default-path.
    path: String,
    secure: bool,
    http_only: bool,
    partitioned: bool,
    same_site: Option<SameSite>,
    /// Expiry in unix seconds; `None` is a session cookie (kept until
    /// [`CookieStore::clear`] or eviction).
    expires_at: Option<i64>,
    /// Insertion order; preserved by an identity replacement, and the
    /// tie-breaker of §5.4.2 ordering and of eviction.
    created: u64,
}

impl StoredCookie {
    fn expired(&self, now_ts: i64) -> bool {
        self.expires_at.is_some_and(|at| at <= now_ts)
    }
}

/// A borrowed read view of one stored cookie — what [`CookieStore::iter`],
/// [`get`](CookieStore::get), and [`matches`](CookieStore::matches) yield.
/// The accessors mirror the [`CookieAttributes`](crate::CookieAttributes)
/// names; the concrete storage stays private.
#[derive(Clone, Copy, Debug)]
pub struct StoredRef<'a>(&'a StoredCookie);

impl<'a> StoredRef<'a> {
    /// The cookie-name, exactly as set (a case-variant prefix is kept
    /// verbatim).
    #[must_use]
    pub fn name(&self) -> &'a str {
        &self.0.name
    }

    /// The decoded logical value.
    #[must_use]
    pub fn value(&self) -> &'a str {
        &self.0.value
    }

    /// The effective domain the cookie is keyed to, canonicalized: the
    /// `Domain` attribute (leading dot stripped), or the setting host when
    /// [`host_only`](StoredRef::host_only).
    #[must_use]
    pub fn domain(&self) -> &'a str {
        &self.0.domain
    }

    /// Whether the cookie is host-only — set without a usable `Domain`
    /// attribute, matching its exact setting host and no subdomain.
    #[must_use]
    pub fn host_only(&self) -> bool {
        self.0.host_only
    }

    /// The cookie path — the `Path` attribute, or the origin's default-path.
    #[must_use]
    pub fn path(&self) -> &'a str {
        &self.0.path
    }

    /// The `Secure` flag.
    #[must_use]
    pub fn secure(&self) -> bool {
        self.0.secure
    }

    /// The `HttpOnly` flag — stored and surfaced, never enforced: it governs
    /// script visibility, and an HTTP client sends such cookies normally.
    #[must_use]
    pub fn http_only(&self) -> bool {
        self.0.http_only
    }

    /// The `Partitioned` flag (CHIPS) — stored and surfaced, never enforced:
    /// the store does not know a request's partition key.
    #[must_use]
    pub fn partitioned(&self) -> bool {
        self.0.partitioned
    }

    /// The `SameSite` attribute — stored and surfaced, never enforced: the
    /// store does not know a request's site-for-cookies.
    #[must_use]
    pub fn same_site(&self) -> Option<SameSite> {
        self.0.same_site
    }

    /// The absolute expiry instant, or `None` for a session cookie. Always
    /// convertible: the stored expiry is clamped into `OffsetDateTime`'s
    /// range at ingest.
    #[must_use]
    pub fn expires(&self) -> Option<OffsetDateTime> {
        self.0
            .expires_at
            .and_then(|at| OffsetDateTime::from_unix_timestamp(at).ok())
    }
}

/// A client-side cookie store: RFC 6265 §5.3 storage, §5.4 retrieval, §6.1
/// capacity limits — the state a cookie-aware HTTP client keeps between a
/// response's `Set-Cookie` and the next request's `Cookie:`.
///
/// The store is a plain value — `&mut self` writes, `&self` reads — with no
/// lock of its own; share it the standard way:
///
/// ```
/// use std::sync::RwLock;
///
/// use kekse::{CookieStore, Insertion, OffsetDateTime};
///
/// let now = OffsetDateTime::from_unix_timestamp(1_752_000_000)?;
/// let url = url::Url::parse("https://example.test/")?;
/// let store = RwLock::new(CookieStore::new());
///
/// let stored = store.write().unwrap().insert(&url, "SID=deadbeef; Secure", now);
/// assert_eq!(stored, Insertion::Stored);
/// let header = store.read().unwrap().cookie_header(&url, now);
/// assert_eq!(header.unwrap(), "SID=deadbeef");
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Debug, Default)]
pub struct CookieStore {
    cookies: Vec<StoredCookie>,
    next_created: u64,
    config: StoreConfig,
}

impl CookieStore {
    /// An empty store with the default [`StoreConfig`] (RFC 6265 §6.1: 3000
    /// cookies, 50 per domain).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// An empty store with explicit capacity limits.
    #[must_use]
    pub fn with_config(config: StoreConfig) -> Self {
        Self {
            config,
            ..Self::default()
        }
    }

    /// Ingest one `Set-Cookie` header value per RFC 6265 §5.3, with the
    /// RFC 6265bis storage gates. The outcome is always reported: stored,
    /// replaced (same `(name, domain, path)` identity, creation order kept),
    /// deleted (the already-expired idiom, including a negative `Max-Age`),
    /// or rejected with a [`RejectionReason`].
    ///
    /// Storage follows the user-agent rules. A `Domain` must cover the origin
    /// host (the anti-planting rule; under `psl` a refused public-suffix
    /// `Domain` is rejected for a foreign host and degrades to host-only when
    /// the origin *is* the suffix — §5.3 step 5 exactly), a missing or
    /// relative `Path` takes the origin's default-path, and `Max-Age` wins
    /// over `Expires`, with a negative `Max-Age` honored as "expire now".
    /// The RFC 6265bis gates then apply: a `Secure` cookie only over a secure
    /// origin — a TLS scheme (`https`/`wss`) or a loopback destination
    /// (loopback IPs, `localhost`, `*.localhost`), the trustworthy-origin
    /// convention — and the `__Host-`/`__Secure-` prefix requirements and
    /// CHIPS' `Partitioned`/`Secure` pairing as witnessed by the parse; a
    /// case-variant prefix whose requirements are met stores verbatim, as
    /// user agents do. Finally the [`StoreConfig`] caps evict, expired
    /// cookies first, then oldest by creation.
    ///
    /// The line is parsed leniently ([`SetCookie::parse`]) — the store mirrors
    /// a user agent, and a recoverable deviation never costs the cookie. A
    /// caller who wants strict grading gates before feeding the store.
    ///
    /// ```
    /// use kekse::{CookieStore, Insertion, OffsetDateTime, RejectionReason};
    ///
    /// let now = OffsetDateTime::from_unix_timestamp(1_752_000_000)?;
    /// let origin = url::Url::parse("https://shop.example.test/cart")?;
    /// let mut store = CookieStore::new();
    ///
    /// let stored = store.insert(&origin, "SID=deadbeef; Path=/; Secure", now);
    /// assert_eq!(stored, Insertion::Stored);
    ///
    /// // The anti-planting rule: a foreign Domain is refused.
    /// let planted = store.insert(&origin, "SID=evil; Domain=victim.test", now);
    /// assert_eq!(
    ///     planted,
    ///     Insertion::Rejected(RejectionReason::DomainMismatch)
    /// );
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn insert(
        &mut self,
        origin: &url::Url,
        set_cookie: &str,
        now: OffsetDateTime,
    ) -> Insertion {
        // A cookie is keyed to its origin host; a URL without one (mailto:,
        // data:) has nothing to key it to.
        let Some((origin_host, origin_path, origin_secure)) = url_parts(origin) else {
            return Insertion::Rejected(RejectionReason::Malformed);
        };
        let Ok(Reported {
            value: cookie,
            issues,
        }) = SetCookie::parse(set_cookie)
        else {
            return Insertion::Rejected(RejectionReason::Malformed);
        };
        let attrs = cookie.attributes();
        let origin_host = canonicalize(origin_host);

        // §5.3 steps 4-6 — the effective domain. An empty Domain value (after
        // the §5.2.3 dot strip) is treated as absent, per §5.2.3's SHOULD.
        let (host_only, domain) = match attrs.domain.map(|d| d.as_str()) {
            Some(d) if !d.strip_prefix('.').unwrap_or(d).is_empty() => {
                let d = canonicalize(d.strip_prefix('.').unwrap_or(d));
                if !domain_matches(&origin_host, &d) {
                    return Insertion::Rejected(RejectionReason::DomainMismatch);
                }
                (false, d)
            }
            Some(_) => (true, origin_host),
            None => {
                // The codec refused the Domain (host-name syntax, public
                // suffix, or punycode gate — hardening builds) and witnessed
                // it with the refused value. §5.3 steps 5-6 both end in
                // "ignore the cookie" for a refused domain naming any foreign
                // host; naming the origin itself is step 5's exception — the
                // cookie degrades to host-only, which is what the dropped
                // attribute already yields.
                if let Some(refused) = refused_domain(&issues) {
                    let refused = refused.strip_prefix('.').unwrap_or(refused);
                    if !refused.is_empty() && canonicalize(refused) != origin_host {
                        return Insertion::Rejected(RejectionReason::InvalidDomain);
                    }
                }
                (true, origin_host)
            }
        };

        // RFC 6265bis §5.5: a Secure cookie may only be set over a secure
        // origin…
        if attrs.secure && !origin_secure {
            return Insertion::Rejected(RejectionReason::InsecureOrigin);
        }
        // …and the prefix / CHIPS requirements are storage gates. The parse
        // already witnessed any violation; only the canonical-case note is
        // not one (engines store a case-variant prefix whose requirements
        // hold — kekse's own parser matrix pins that behavior).
        if issues.iter().any(|issue| {
            matches!(
                issue,
                SetCookieIssue::ConstraintViolation { constraint }
                    if !matches!(constraint, CookieConstraint::NonCanonicalPrefixCase)
            )
        }) {
            return Insertion::Rejected(RejectionReason::ConstraintViolation);
        }

        // §5.3 step 7 — the path: a `/`-rooted Path attribute, else the
        // origin's default-path (§5.2.4 sends a relative Path there too).
        let path = match attrs.path.map(|p| p.as_str()) {
            Some(p) if p.starts_with('/') => p.to_owned(),
            _ => default_path(origin_path).to_owned(),
        };

        // §5.3 step 3 — expiry, as unix seconds: Max-Age wins over Expires,
        // and a witnessed negative Max-Age (§5.2.2's `-` branch, which the
        // u64 attribute cannot hold) means "expire now".
        let now_ts = now.unix_timestamp();
        let expires_at = if negative_max_age(&issues) {
            Some(now_ts)
        } else if let Some(seconds) = attrs.max_age {
            Some(now_ts.saturating_add_unsigned(seconds).min(MAX_EXPIRY_TS))
        } else {
            attrs.expires.map(OffsetDateTime::unix_timestamp)
        };

        // Born expired — the §5.3 deletion idiom: evict the identity twin,
        // store nothing.
        if expires_at.is_some_and(|at| at <= now_ts) {
            self.remove_stored(cookie.name(), &domain, &path);
            return Insertion::Deleted;
        }

        // §5.3 step 11 — same (name, domain, path) replaces, keeping the
        // original creation order (step 11.3).
        if let Some(existing) = self
            .cookies
            .iter_mut()
            .find(|c| c.name == cookie.name() && c.domain == domain && c.path == path)
        {
            existing.value = cookie.value().to_owned();
            existing.host_only = host_only;
            existing.secure = attrs.secure;
            existing.http_only = attrs.http_only;
            existing.partitioned = attrs.partitioned;
            existing.same_site = attrs.same_site;
            existing.expires_at = expires_at;
            return Insertion::Replaced;
        }

        self.cookies.push(StoredCookie {
            name: cookie.name().to_owned(),
            value: cookie.value().to_owned(),
            domain,
            host_only,
            path,
            secure: attrs.secure,
            http_only: attrs.http_only,
            partitioned: attrs.partitioned,
            same_site: attrs.same_site,
            expires_at,
            created: self.next_created,
        });
        self.next_created += 1;
        self.enforce_caps(now_ts);
        Insertion::Stored
    }

    /// Ingest several `Set-Cookie` header values from one response, in order.
    /// Per-line outcomes are discarded — use [`insert`](CookieStore::insert)
    /// where they matter.
    pub fn insert_all<'s>(
        &mut self,
        origin: &url::Url,
        lines: impl IntoIterator<Item = &'s str>,
        now: OffsetDateTime,
    ) {
        for line in lines {
            let _ = self.insert(origin, line, now);
        }
    }

    /// Ingest every `Set-Cookie` header of a response's [`http::HeaderMap`],
    /// in order. A header value that is not valid UTF-8 is skipped (the parse
    /// boundary is `&str`); per-line outcomes are discarded — use
    /// [`insert`](CookieStore::insert) where they matter.
    pub fn insert_response(
        &mut self,
        origin: &url::Url,
        headers: &http::HeaderMap,
        now: OffsetDateTime,
    ) {
        self.insert_all(
            origin,
            headers
                .get_all(http::header::SET_COOKIE)
                .into_iter()
                .filter_map(|value| value.to_str().ok()),
            now,
        );
    }

    /// The cookies to attach to a request, per RFC 6265 §5.4: not expired at
    /// `now`, `Secure` only onto a secure request (a TLS scheme or a loopback
    /// destination), host or domain match, path match — ordered per §5.4.2
    /// (longest path first, then earliest creation). A hostless URL matches
    /// nothing.
    pub fn matches<'s>(
        &'s self,
        request: &url::Url,
        now: OffsetDateTime,
    ) -> impl Iterator<Item = StoredRef<'s>> + 's {
        let now_ts = now.unix_timestamp();
        let mut hits: Vec<&StoredCookie> = match url_parts(request) {
            Some((host, path, secure)) => {
                let host = canonicalize(host);
                self.cookies
                    .iter()
                    .filter(|c| {
                        !c.expired(now_ts)
                            && (!c.secure || secure)
                            && (if c.host_only {
                                host == c.domain
                            } else {
                                domain_matches(&host, &c.domain)
                            })
                            && path_matches(path, &c.path)
                    })
                    .collect()
            }
            // A URL without a host (mailto:, data:) matches no cookie.
            None => Vec::new(),
        };
        // §5.4.2: longer paths first; equal lengths by earlier creation.
        hits.sort_unstable_by(|a, b| {
            b.path
                .len()
                .cmp(&a.path.len())
                .then(a.created.cmp(&b.created))
        });
        hits.into_iter().map(StoredRef)
    }

    /// The request `Cookie:` header for `request` — the
    /// [`matches`](CookieStore::matches) rendered through a
    /// [`CookieJar`](crate::CookieJar) with the canonical
    /// [`Percent`](crate::ValueEncoding::Percent) encoding — or `None` when
    /// nothing matches (send no header at all, rather than an empty one).
    #[must_use]
    pub fn cookie_header(
        &self,
        request: &url::Url,
        now: OffsetDateTime,
    ) -> Option<http::HeaderValue> {
        let mut jar = CookieJar::new();
        for cookie in self.matches(request, now) {
            jar.add(Cookie::new(cookie.name(), cookie.value()));
        }
        if jar.is_empty() {
            return None;
        }
        // Infallible by construction: every stored name passed the parse's
        // token gate and Percent emits only header-valid bytes.
        Some(
            jar.to_header_value(ValueEncoding::Percent)
                .expect("stored names are tokens and Percent output is header-valid"),
        )
    }

    /// Every stored cookie, in storage order — including cookies already
    /// expired but not yet purged ([`purge_expired`](CookieStore::purge_expired)).
    pub fn iter(&self) -> impl Iterator<Item = StoredRef<'_>> {
        self.cookies.iter().map(StoredRef)
    }

    /// Every stored cookie with this name (any domain and path), in storage
    /// order.
    pub fn get<'s>(&'s self, name: &'s str) -> impl Iterator<Item = StoredRef<'s>> + 's {
        self.iter().filter(move |c| c.name() == name)
    }

    /// Remove the cookie with exactly this `(name, domain, path)` identity —
    /// `domain` is the effective domain (the setting host for a host-only
    /// cookie); a leading dot is stripped and the comparison is
    /// case-insensitive, like storage. `true` iff a cookie was removed.
    pub fn remove(&mut self, name: &str, domain: &str, path: &str) -> bool {
        let domain = domain.strip_prefix('.').unwrap_or(domain);
        self.remove_stored(name, &canonicalize(domain), path)
    }

    /// Drop every cookie.
    pub fn clear(&mut self) {
        self.cookies.clear();
    }

    /// Drop every cookie expired at `now`. Retrieval already filters expiry,
    /// so this is housekeeping, not correctness.
    pub fn purge_expired(&mut self, now: OffsetDateTime) {
        let now_ts = now.unix_timestamp();
        self.cookies.retain(|c| !c.expired(now_ts));
    }

    /// The number of stored cookies — including expired-but-unpurged ones.
    #[must_use]
    pub fn len(&self) -> usize {
        self.cookies.len()
    }

    /// Whether the store holds no cookies at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cookies.is_empty()
    }

    fn remove_stored(&mut self, name: &str, domain: &str, path: &str) -> bool {
        let before = self.cookies.len();
        self.cookies
            .retain(|c| !(c.name == name && c.domain == domain && c.path == path));
        before != self.cookies.len()
    }

    /// Enforce [`StoreConfig`]: purge expired cookies, then keep the newest
    /// `max_cookies_per_domain` of each effective domain and the newest
    /// `max_cookies` overall, evicting oldest-by-creation.
    fn enforce_caps(&mut self, now_ts: i64) {
        if self.cookies.len() <= self.config.max_cookies
            && self.cookies.len() <= self.config.max_cookies_per_domain
        {
            return;
        }
        self.cookies.retain(|c| !c.expired(now_ts));
        let dropped = {
            let mut order: Vec<usize> = (0..self.cookies.len()).collect();
            order.sort_unstable_by_key(|&i| std::cmp::Reverse(self.cookies[i].created));
            let mut per_domain: HashMap<&str, usize> = HashMap::new();
            let mut kept_total = 0;
            let mut dropped = vec![false; self.cookies.len()];
            for &i in &order {
                let of_domain = per_domain
                    .entry(self.cookies[i].domain.as_str())
                    .or_insert(0);
                if *of_domain >= self.config.max_cookies_per_domain
                    || kept_total >= self.config.max_cookies
                {
                    dropped[i] = true;
                } else {
                    *of_domain += 1;
                    kept_total += 1;
                }
            }
            dropped
        };
        let mut index = 0;
        self.cookies.retain(|_| {
            let keep = !dropped[index];
            index += 1;
            keep
        });
    }
}

/// One cookie of the persisted representation (`serde` feature) — the store's
/// matching state as plain data, never the codec's wire types.
#[cfg(feature = "serde")]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PersistedCookie {
    /// The cookie-name.
    pub name: String,
    /// The decoded logical value.
    pub value: String,
    /// The effective domain, canonicalized (the setting host when
    /// `host_only`).
    pub domain: String,
    /// Whether the cookie matches only its exact setting host.
    pub host_only: bool,
    /// The cookie path.
    pub path: String,
    /// The `Secure` flag.
    pub secure: bool,
    /// The `HttpOnly` flag.
    pub http_only: bool,
    /// The `Partitioned` flag (CHIPS).
    pub partitioned: bool,
    /// The `SameSite` attribute as its canonical token (`Strict` / `Lax` /
    /// `None`), if set.
    pub same_site: Option<String>,
    /// Expiry in unix seconds; `None` is a session cookie.
    pub expires_at: Option<i64>,
}

/// A [`CookieStore`]'s persisted representation (`serde` feature): the stored
/// cookies in creation order, ready for any serde format. Produced by
/// [`CookieStore::export`], consumed by [`CookieStore::import`].
#[cfg(feature = "serde")]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PersistedStore {
    /// The stored cookies, in creation order.
    pub cookies: Vec<PersistedCookie>,
}

#[cfg(feature = "serde")]
impl CookieStore {
    /// Export the stored representation for persistence: every cookie —
    /// session cookies and the expired-but-unpurged included — in creation
    /// order, as plain data.
    #[must_use]
    pub fn export(&self) -> PersistedStore {
        PersistedStore {
            cookies: self
                .cookies
                .iter()
                .map(|c| PersistedCookie {
                    name: c.name.clone(),
                    value: c.value.clone(),
                    domain: c.domain.clone(),
                    host_only: c.host_only,
                    path: c.path.clone(),
                    secure: c.secure,
                    http_only: c.http_only,
                    partitioned: c.partitioned,
                    same_site: c.same_site.map(|s| s.to_string()),
                    expires_at: c.expires_at,
                })
                .collect(),
        }
    }

    /// Rebuild a store from its persisted representation, under `config`:
    /// list order becomes creation order, cookies already expired at `now`
    /// are dropped, and the capacity caps apply immediately. Import trusts
    /// its input — the persisted form is the caller's own export — and an
    /// unrecognized `same_site` token degrades to unset.
    #[must_use]
    pub fn import(persisted: PersistedStore, config: StoreConfig, now: OffsetDateTime) -> Self {
        let mut store = Self::with_config(config);
        for (created, c) in persisted.cookies.into_iter().enumerate() {
            store.cookies.push(StoredCookie {
                name: c.name,
                value: c.value,
                domain: c.domain,
                host_only: c.host_only,
                path: c.path,
                secure: c.secure,
                http_only: c.http_only,
                partitioned: c.partitioned,
                same_site: c.same_site.as_deref().and_then(|s| s.parse().ok()),
                expires_at: c.expires_at,
                created: created as u64,
            });
        }
        store.next_created = store.cookies.len() as u64;
        store.purge_expired(now);
        store.enforce_caps(now.unix_timestamp());
        store
    }
}

/// The last refused `Domain` value the parse witnessed —
/// [`InvalidAttributeValue`](SetCookieIssue::InvalidAttributeValue) on
/// [`Domain`](KnownAttribute::Domain). Last, because RFC 6265 §5.3 reads the
/// final occurrence of an attribute.
fn refused_domain<'a>(issues: &[SetCookieIssue<'a>]) -> Option<&'a str> {
    issues.iter().rev().find_map(|issue| match issue {
        SetCookieIssue::InvalidAttributeValue {
            attribute: KnownAttribute::Domain,
            value,
        } => Some(*value),
        _ => None,
    })
}

/// Whether the parse witnessed a negative `Max-Age` — `-` followed by digits,
/// the RFC 6265 §5.2.2 shape meaning "expire now", which the `u64` attribute
/// cannot hold. Any occurrence counts: a deletion intent is honored even in
/// the degenerate mixed-duplicates case.
fn negative_max_age(issues: &[SetCookieIssue<'_>]) -> bool {
    issues.iter().any(|issue| {
        matches!(
            issue,
            SetCookieIssue::InvalidAttributeValue {
                attribute: KnownAttribute::MaxAge,
                value,
            } if value
                .strip_prefix('-')
                .is_some_and(|digits| !digits.is_empty()
                    && digits.bytes().all(|b| b.is_ascii_digit()))
        )
    })
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::*;

    fn now() -> OffsetDateTime {
        datetime!(2026-07-11 12:00 UTC)
    }

    fn u(s: &str) -> url::Url {
        url::Url::parse(s).expect("test url")
    }

    /// The rendered `Cookie:` header, or `""` when nothing matches.
    fn header(store: &CookieStore, url: &url::Url, at: OffsetDateTime) -> String {
        store
            .cookie_header(url, at)
            .map(|h| {
                h.to_str()
                    .expect("percent-encoded header is ASCII")
                    .to_owned()
            })
            .unwrap_or_default()
    }

    #[test]
    fn host_only_cookie_matches_exactly_its_setting_host() {
        let mut store = CookieStore::new();
        assert_eq!(
            store.insert(&u("https://a.example.test/"), "SID=x", now()),
            Insertion::Stored
        );
        assert_eq!(
            header(&store, &u("https://a.example.test/"), now()),
            "SID=x"
        );
        // Neither a sibling nor a subdomain of the setting host sees it.
        assert_eq!(header(&store, &u("https://b.example.test/"), now()), "");
        assert_eq!(header(&store, &u("https://sub.a.example.test/"), now()), "");
        let stored = store.iter().next().unwrap();
        assert!(stored.host_only());
        assert_eq!(stored.domain(), "a.example.test");
    }

    #[test]
    fn domain_cookie_covers_subdomains_not_siblings() {
        let mut store = CookieStore::new();
        // The §5.2.3 leading-dot wire form is stripped for matching.
        assert_eq!(
            store.insert(
                &u("https://www.example.test/"),
                "SID=x; Domain=.example.test",
                now()
            ),
            Insertion::Stored
        );
        for host in ["example.test", "www.example.test", "deep.sub.example.test"] {
            assert_eq!(
                header(&store, &u(&format!("https://{host}/")), now()),
                "SID=x",
                "{host}"
            );
        }
        assert_eq!(header(&store, &u("https://other.test/"), now()), "");
        assert_eq!(header(&store, &u("https://badexample.test/"), now()), "");
        let stored = store.iter().next().unwrap();
        assert!(!stored.host_only());
        assert_eq!(stored.domain(), "example.test");
    }

    #[test]
    fn foreign_domain_is_the_anti_planting_rejection() {
        let mut store = CookieStore::new();
        // A sibling's domain, and a *deeper* domain than the origin: neither
        // is domain-matched by the origin host (§5.3 step 6).
        for wire in [
            "SID=x; Domain=victim.test",
            "SID=x; Domain=sub.example.test",
        ] {
            assert_eq!(
                store.insert(&u("https://example.test/"), wire, now()),
                Insertion::Rejected(RejectionReason::DomainMismatch),
                "{wire}"
            );
        }
        assert!(store.is_empty());
    }

    #[test]
    fn empty_domain_attribute_degrades_to_host_only() {
        // §5.2.3's SHOULD: an empty Domain value is ignored — including the
        // bare-dot form that strips to empty.
        for wire in ["SID=x; Domain=", "SID=x; Domain=."] {
            let mut store = CookieStore::new();
            assert_eq!(
                store.insert(&u("https://example.test/"), wire, now()),
                Insertion::Stored,
                "{wire}"
            );
            let stored = store.iter().next().unwrap();
            assert!(stored.host_only(), "{wire}");
            assert_eq!(header(&store, &u("https://sub.example.test/"), now()), "");
        }
    }

    #[cfg(not(feature = "psl"))]
    #[test]
    fn without_psl_a_public_suffix_domain_is_the_bare_rfc_attach() {
        // The §5.3 step 5 rejection is conditional on a public-suffix-aware
        // agent; without the `psl` tables kekse is not one, and the bare RFC
        // stores the supercookie. The psl twin below pins the defense.
        let mut store = CookieStore::new();
        assert_eq!(
            store.insert(&u("https://foo.com/"), "SID=x; Domain=com", now()),
            Insertion::Stored
        );
        assert_eq!(header(&store, &u("https://bar.com/"), now()), "SID=x");
    }

    #[cfg(feature = "psl")]
    #[test]
    fn with_psl_a_foreign_public_suffix_domain_rejects_the_cookie() {
        let mut store = CookieStore::new();
        assert_eq!(
            store.insert(&u("https://foo.com/"), "SID=x; Domain=com", now()),
            Insertion::Rejected(RejectionReason::InvalidDomain)
        );
        assert!(store.is_empty());
    }

    #[cfg(feature = "psl")]
    #[test]
    fn with_psl_the_origin_on_the_suffix_itself_degrades_to_host_only() {
        // §5.3 step 5's exception: a site *on* a public suffix (github.io is
        // one) naming itself keeps the cookie, host-only.
        let mut store = CookieStore::new();
        assert_eq!(
            store.insert(&u("https://github.io/"), "SID=x; Domain=github.io", now()),
            Insertion::Stored
        );
        let stored = store.iter().next().unwrap();
        assert!(stored.host_only());
        assert_eq!(header(&store, &u("https://github.io/"), now()), "SID=x");
        assert_eq!(header(&store, &u("https://user.github.io/"), now()), "");
    }

    #[test]
    fn hosts_and_domains_compare_canonicalized() {
        let mut store = CookieStore::new();
        assert_eq!(
            store.insert(
                &u("https://WWW.Example.TEST/"),
                "SID=x; Domain=EXAMPLE.test",
                now()
            ),
            Insertion::Stored
        );
        assert_eq!(store.iter().next().unwrap().domain(), "example.test");
        assert_eq!(
            header(&store, &u("https://www.example.test/"), now()),
            "SID=x"
        );
    }

    #[test]
    fn path_attribute_scopes_and_default_path_applies() {
        let mut store = CookieStore::new();
        let origin = u("https://example.test/a/b/c");
        // An explicit rooted Path wins over the origin's path…
        assert_eq!(
            store.insert(&origin, "scoped=1; Path=/app", now()),
            Insertion::Stored
        );
        // …no Path (and a non-rooted Path, §5.2.4) takes the default-path.
        assert_eq!(store.insert(&origin, "def=1", now()), Insertion::Stored);
        assert_eq!(
            store.insert(&origin, "rel=1; Path=nope", now()),
            Insertion::Stored
        );

        assert_eq!(
            header(&store, &u("https://example.test/app/x"), now()),
            "scoped=1"
        );
        assert_eq!(header(&store, &u("https://example.test/apple"), now()), "");
        // default-path of /a/b/c is /a/b: covers /a/b and below, not /a.
        assert_eq!(
            header(&store, &u("https://example.test/a/b/x"), now()),
            "def=1; rel=1"
        );
        assert_eq!(header(&store, &u("https://example.test/a"), now()), "");
        for c in store.iter().filter(|c| c.name() != "scoped") {
            assert_eq!(c.path(), "/a/b");
        }
    }

    #[test]
    fn secure_cookie_needs_a_secure_origin_and_a_secure_request() {
        let mut store = CookieStore::new();
        // RFC 6265bis §5.5: setting over an insecure origin is refused…
        assert_eq!(
            store.insert(&u("http://example.test/"), "SID=x; Secure", now()),
            Insertion::Rejected(RejectionReason::InsecureOrigin)
        );
        // …setting over a secure one sticks, and §5.4 gates the send side.
        assert_eq!(
            store.insert(&u("https://example.test/"), "SID=x; Secure", now()),
            Insertion::Stored
        );
        assert_eq!(header(&store, &u("http://example.test/"), now()), "");
        assert_eq!(header(&store, &u("https://example.test/"), now()), "SID=x");
        // A non-Secure cookie still travels both ways.
        assert_eq!(
            store.insert(&u("http://example.test/"), "plain=1", now()),
            Insertion::Stored
        );
        assert_eq!(header(&store, &u("http://example.test/"), now()), "plain=1");
    }

    #[test]
    fn prefix_requirements_gate_storage() {
        let mut store = CookieStore::new();
        let origin = u("https://example.test/");
        let rejected = Insertion::Rejected(RejectionReason::ConstraintViolation);
        // Each unmet __Host- requirement refuses the cookie…
        assert_eq!(store.insert(&origin, "__Host-a=1; Path=/", now()), rejected);
        assert_eq!(store.insert(&origin, "__Host-a=1; Secure", now()), rejected);
        assert_eq!(
            store.insert(
                &origin,
                "__Host-a=1; Secure; Path=/; Domain=example.test",
                now()
            ),
            rejected
        );
        // …and so do the __Secure- and CHIPS pairings.
        assert_eq!(store.insert(&origin, "__Secure-b=1", now()), rejected);
        assert_eq!(
            store.insert(&origin, "part=1; Partitioned", now()),
            rejected
        );
        assert!(store.is_empty());
        // The conformant shapes store.
        assert_eq!(
            store.insert(&origin, "__Host-a=1; Secure; Path=/", now()),
            Insertion::Stored
        );
        assert_eq!(
            store.insert(&origin, "__Secure-b=1; Secure", now()),
            Insertion::Stored
        );
        assert_eq!(
            store.insert(&origin, "part=1; Partitioned; Secure", now()),
            Insertion::Stored
        );
        let part = store.get("part").next().unwrap();
        assert!(part.partitioned() && part.secure());
    }

    #[test]
    fn a_case_variant_prefix_with_met_requirements_stores_verbatim() {
        // Engines enforce prefix requirements case-insensitively but keep a
        // case-variant spelling whose requirements hold (the parser matrix's
        // prefix-host-case-conformant cell) — the casing note is a witness for
        // the codec's callers, not a storage gate.
        let mut store = CookieStore::new();
        let origin = u("https://example.test/");
        assert_eq!(
            store.insert(&origin, "__host-SID=x; Secure; Path=/", now()),
            Insertion::Stored
        );
        assert_eq!(store.iter().next().unwrap().name(), "__host-SID");
        // A case-variant spelling does not dodge the requirements themselves.
        assert_eq!(
            store.insert(&origin, "__host-other=x", now()),
            Insertion::Rejected(RejectionReason::ConstraintViolation)
        );
    }

    #[test]
    fn max_age_expires_and_wins_over_expires() {
        let mut store = CookieStore::new();
        let origin = u("https://example.test/");
        assert_eq!(
            store.insert(&origin, "short=1; Max-Age=60", now()),
            Insertion::Stored
        );
        // Max-Age wins over a conflicting Expires in either direction (§5.3
        // step 3): a past Expires does not shorten it…
        assert_eq!(
            store.insert(
                &origin,
                "mixed=1; Max-Age=60; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
                now()
            ),
            Insertion::Stored
        );
        // …and a far-future Expires does not extend a zero Max-Age.
        assert_eq!(
            store.insert(
                &origin,
                "gone=1; Expires=Fri, 31 Dec 9999 23:59:59 GMT; Max-Age=0",
                now()
            ),
            Insertion::Deleted
        );
        let at = |secs: i64| now() + time::Duration::seconds(secs);
        assert_eq!(header(&store, &origin, at(30)), "short=1; mixed=1");
        assert_eq!(header(&store, &origin, at(61)), "");
        assert_eq!(
            store.get("short").next().unwrap().expires(),
            Some(now() + time::Duration::seconds(60))
        );
    }

    #[test]
    fn negative_max_age_is_the_delete_idiom() {
        let mut store = CookieStore::new();
        let origin = u("https://example.test/");
        // §5.2.2's `-` branch: valid wire the u64 attribute cannot hold — the
        // witness carries it, and the store honors the deletion.
        assert_eq!(store.insert(&origin, "SID=x", now()), Insertion::Stored);
        assert_eq!(
            store.insert(&origin, "SID=; Max-Age=-1", now()),
            Insertion::Deleted
        );
        assert!(store.is_empty());
        // Deleted is reported even with nothing to delete…
        assert_eq!(
            store.insert(&origin, "SID=; Max-Age=-1", now()),
            Insertion::Deleted
        );
        // …and a genuinely malformed Max-Age is not a deletion: the attribute
        // drops, the cookie stays a session cookie.
        assert_eq!(
            store.insert(&origin, "keep=1; Max-Age=banana", now()),
            Insertion::Stored
        );
        assert_eq!(store.get("keep").next().unwrap().expires(), None);
    }

    #[test]
    fn a_past_expires_deletes_the_identity_twin() {
        let mut store = CookieStore::new();
        let origin = u("https://example.test/");
        assert_eq!(
            store.insert(&origin, "SID=x; Path=/", now()),
            Insertion::Stored
        );
        assert_eq!(
            store.insert(
                &origin,
                "SID=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
                now()
            ),
            Insertion::Deleted
        );
        assert!(store.is_empty());
    }

    #[test]
    fn a_session_cookie_outlives_any_clock() {
        let mut store = CookieStore::new();
        let origin = u("https://example.test/");
        assert_eq!(store.insert(&origin, "SID=x", now()), Insertion::Stored);
        let far = datetime!(9999-01-01 0:00 UTC);
        assert_eq!(header(&store, &origin, far), "SID=x");
    }

    #[test]
    fn replacement_keeps_the_creation_order() {
        let mut store = CookieStore::new();
        let origin = u("https://example.test/");
        assert_eq!(store.insert(&origin, "first=1", now()), Insertion::Stored);
        assert_eq!(store.insert(&origin, "second=1", now()), Insertion::Stored);
        // Same (name, domain, path) identity: replaced, not re-created —
        // §5.4.2's equal-path tie still orders it first.
        assert_eq!(store.insert(&origin, "first=2", now()), Insertion::Replaced);
        assert_eq!(store.len(), 2);
        assert_eq!(header(&store, &origin, now()), "first=2; second=1");
    }

    #[test]
    fn a_domain_variant_replaces_its_host_only_identity_twin() {
        // §5.3 step 11 keys identity on (name, domain, path) — the host-only
        // flag is payload, so the Domain form takes over the identity.
        let mut store = CookieStore::new();
        let origin = u("https://example.test/");
        assert_eq!(store.insert(&origin, "SID=a", now()), Insertion::Stored);
        assert_eq!(
            store.insert(&origin, "SID=b; Domain=example.test", now()),
            Insertion::Replaced
        );
        let stored = store.iter().next().unwrap();
        assert!(!stored.host_only());
        assert_eq!(
            header(&store, &u("https://sub.example.test/"), now()),
            "SID=b"
        );
    }

    #[test]
    fn ordering_is_longest_path_then_creation() {
        let mut store = CookieStore::new();
        let origin = u("https://example.test/a/b");
        assert_eq!(
            store.insert(&origin, "root=1; Path=/", now()),
            Insertion::Stored
        );
        assert_eq!(
            store.insert(&origin, "deep=1; Path=/a/b", now()),
            Insertion::Stored
        );
        assert_eq!(
            store.insert(&origin, "mid=1; Path=/a", now()),
            Insertion::Stored
        );
        assert_eq!(
            store.insert(&origin, "deep2=1; Path=/a/b", now()),
            Insertion::Stored
        );
        assert_eq!(
            header(&store, &origin, now()),
            "deep=1; deep2=1; mid=1; root=1"
        );
    }

    #[test]
    fn the_per_domain_cap_evicts_the_oldest_of_that_domain() {
        let mut store = CookieStore::with_config(StoreConfig {
            max_cookies: 100,
            max_cookies_per_domain: 2,
        });
        let a = u("https://a.test/");
        let b = u("https://b.test/");
        assert_eq!(store.insert(&a, "a1=1", now()), Insertion::Stored);
        assert_eq!(store.insert(&b, "b1=1", now()), Insertion::Stored);
        assert_eq!(store.insert(&a, "a2=1", now()), Insertion::Stored);
        assert_eq!(store.insert(&a, "a3=1", now()), Insertion::Stored);
        // a1 (oldest of a.test) fell; b.test was never touched.
        assert_eq!(header(&store, &a, now()), "a2=1; a3=1");
        assert_eq!(header(&store, &b, now()), "b1=1");
    }

    #[test]
    fn the_global_cap_evicts_the_oldest_overall() {
        let mut store = CookieStore::with_config(StoreConfig {
            max_cookies: 2,
            max_cookies_per_domain: 100,
        });
        assert_eq!(
            store.insert(&u("https://a.test/"), "a=1", now()),
            Insertion::Stored
        );
        assert_eq!(
            store.insert(&u("https://b.test/"), "b=1", now()),
            Insertion::Stored
        );
        assert_eq!(
            store.insert(&u("https://c.test/"), "c=1", now()),
            Insertion::Stored
        );
        assert_eq!(store.len(), 2);
        assert_eq!(header(&store, &u("https://a.test/"), now()), "");
        assert_eq!(header(&store, &u("https://c.test/"), now()), "c=1");
    }

    #[test]
    fn eviction_prefers_expired_cookies_over_live_ones() {
        let mut store = CookieStore::with_config(StoreConfig {
            max_cookies: 2,
            max_cookies_per_domain: 2,
        });
        let origin = u("https://example.test/");
        assert_eq!(store.insert(&origin, "old=1", now()), Insertion::Stored);
        assert_eq!(
            store.insert(&origin, "brief=1; Max-Age=1", now()),
            Insertion::Stored
        );
        // Two seconds later the cap is hit again: the expired cookie goes
        // first, not the oldest live one.
        let later = now() + time::Duration::seconds(2);
        assert_eq!(store.insert(&origin, "new=1", later), Insertion::Stored);
        assert_eq!(header(&store, &origin, later), "old=1; new=1");
    }

    #[test]
    fn manage_remove_get_iter_clear_purge() {
        let mut store = CookieStore::new();
        let origin = u("https://example.test/a/b");
        assert_eq!(
            store.insert(&origin, "SID=x; Path=/", now()),
            Insertion::Stored
        );
        // A distinct path is a distinct §5.3 identity, so this is a second
        // SID cookie, not a replacement of the first.
        assert_eq!(
            store.insert(&origin, "SID=y; Domain=.Example.test; Path=/other", now()),
            Insertion::Stored
        );
        assert_eq!(
            store.insert(&origin, "tmp=1; Max-Age=10", now()),
            Insertion::Stored
        );
        assert_eq!(store.get("SID").count(), 2);
        assert_eq!(store.iter().count(), 3);
        assert_eq!(store.len(), 3);
        // remove takes the effective-domain identity, dot- and case-tolerant.
        assert!(store.remove("SID", ".EXAMPLE.test", "/other"));
        assert!(!store.remove("SID", "other.test", "/"));
        assert_eq!(store.get("SID").count(), 1);
        // purge_expired is by-time housekeeping; len counts what is held.
        store.purge_expired(now() + time::Duration::seconds(11));
        assert_eq!(store.len(), 1);
        store.clear();
        assert!(store.is_empty());
        assert_eq!(store.cookie_header(&origin, now()), None);
    }

    #[test]
    fn malformed_lines_and_a_hostless_origin_are_rejected() {
        let mut store = CookieStore::new();
        let origin = u("https://example.test/");
        for wire in ["garbage", "=v", " ; "] {
            assert_eq!(
                store.insert(&origin, wire, now()),
                Insertion::Rejected(RejectionReason::Malformed),
                "{wire}"
            );
        }
        // A URL without a host has nothing to key a cookie to…
        assert_eq!(
            store.insert(&u("mailto:x@example.test"), "SID=x", now()),
            Insertion::Rejected(RejectionReason::Malformed)
        );
        assert!(store.is_empty());
        // …and matches nothing on the way out either.
        assert_eq!(store.insert(&origin, "SID=x", now()), Insertion::Stored);
        assert_eq!(
            store.cookie_header(&u("mailto:x@example.test"), now()),
            None
        );
        assert_eq!(store.cookie_header(&u("data:text/plain,hi"), now()), None);
    }

    #[test]
    fn loopback_origins_count_as_secure() {
        // The trustworthy-origin convention: `Secure` works on loopback over
        // plain http — ingest and send — but never on other plain-http hosts.
        for origin in [
            "http://127.0.0.1/",
            "http://127.9.9.9/",
            "http://[::1]/",
            "http://localhost/",
            "http://app.localhost/",
        ] {
            let mut store = CookieStore::new();
            assert_eq!(
                store.insert(&u(origin), "SID=x; Secure", now()),
                Insertion::Stored,
                "{origin}"
            );
            assert_eq!(header(&store, &u(origin), now()), "SID=x", "{origin}");
        }
        let mut store = CookieStore::new();
        assert_eq!(
            store.insert(&u("http://192.168.0.1/"), "SID=x; Secure", now()),
            Insertion::Rejected(RejectionReason::InsecureOrigin)
        );
    }

    #[test]
    fn wss_is_a_tls_scheme_and_ws_is_not() {
        let mut store = CookieStore::new();
        assert_eq!(
            store.insert(&u("wss://example.test/"), "SID=x; Secure", now()),
            Insertion::Stored
        );
        assert_eq!(header(&store, &u("wss://example.test/"), now()), "SID=x");
        assert_eq!(header(&store, &u("ws://example.test/"), now()), "");
    }

    #[test]
    fn a_huge_max_age_saturates_inside_the_datetime_range() {
        // The clamp constant is the top of OffsetDateTime's range: pin both
        // sides so the constant cannot drift from the `time` crate.
        assert!(OffsetDateTime::from_unix_timestamp(MAX_EXPIRY_TS).is_ok());
        assert!(OffsetDateTime::from_unix_timestamp(MAX_EXPIRY_TS + 1).is_err());
        let mut store = CookieStore::new();
        let origin = u("https://example.test/");
        assert_eq!(
            store.insert(&origin, "SID=x; Max-Age=18446744073709551615", now()),
            Insertion::Stored
        );
        assert_eq!(
            store.get("SID").next().unwrap().expires(),
            Some(OffsetDateTime::from_unix_timestamp(MAX_EXPIRY_TS).unwrap())
        );
    }

    #[test]
    fn insert_all_and_insert_response_walk_every_line() {
        let origin = u("https://example.test/");
        let mut store = CookieStore::new();
        store.insert_all(&origin, ["a=1", "b=2; Max-Age=-1", "garbage"], now());
        assert_eq!(header(&store, &origin, now()), "a=1");

        let mut headers = http::HeaderMap::new();
        headers.append(http::header::SET_COOKIE, "c=3".parse().unwrap());
        headers.append(http::header::SET_COOKIE, "d=4; Secure".parse().unwrap());
        let mut store = CookieStore::new();
        store.insert_response(&origin, &headers, now());
        assert_eq!(header(&store, &origin, now()), "c=3; d=4");
    }

    #[test]
    fn http_only_and_same_site_are_surfaced_not_enforced() {
        let mut store = CookieStore::new();
        let origin = u("https://example.test/");
        assert_eq!(
            store.insert(&origin, "SID=x; HttpOnly; SameSite=Strict", now()),
            Insertion::Stored
        );
        let stored = store.iter().next().unwrap();
        assert!(stored.http_only());
        assert_eq!(stored.same_site(), Some(SameSite::Strict));
        // HttpOnly guards scripts, not requests; SameSite needs the caller's
        // site-for-cookies — both still travel.
        assert_eq!(header(&store, &origin, now()), "SID=x");
    }

    #[test]
    fn values_round_trip_decoded_and_render_canonically() {
        let mut store = CookieStore::new();
        let origin = u("https://example.test/");
        // A quoted wire value arrives decoded (the codec's lenient pipeline)…
        assert_eq!(
            store.insert(&origin, "pref=\"dark mode\"", now()),
            Insertion::Stored
        );
        assert_eq!(store.get("pref").next().unwrap().value(), "dark mode");
        // …and leaves canonically percent-encoded.
        assert_eq!(header(&store, &origin, now()), "pref=dark%20mode");
    }
}

#[cfg(all(test, feature = "serde"))]
mod serde_tests {
    use time::macros::datetime;

    use super::*;

    fn now() -> OffsetDateTime {
        datetime!(2026-07-11 12:00 UTC)
    }

    fn u(s: &str) -> url::Url {
        url::Url::parse(s).expect("test url")
    }

    #[test]
    fn export_import_round_trips_through_json() {
        let origin = u("https://shop.example.test/");
        let mut store = CookieStore::new();
        store.insert_all(
            &origin,
            [
                "SID=deadbeef; Secure; HttpOnly; SameSite=Strict; Path=/",
                "part=1; Partitioned; Secure",
                "theme=dark; Max-Age=3600",
                "wide=1; Domain=example.test",
            ],
            now(),
        );

        let json = serde_json::to_string(&store.export()).unwrap();
        let revived = CookieStore::import(
            serde_json::from_str(&json).unwrap(),
            StoreConfig::default(),
            now(),
        );

        // Identical matching behavior and §5.4.2 order…
        let request = u("https://shop.example.test/x");
        assert_eq!(
            revived.cookie_header(&request, now()),
            store.cookie_header(&request, now())
        );
        // …the flags and expiry survive as data…
        let sid = revived.get("SID").next().unwrap();
        assert!(sid.http_only() && sid.secure());
        assert_eq!(sid.same_site(), Some(SameSite::Strict));
        assert!(revived.get("part").next().unwrap().partitioned());
        assert_eq!(
            revived.get("theme").next().unwrap().expires(),
            store.get("theme").next().unwrap().expires()
        );
        // …and a second export is the same representation — a fixpoint.
        assert_eq!(revived.export(), store.export());
    }

    #[test]
    fn import_applies_now_and_the_caps() {
        let origin = u("https://example.test/");
        let mut store = CookieStore::new();
        store.insert_all(&origin, ["a=1", "b=2; Max-Age=60", "c=3", "d=4"], now());
        let persisted = store.export();

        // An hour later b has expired out at import; the cap of 2 then keeps
        // the newest of what survives.
        let later = now() + time::Duration::hours(1);
        let revived = CookieStore::import(
            persisted,
            StoreConfig {
                max_cookies: 2,
                max_cookies_per_domain: 2,
            },
            later,
        );
        let names: Vec<_> = revived.iter().map(|c| c.name().to_owned()).collect();
        assert_eq!(names, ["c", "d"]);

        // An unrecognized same_site token degrades to unset, never an error.
        let mut odd = store.export();
        odd.cookies.truncate(1);
        odd.cookies[0].same_site = Some("Sideways".to_owned());
        let revived = CookieStore::import(odd, StoreConfig::default(), now());
        assert_eq!(revived.iter().next().unwrap().same_site(), None);
    }
}
