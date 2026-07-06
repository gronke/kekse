// keksbruch Java sidecar.
//
// Reads base64-JSONL payload records on stdin and parses each with six JVM cookie
// parsers, emitting one normalized ParseOutcome per dependency. The columns:
//   - "Tomcat RFC6265" / "Tomcat legacy": org.apache.tomcat.util.http's strict
//     (RFC 6265) and lenient request-cookie processors. Request-only — the response
//     direction is n/a (Tomcat has no inbound Set-Cookie parser).
//   - "Jakarta RESTEasy" / "Jakarta Jersey": the jakarta.ws.rs cookie API parsed by
//     each provider (discovered via ServiceLoader and driven side by side), for both
//     directions — Cookie for requests, NewCookie for Set-Cookie responses.
//   - "java.net.HttpCookie": the JDK's built-in Set-Cookie parser. Response-only.
//   - "Apache HttpClient5": HttpClient 5's RFC 6265 cookie spec. Response-only — the
//     realistic redistributable stand-in for the (proprietary, unbundleable) Burp parser.
// Keycloak is deliberately not a column: it does not parse cookies itself but reads
// them through the JAX-RS layer (RESTEasy), so its parsing IS the "Jakarta RESTEasy"
// column. `--selfcheck` reports availability + versions, then exits.
// Full contract: ../PROTOCOL.md.

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.HttpCookie;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import java.util.ServiceLoader;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import jakarta.ws.rs.core.Cookie;
import jakarta.ws.rs.core.NewCookie;
import jakarta.ws.rs.ext.RuntimeDelegate;
import jakarta.ws.rs.ext.RuntimeDelegate.HeaderDelegate;

import org.apache.tomcat.util.buf.MessageBytes;
import org.apache.tomcat.util.http.CookieProcessor;
import org.apache.tomcat.util.http.LegacyCookieProcessor;
import org.apache.tomcat.util.http.MimeHeaders;
import org.apache.tomcat.util.http.Rfc6265CookieProcessor;
import org.apache.tomcat.util.http.ServerCookie;
import org.apache.tomcat.util.http.ServerCookies;

// Apache HttpClient 5 cookie API. Its Cookie type is referenced by its fully
// qualified name in the parse method, to avoid clashing with jakarta.ws.rs.core.Cookie.
import org.apache.hc.client5.http.cookie.CookieOrigin;
import org.apache.hc.client5.http.cookie.CookieSpec;
import org.apache.hc.client5.http.impl.cookie.RFC6265CookieSpecFactory;
import org.apache.hc.core5.http.message.BasicHeader;

public final class Sidecar {
    static final String TOMCAT_RFC = "Tomcat RFC6265";
    static final String TOMCAT_LEGACY = "Tomcat legacy";
    static final String JAKARTA_RESTEASY = "Jakarta RESTEasy";
    static final String JAKARTA_JERSEY = "Jakarta Jersey";
    static final String JDK_HTTPCOOKIE = "java.net.HttpCookie";
    static final String APACHE_HC5 = "Apache HttpClient5";

    // disableHtmlEscaping: keep '=', '<' etc. literal (still decodes identically on
    // the Rust side, but reads cleanly). serializeNulls: emit explicit `null` for
    // absent Set-Cookie attributes, matching the harness's `string or null` fields.
    static final Gson GSON =
        new GsonBuilder().disableHtmlEscaping().serializeNulls().create();

    // Tomcat request-cookie processors; null if the class fails to load.
    static CookieProcessor rfc;
    static CookieProcessor legacy;

    // Apache HttpClient 5's RFC 6265 cookie spec; null if the class fails to load.
    static CookieSpec hc5;

    // Per-provider header delegates, discovered via ServiceLoader; null if absent.
    static HeaderDelegate<Cookie> resteasyCookie;
    static HeaderDelegate<NewCookie> resteasyNewCookie;
    static HeaderDelegate<Cookie> jerseyCookie;
    static HeaderDelegate<NewCookie> jerseyNewCookie;

    // Library versions for the matrix footer. A shaded jar collapses per-jar
    // manifests, so these come from a build-filtered resource, not the manifest.
    static String tomcatVersion = "?";
    static String resteasyVersion = "?";
    static String jerseyVersion = "?";
    static String hc5Version = "?";

    public static void main(String[] args) throws IOException {
        loadVersions();
        initTomcat();
        initHc5();
        discoverProviders();
        for (String a : args) {
            if ("--selfcheck".equals(a)) {
                printSelfcheck();
                return;
            }
        }
        runLoop();
    }

    static void loadVersions() {
        try (InputStream in = Sidecar.class.getResourceAsStream("/sidecar-versions.properties")) {
            if (in != null) {
                Properties p = new Properties();
                p.load(in);
                tomcatVersion = p.getProperty("tomcat", "?");
                resteasyVersion = p.getProperty("resteasy", "?");
                jerseyVersion = p.getProperty("jersey", "?");
                hc5Version = p.getProperty("httpclient5", "?");
            }
        } catch (Throwable t) {
            // keep the "?" defaults
        }
    }

    static void initTomcat() {
        try {
            rfc = new Rfc6265CookieProcessor();
        } catch (Throwable t) {
            rfc = null;
        }
        try {
            legacy = new LegacyCookieProcessor();
        } catch (Throwable t) {
            legacy = null;
        }
    }

    static void initHc5() {
        try {
            // The default RFC6265 (lax) spec — a thread-safe, shareable parser.
            hc5 = new RFC6265CookieSpecFactory().create(null);
        } catch (Throwable t) {
            hc5 = null;
        }
    }

    static void discoverProviders() {
        // Both RESTEasy and Jersey register a jakarta.ws.rs.ext.RuntimeDelegate via
        // META-INF/services (merged by the shade plugin). The static
        // RuntimeDelegate.getInstance() would pick only one, so we enumerate all of
        // them and instantiate each by package — driving both providers at once.
        try {
            ServiceLoader<RuntimeDelegate> loader = ServiceLoader.load(RuntimeDelegate.class);
            loader.stream().forEach(provider -> {
                try {
                    String name = provider.type().getName();
                    if (name.startsWith("org.jboss.resteasy")) {
                        RuntimeDelegate rd = provider.get();
                        resteasyCookie = rd.createHeaderDelegate(Cookie.class);
                        resteasyNewCookie = rd.createHeaderDelegate(NewCookie.class);
                    } else if (name.startsWith("org.glassfish.jersey")) {
                        RuntimeDelegate rd = provider.get();
                        jerseyCookie = rd.createHeaderDelegate(Cookie.class);
                        jerseyNewCookie = rd.createHeaderDelegate(NewCookie.class);
                    }
                } catch (Throwable t) {
                    // leave that provider's delegates null → its column SKIPs
                }
            });
        } catch (Throwable t) {
            // discovery aborted entirely → both Jakarta columns SKIP
        }
    }

    static void runLoop() throws IOException {
        BufferedReader in =
            new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        PrintStream out = new PrintStream(System.out, true, StandardCharsets.UTF_8);
        String line;
        while ((line = in.readLine()) != null) {
            if (line.isEmpty()) {
                continue;
            }
            JsonObject rec;
            try {
                rec = JsonParser.parseString(line).getAsJsonObject();
            } catch (Throwable t) {
                continue;
            }
            String id = rec.get("id").getAsString();
            String direction = rec.get("direction").getAsString();
            byte[] raw = Base64.getDecoder().decode(rec.get("wire_b64").getAsString());
            // View the raw bytes as latin-1 (each byte -> one codepoint) for the
            // String-based provider parsers, so a non-UTF-8 wire renders as the same
            // mojibake the py/node/php columns show. Tomcat parses the raw bytes and
            // applies its own charset, which the matrix surfaces as its own column.
            String wire = new String(raw, StandardCharsets.ISO_8859_1);

            JsonObject byDep = new JsonObject();
            if ("request".equals(direction)) {
                byDep.add(TOMCAT_RFC, rfc != null ? tomcatParse(rfc, raw) : skipped());
                byDep.add(TOMCAT_LEGACY, legacy != null ? tomcatParse(legacy, raw) : skipped());
                byDep.add(JAKARTA_RESTEASY,
                    resteasyCookie != null ? jakartaRequest(resteasyCookie, wire) : skipped());
                byDep.add(JAKARTA_JERSEY,
                    jerseyCookie != null ? jakartaRequest(jerseyCookie, wire) : skipped());
                // Both Set-Cookie parsers are response-only.
                byDep.add(JDK_HTTPCOOKIE, notApplicable());
                byDep.add(APACHE_HC5, notApplicable());
            } else if ("response".equals(direction)) {
                byDep.add(TOMCAT_RFC, notApplicable());
                byDep.add(TOMCAT_LEGACY, notApplicable());
                byDep.add(JAKARTA_RESTEASY,
                    resteasyNewCookie != null ? jakartaResponse(resteasyNewCookie, wire) : skipped());
                byDep.add(JAKARTA_JERSEY,
                    jerseyNewCookie != null ? jakartaResponse(jerseyNewCookie, wire) : skipped());
                byDep.add(JDK_HTTPCOOKIE, jdkHttpCookieResponse(wire));
                byDep.add(APACHE_HC5, hc5 != null ? hc5Response(wire) : skipped());
            } else {
                // An unrecognized record kind (e.g. protocol v2 "jar" probes — no
                // CookieManager column here yet): NotApplicable across the board,
                // per PROTOCOL.md.
                byDep.add(TOMCAT_RFC, notApplicable());
                byDep.add(TOMCAT_LEGACY, notApplicable());
                byDep.add(JAKARTA_RESTEASY, notApplicable());
                byDep.add(JAKARTA_JERSEY, notApplicable());
                byDep.add(JDK_HTTPCOOKIE, notApplicable());
                byDep.add(APACHE_HC5, notApplicable());
            }
            JsonObject result = new JsonObject();
            result.addProperty("id", id);
            result.add("by_dep", byDep);
            out.println(GSON.toJson(result));
        }
    }

    /// Parse a request Cookie header with a Tomcat processor. Tomcat drops malformed
    /// cookies rather than throwing, so a corrupt pair shows as a smaller (or empty)
    /// pair list; only an exception (unexpected) becomes a Rejected.
    static JsonObject tomcatParse(CookieProcessor proc, byte[] raw) {
        try {
            MimeHeaders headers = new MimeHeaders();
            MessageBytes value = headers.addValue("Cookie");
            value.setBytes(raw, 0, raw.length);
            ServerCookies cookies = new ServerCookies(8);
            proc.parseCookieHeader(headers, cookies);
            JsonArray pairs = new JsonArray();
            for (int i = 0; i < cookies.getCookieCount(); i++) {
                ServerCookie c = cookies.getCookie(i);
                JsonObject pair = new JsonObject();
                pair.addProperty("name", c.getName().toString());
                pair.addProperty("value", c.getValue().toString());
                pairs.add(pair);
            }
            JsonObject o = new JsonObject();
            o.addProperty("outcome", "Cookies");
            o.add("cookies", pairs);
            return o;
        } catch (Throwable t) {
            return errorOutcome("Rejected", errorString(t));
        }
    }

    /// Parse a request Cookie header with a Jakarta provider. The Cookie header
    /// delegate parses a SINGLE cookie, so we tokenize on ';' ourselves (the standard
    /// request-cookie delimiter) and parse each pair with the provider — the split is
    /// ours, the per-pair parse and any rejection are the provider's. If every pair is
    /// rejected (and there was one), the whole header is Rejected.
    static JsonObject jakartaRequest(HeaderDelegate<Cookie> delegate, String wire) {
        JsonArray pairs = new JsonArray();
        Throwable lastError = null;
        for (String segment : wire.split(";")) {
            String token = segment.trim();
            if (token.isEmpty()) {
                continue;
            }
            try {
                Cookie cookie = delegate.fromString(token);
                if (cookie == null) {
                    continue;
                }
                JsonObject pair = new JsonObject();
                pair.addProperty("name", cookie.getName());
                pair.addProperty("value", cookie.getValue() == null ? "" : cookie.getValue());
                pairs.add(pair);
            } catch (Throwable t) {
                lastError = t;
            }
        }
        if (pairs.size() == 0 && lastError != null) {
            return errorOutcome("Rejected", errorString(lastError));
        }
        JsonObject o = new JsonObject();
        o.addProperty("outcome", "Cookies");
        o.add("cookies", pairs);
        return o;
    }

    /// Parse a Set-Cookie value with a Jakarta provider's NewCookie delegate.
    static JsonObject jakartaResponse(HeaderDelegate<NewCookie> delegate, String wire) {
        try {
            NewCookie c = delegate.fromString(wire);
            if (c == null) {
                return errorOutcome("SetCookieRejected", "fromString returned null");
            }
            JsonObject sc = new JsonObject();
            sc.addProperty("name", c.getName());
            sc.addProperty("value", c.getValue() == null ? "" : c.getValue());
            sc.addProperty("http_only", c.isHttpOnly());
            sc.addProperty("secure", c.isSecure());
            NewCookie.SameSite sameSite = c.getSameSite();
            if (sameSite == null) {
                sc.add("same_site", JsonNull.INSTANCE);
            } else {
                sc.addProperty("same_site", titleCase(sameSite.name()));
            }
            addOrNull(sc, "path", c.getPath());
            addOrNull(sc, "domain", c.getDomain());
            int maxAge = c.getMaxAge();
            // NewCookie's sentinel for "no Max-Age" is -1; report that as null.
            if (maxAge == -1) {
                sc.add("max_age", JsonNull.INSTANCE);
            } else {
                sc.addProperty("max_age", maxAge);
            }
            JsonObject o = new JsonObject();
            o.addProperty("outcome", "SetCookie");
            o.add("set_cookie", sc);
            return o;
        } catch (Throwable t) {
            return errorOutcome("SetCookieRejected", errorString(t));
        }
    }

    /// Parse a Set-Cookie value with the JDK's java.net.HttpCookie. It folds an
    /// Expires date into a clock-relative max-age (and exposes no SameSite), so to
    /// stay deterministic and comparable to the other columns we report max-age only
    /// when the wire actually carries a Max-Age attribute (else null).
    static JsonObject jdkHttpCookieResponse(String wire) {
        try {
            List<HttpCookie> cookies = HttpCookie.parse(wire);
            if (cookies.isEmpty()) {
                return errorOutcome("SetCookieRejected", "no cookie parsed");
            }
            HttpCookie c = cookies.get(0);
            JsonObject sc = new JsonObject();
            sc.addProperty("name", c.getName());
            sc.addProperty("value", c.getValue() == null ? "" : c.getValue());
            sc.addProperty("http_only", c.isHttpOnly());
            sc.addProperty("secure", c.getSecure());
            // java.net.HttpCookie has no SameSite accessor — always null here.
            sc.add("same_site", JsonNull.INSTANCE);
            addOrNull(sc, "path", c.getPath());
            addOrNull(sc, "domain", c.getDomain());
            if (hasMaxAgeAttr(wire)) {
                sc.addProperty("max_age", c.getMaxAge());
            } else {
                sc.add("max_age", JsonNull.INSTANCE);
            }
            JsonObject o = new JsonObject();
            o.addProperty("outcome", "SetCookie");
            o.add("set_cookie", sc);
            return o;
        } catch (Throwable t) {
            return errorOutcome("SetCookieRejected", errorString(t));
        }
    }

    /// Parse a Set-Cookie value with Apache HttpClient 5's RFC 6265 cookie spec. It
    /// needs a CookieOrigin (the request context the cookie would attach to); a
    /// neutral https origin lets domain/path attributes parse without being rejected
    /// as out-of-scope. hc5 keeps the raw Max-Age attribute string, so we report that
    /// integer directly (rather than its derived expiry Instant).
    static JsonObject hc5Response(String wire) {
        try {
            CookieOrigin origin = new CookieOrigin("example.com", 443, "/", true);
            List<org.apache.hc.client5.http.cookie.Cookie> cookies =
                hc5.parse(new BasicHeader("Set-Cookie", wire), origin);
            if (cookies.isEmpty()) {
                return errorOutcome("SetCookieRejected", "no cookie parsed");
            }
            org.apache.hc.client5.http.cookie.Cookie c = cookies.get(0);
            JsonObject sc = new JsonObject();
            sc.addProperty("name", c.getName());
            sc.addProperty("value", c.getValue() == null ? "" : c.getValue());
            sc.addProperty("http_only", c.isHttpOnly());
            sc.addProperty("secure", c.isSecure());
            // hc5's RFC6265 spec has no SameSite handler; surface a raw attribute if present.
            addOrNull(sc, "same_site", c.getAttribute("samesite"));
            addOrNull(sc, "path", c.getPath());
            addOrNull(sc, "domain", c.getDomain());
            String rawMaxAge = c.getAttribute(org.apache.hc.client5.http.cookie.Cookie.MAX_AGE_ATTR);
            if (rawMaxAge == null) {
                sc.add("max_age", JsonNull.INSTANCE);
            } else {
                try {
                    sc.addProperty("max_age", Long.parseLong(rawMaxAge.trim()));
                } catch (NumberFormatException nfe) {
                    sc.add("max_age", JsonNull.INSTANCE);
                }
            }
            JsonObject o = new JsonObject();
            o.addProperty("outcome", "SetCookie");
            o.add("set_cookie", sc);
            return o;
        } catch (Throwable t) {
            return errorOutcome("SetCookieRejected", errorString(t));
        }
    }

    /// Whether the wire carries a `Max-Age` attribute (case-insensitive), so the
    /// HttpCookie column reports an explicit Max-Age but not an Expires-derived one.
    static boolean hasMaxAgeAttr(String wire) {
        return wire.toLowerCase(Locale.ROOT).contains("max-age");
    }

    static void printSelfcheck() {
        JsonObject available = new JsonObject();
        available.addProperty(TOMCAT_RFC, rfc != null);
        available.addProperty(TOMCAT_LEGACY, legacy != null);
        available.addProperty(JAKARTA_RESTEASY, resteasyCookie != null && resteasyNewCookie != null);
        available.addProperty(JAKARTA_JERSEY, jerseyCookie != null && jerseyNewCookie != null);
        available.addProperty(JDK_HTTPCOOKIE, true); // JDK built-in, always present
        available.addProperty(APACHE_HC5, hc5 != null);

        JsonObject versions = new JsonObject();
        versions.addProperty("runtime", "Java " + System.getProperty("java.version"));
        versions.addProperty(TOMCAT_RFC, tomcatVersion);
        versions.addProperty(TOMCAT_LEGACY, tomcatVersion);
        versions.addProperty(JAKARTA_RESTEASY, resteasyVersion);
        versions.addProperty(JAKARTA_JERSEY, jerseyVersion);
        versions.addProperty(JDK_HTTPCOOKIE, "JDK " + System.getProperty("java.version"));
        versions.addProperty(APACHE_HC5, hc5Version);

        JsonObject root = new JsonObject();
        root.add("available", available);
        root.add("versions", versions);

        PrintStream out = new PrintStream(System.out, true, StandardCharsets.UTF_8);
        out.println(GSON.toJson(root));
    }

    static JsonObject errorOutcome(String outcome, String error) {
        JsonObject o = new JsonObject();
        o.addProperty("outcome", outcome);
        o.addProperty("error", error);
        return o;
    }

    static String errorString(Throwable t) {
        if (t == null) {
            return "rejected";
        }
        String message = t.getMessage();
        return t.getClass().getSimpleName() + (message != null ? ": " + message : "");
    }

    static JsonObject notApplicable() {
        return outcomeOnly("NotApplicable");
    }

    static JsonObject skipped() {
        return outcomeOnly("Skipped");
    }

    static JsonObject outcomeOnly(String outcome) {
        JsonObject o = new JsonObject();
        o.addProperty("outcome", outcome);
        return o;
    }

    static void addOrNull(JsonObject o, String key, String value) {
        if (value == null) {
            o.add(key, JsonNull.INSTANCE);
        } else {
            o.addProperty(key, value);
        }
    }

    /// STRICT -> Strict, LAX -> Lax, NONE -> None (matches the .NET sidecar's render
    /// so the SameSite cells are comparable in the consensus vote).
    static String titleCase(String enumName) {
        if (enumName.isEmpty()) {
            return enumName;
        }
        return enumName.charAt(0) + enumName.substring(1).toLowerCase(Locale.ROOT);
    }

    private Sidecar() {
    }
}
