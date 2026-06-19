// keksbruch .NET sidecar.
//
// Reads base64-JSONL payload records on stdin and parses each with ASP.NET Core's
// Microsoft.Net.Http.Headers — CookieHeaderValue for a request Cookie header,
// SetCookieHeaderValue for a Set-Cookie line. Emits one normalized JSONL result
// per line. `--selfcheck` reports availability + version, then exits.

using System.Text;
using System.Text.Json;
using Microsoft.Net.Http.Headers;

if (args.Contains("--selfcheck"))
{
    var info = new Dictionary<string, object>
    {
        ["available"] = new Dictionary<string, bool> { ["Microsoft.Net.Http.Headers"] = true },
        ["versions"] = new Dictionary<string, string>
        {
            ["runtime"] = ".NET " + Environment.Version,
            ["Microsoft.Net.Http.Headers"] =
                typeof(CookieHeaderValue).Assembly.GetName().Version?.ToString() ?? "?",
        },
    };
    Console.WriteLine(JsonSerializer.Serialize(info));
    return 0;
}

string? line;
while ((line = Console.In.ReadLine()) is not null)
{
    if (line.Length == 0) continue;
    JsonElement rec;
    try { rec = JsonSerializer.Deserialize<JsonElement>(line); }
    catch { continue; }

    var id = rec.GetProperty("id").GetString() ?? "";
    var direction = rec.GetProperty("direction").GetString() ?? "";
    var wireB64 = rec.GetProperty("wire_b64").GetString() ?? "";

    byte[] raw;
    try { raw = Convert.FromBase64String(wireB64); }
    catch { continue; }
    var wire = Encoding.Latin1.GetString(raw); // byte-faithful, like the py/node sidecars

    object outcome = direction == "request" ? ParseRequest(wire) : ParseResponse(wire);
    var result = new Dictionary<string, object>
    {
        ["id"] = id,
        ["by_dep"] = new Dictionary<string, object> { ["Microsoft.Net.Http.Headers"] = outcome },
    };
    Console.WriteLine(JsonSerializer.Serialize(result));
}

return 0;

static object ParseRequest(string wire)
{
    if (CookieHeaderValue.TryParseList(new List<string> { wire }, out var cookies) && cookies is not null)
    {
        var pairs = cookies
            .Select(c => new Dictionary<string, string>
            {
                ["name"] = c.Name.ToString(),
                ["value"] = c.Value.ToString(),
            })
            .ToList();
        return new Dictionary<string, object> { ["outcome"] = "Cookies", ["cookies"] = pairs };
    }
    return new Dictionary<string, object> { ["outcome"] = "Rejected", ["error"] = "TryParseList failed" };
}

static object ParseResponse(string wire)
{
    if (SetCookieHeaderValue.TryParse(wire, out var sc) && sc is not null)
    {
        var view = new Dictionary<string, object?>
        {
            ["name"] = sc.Name.ToString(),
            ["value"] = sc.Value.ToString(),
            ["http_only"] = sc.HttpOnly,
            ["secure"] = sc.Secure,
            ["same_site"] = sc.SameSite switch
            {
                SameSiteMode.Strict => "Strict",
                SameSiteMode.Lax => "Lax",
                SameSiteMode.None => "None",
                _ => null,
            },
            ["path"] = sc.Path.HasValue ? sc.Path.ToString() : null,
            ["domain"] = sc.Domain.HasValue ? sc.Domain.ToString() : null,
            ["max_age"] = sc.MaxAge.HasValue ? (long)sc.MaxAge.Value.TotalSeconds : (long?)null,
        };
        return new Dictionary<string, object> { ["outcome"] = "SetCookie", ["set_cookie"] = view };
    }
    return new Dictionary<string, object> { ["outcome"] = "SetCookieRejected", ["error"] = "TryParse failed" };
}
