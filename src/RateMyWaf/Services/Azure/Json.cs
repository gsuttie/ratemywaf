using System.Text.Json;

namespace RateMyWaf.Services.Azure;

/// <summary>Null-tolerant JsonElement accessors used by the parsers.</summary>
internal static class Json
{
    public static string Str(JsonElement el, string name) =>
        el.ValueKind == JsonValueKind.Object && el.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String
            ? v.GetString() ?? string.Empty
            : string.Empty;

    public static int? Int(JsonElement el, string name) =>
        el.ValueKind == JsonValueKind.Object && el.TryGetProperty(name, out var v) &&
        v.ValueKind == JsonValueKind.Number && v.TryGetInt32(out var n)
            ? n
            : null;

    public static bool? Bool(JsonElement el, string name) =>
        el.ValueKind == JsonValueKind.Object && el.TryGetProperty(name, out var v)
            ? v.ValueKind switch { JsonValueKind.True => true, JsonValueKind.False => false, _ => null }
            : null;

    public static JsonElement Obj(JsonElement el, string name) =>
        el.ValueKind == JsonValueKind.Object && el.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Object
            ? v
            : default;

    public static IEnumerable<JsonElement> Arr(JsonElement el, string name) =>
        el.ValueKind == JsonValueKind.Object && el.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Array
            ? v.EnumerateArray()
            : [];

    public static int ArrLen(JsonElement el, string name) =>
        el.ValueKind == JsonValueKind.Object && el.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Array
            ? v.GetArrayLength()
            : 0;

    public static string? NullIfEmpty(string s) => string.IsNullOrEmpty(s) ? null : s;

    public static string FirstNonEmpty(params string[] values) =>
        values.FirstOrDefault(v => !string.IsNullOrEmpty(v)) ?? string.Empty;

    public static string LastSegment(string resourceId)
    {
        var idx = resourceId.LastIndexOf('/');
        return idx >= 0 && idx < resourceId.Length - 1 ? resourceId[(idx + 1)..] : resourceId;
    }

    // ── Log Analytics row helpers ─────────────────────────────────────────────

    public static string Cell(Dictionary<string, JsonElement> row, string name) =>
        row.TryGetValue(name, out var v)
            ? v.ValueKind == JsonValueKind.String ? v.GetString() ?? string.Empty
            : v.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined ? string.Empty
            : v.ToString()
            : string.Empty;

    public static int CellInt(Dictionary<string, JsonElement> row, string name)
    {
        if (!row.TryGetValue(name, out var v)) return 0;
        if (v.ValueKind == JsonValueKind.Number && v.TryGetInt64(out var n))
            return n > int.MaxValue ? int.MaxValue : (int)n;
        return int.TryParse(v.ToString(), out var parsed) ? parsed : 0;
    }

    /// <summary>Dynamic columns (make_set) arrive as JSON, either as an array or an encoded string.</summary>
    public static List<string> CellList(Dictionary<string, JsonElement> row, string name)
    {
        var list = new List<string>();
        if (!row.TryGetValue(name, out var v)) return list;

        if (v.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in v.EnumerateArray())
                if (item.ValueKind == JsonValueKind.String && !string.IsNullOrEmpty(item.GetString()))
                    list.Add(item.GetString()!);
        }
        else if (v.ValueKind == JsonValueKind.String)
        {
            try
            {
                using var doc = JsonDocument.Parse(v.GetString() ?? "[]");
                if (doc.RootElement.ValueKind == JsonValueKind.Array)
                    foreach (var item in doc.RootElement.EnumerateArray())
                        if (item.ValueKind == JsonValueKind.String && !string.IsNullOrEmpty(item.GetString()))
                            list.Add(item.GetString()!);
            }
            catch { /* leave empty */ }
        }
        return list;
    }
}
