using System.Text.Json;

namespace RateMyWaf.Services.Azure;

/// <summary>
/// Thin, read-only access to the three Azure data planes the app needs. Everything the app knows
/// about a customer's WAF estate comes through here, so tests can substitute canned JSON.
/// </summary>
public interface IAzureApi
{
    /// <summary>Runs an Azure Resource Graph query across the given subscriptions, following $skipToken paging.</summary>
    Task<List<JsonElement>> QueryResourceGraphAsync(string query, IReadOnlyCollection<string> subscriptionIds, string? tenantId, CancellationToken ct = default);

    /// <summary>GETs an ARM collection URL and returns the concatenated "value" items across nextLink pages.</summary>
    Task<List<JsonElement>> GetArmListAsync(string url, string? tenantId, CancellationToken ct = default);

    /// <summary>Runs a KQL query scoped to a resource (Log Analytics resource-centric query) and returns the first table's rows.</summary>
    Task<List<Dictionary<string, JsonElement>>> QueryLogAnalyticsAsync(string resourceId, string query, string? tenantId, CancellationToken ct = default);
}
