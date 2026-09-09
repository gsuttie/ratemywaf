using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using RateMyWaf.Models;
using RateMyWaf.Services;
using RateMyWaf.Services.Azure;
using Xunit;

namespace RateMyWaf.Tests;

/// <summary>Choosing and querying an explicit Log Analytics workspace when a resource's logs are split.</summary>
public class WorkspaceTests
{
    /// <summary>Records which Log Analytics endpoint was hit and returns no rows.</summary>
    private sealed class RecordingAzureApi : IAzureApi
    {
        public List<string> Calls { get; } = new();
        public List<JsonElement> WorkspaceRows { get; set; } = new();
        /// <summary>Rows returned for the unfiltered probe query (the one grouping by PolicyOut only).</summary>
        public List<Dictionary<string, JsonElement>> ProbeRows { get; set; } = new();

        private List<Dictionary<string, JsonElement>> RowsFor(string query) =>
            query.Contains("summarize Count=count() by PolicyOut") ? ProbeRows : new();

        public Task<List<JsonElement>> QueryResourceGraphAsync(string query, IReadOnlyCollection<string> subscriptionIds, string? tenantId, CancellationToken ct = default)
        {
            Calls.Add("graph:" + string.Join(",", subscriptionIds));
            return Task.FromResult(WorkspaceRows);
        }
        public Task<List<JsonElement>> GetArmListAsync(string url, string? tenantId, CancellationToken ct = default) => Task.FromResult(new List<JsonElement>());
        public Task<List<Dictionary<string, JsonElement>>> QueryLogAnalyticsAsync(string resourceId, string query, string? tenantId, CancellationToken ct = default)
        {
            Calls.Add("resource:" + resourceId);
            return Task.FromResult(RowsFor(query));
        }
        public Task<List<Dictionary<string, JsonElement>>> QueryLogAnalyticsWorkspaceAsync(string workspaceCustomerId, string query, string? tenantId, CancellationToken ct = default)
        {
            Calls.Add("workspace:" + workspaceCustomerId + (query.Contains("_ResourceId") ? ":scoped" : ":unscoped"));
            return Task.FromResult(RowsFor(query));
        }
    }

    private const string GwId = "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Network/applicationGateways/agw";

    [Fact]
    public async Task ParseWorkspace_AndListAcrossSubscriptions()
    {
        var api = new RecordingAzureApi
        {
            WorkspaceRows =
            [
                JsonDocument.Parse("""{ "id": "/subscriptions/s2/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/law-security", "name": "law-security", "location": "westeurope", "resourceGroup": "rg", "subscriptionId": "s2", "customerId": "11111111-2222-3333-4444-555555555555" }""").RootElement.Clone(),
                JsonDocument.Parse("""{ "id": "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/law-app", "name": "law-app", "subscriptionId": "s1", "customerId": "aaaa" }""").RootElement.Clone(),
            ]
        };
        var discovery = new WafDiscoveryService(api, NullLogger<WafDiscoveryService>.Instance);

        var workspaces = await discovery.GetWorkspacesAsync(["s1", "s2", "s3"], "t");

        Assert.Equal("graph:s1,s2,s3", api.Calls.Single());
        Assert.Equal(["law-app", "law-security"], workspaces.Select(w => w.Name).ToList());
        var security = workspaces.Single(w => w.Name == "law-security");
        Assert.Equal("s2", security.SubscriptionId);
        Assert.Equal("11111111-2222-3333-4444-555555555555", security.CustomerId);
    }

    [Fact]
    public async Task Analyze_WithWorkspace_QueriesThatWorkspaceScopedToTheResource()
    {
        var api = new RecordingAzureApi();
        var service = new WafLogAnalysisService(api, NullLogger<WafLogAnalysisService>.Instance);
        var workspace = new LogWorkspaceInfo { Id = "/w", Name = "law-security", CustomerId = "cid-123" };

        var analysis = await service.AnalyzeAsync(WafFlowKind.ApplicationGateway, GwId, "agw", [new WafPolicyInfo { Name = "pol" }], "24h", "t", workspace);

        Assert.True(analysis.LogsQueryable);
        Assert.Equal("law-security", analysis.WorkspaceName);
        // Evidence + changes + the empty-result probe, all against the workspace and pinned to the resource.
        Assert.Equal(3, api.Calls.Count);
        Assert.All(api.Calls, c => Assert.Equal("workspace:cid-123:scoped", c));
        Assert.Contains(analysis.Warnings, w => w.Contains("No firewall log rows exist") && w.Contains("law-security"));
    }

    [Fact]
    public async Task Analyze_EmptyResult_ReportsPolicyNamesActuallyInTheLogs()
    {
        var api = new RecordingAzureApi
        {
            ProbeRows =
            [
                new(StringComparer.OrdinalIgnoreCase) { ["PolicyOut"] = JsonSerializer.SerializeToElement("waf-other"), ["Count"] = JsonSerializer.SerializeToElement(42) },
                new(StringComparer.OrdinalIgnoreCase) { ["PolicyOut"] = JsonSerializer.SerializeToElement(""), ["Count"] = JsonSerializer.SerializeToElement(3) },
            ]
        };
        var service = new WafLogAnalysisService(api, NullLogger<WafLogAnalysisService>.Instance);

        var analysis = await service.AnalyzeAsync(WafFlowKind.ApplicationGateway, GwId, "agw", [new WafPolicyInfo { Name = "waf-mine" }], "24h", "t");

        Assert.Equal(0, analysis.TotalEvents);
        var warning = Assert.Single(analysis.Warnings);
        Assert.Contains("45 firewall event(s)", warning);
        Assert.Contains("'waf-other' (42)", warning);
        Assert.Contains("'(no policy name)' (3)", warning);
    }

    [Fact]
    public void AppGatewayQuery_TakesPolicyNameFromPolicyId_NotScopeName()
    {
        // policyScopeName is 'Global' for a gateway-level policy, so filtering on it would never match.
        var (evidence, _) = WafLogAnalysisService.BuildQueries(WafFlowKind.ApplicationGateway, [new WafPolicyInfo { Name = "waf-appgw" }], "24h");
        Assert.Contains("split(column_ifexists('policyId_s',''), '/')[-1]", evidence);
        Assert.Contains("split(tostring(column_ifexists('PolicyId','')), '/')[-1]", evidence);
        Assert.DoesNotContain("policyScopeName", evidence);
        Assert.Contains("PolicyOut in~ ('waf-appgw')", evidence);

        var probe = WafLogAnalysisService.BuildProbeQuery(WafFlowKind.ApplicationGateway, "24h", GwId);
        Assert.Contains($"_ResourceId =~ '{GwId}'", probe);
        Assert.DoesNotContain("PolicyOut in~", probe);
        Assert.EndsWith("summarize Count=count() by PolicyOut", probe);
    }

    [Fact]
    public async Task Analyze_WithoutWorkspace_UsesResourceCentricQuery()
    {
        var api = new RecordingAzureApi();
        var service = new WafLogAnalysisService(api, NullLogger<WafLogAnalysisService>.Instance);

        var analysis = await service.AnalyzeAsync(WafFlowKind.FrontDoor, "/fd", "fd", [], "1h", "t");

        Assert.Empty(analysis.WorkspaceName);
        Assert.All(api.Calls, c => Assert.Equal("resource:/fd", c));
    }

    [Fact]
    public async Task Analyze_WorkspaceWithoutCustomerId_ReportsAClearError()
    {
        var api = new RecordingAzureApi();
        var service = new WafLogAnalysisService(api, NullLogger<WafLogAnalysisService>.Instance);

        var analysis = await service.AnalyzeAsync(WafFlowKind.FrontDoor, "/fd", "fd", [], "1h", "t", new LogWorkspaceInfo { Name = "law-x" });

        Assert.False(analysis.LogsQueryable);
        Assert.Contains("law-x", analysis.QueryError);
        Assert.Empty(api.Calls);
    }

    [Fact]
    public void DemoGateway_FirewallLogGoesToAWorkspaceInAnotherSubscription()
    {
        var scan = DemoDataService.Scan(WafFlowKind.ApplicationGateway, [DemoDataService.SubProd, DemoDataService.SubShared]);
        var gw = scan.AppGateways.Single(g => g.Name == "agw-contoso-prod");
        var workspace = DemoDataService.Workspaces().Single(w => w.Id == gw.LogWorkspaceIds.Single());

        Assert.Equal("law-contoso-security", workspace.Name);
        Assert.NotEqual(gw.SubscriptionId, workspace.SubscriptionId);
    }
}
