using RateMyWaf.Models;

namespace RateMyWaf.Services;

/// <summary>
/// Orchestrates one flow's steps against either Azure or the built-in demo estate, so the UI never
/// has to know which one it is talking to.
/// </summary>
public sealed class WafFlowService
{
    private readonly SessionState _state;
    private readonly WafDiscoveryService _discovery;
    private readonly WafLogAnalysisService _logs;

    public WafFlowService(SessionState state, WafDiscoveryService discovery, WafLogAnalysisService logs)
    {
        _state = state;
        _discovery = discovery;
        _logs = logs;
    }

    public SessionState State => _state;

    public IReadOnlyList<SubscriptionInfo> Subscriptions =>
        _state.DemoMode ? DemoDataService.Subscriptions() : _state.Subscriptions;

    public string TenantName(string tenantId) =>
        _state.DemoMode ? DemoDataService.Tenants()[DemoDataService.TenantId].BestName : _state.TenantName(tenantId);

    public string SubscriptionName(string subscriptionId) =>
        Subscriptions.FirstOrDefault(s => s.SubscriptionId.Equals(subscriptionId, StringComparison.OrdinalIgnoreCase))?.DisplayName ?? subscriptionId;

    public Task LoadSubscriptionsAsync(bool force = false, CancellationToken ct = default) =>
        _state.DemoMode ? Task.CompletedTask : _state.EnsureLoadedAsync(force, ct);

    public void EnterDemoMode()
    {
        _state.DemoMode = true;
        foreach (var flow in _state.Flows.Values)
        {
            flow.Scan = null;
            flow.LogAnalysis = null;
            flow.ScanError = null;
            flow.SelectedSubscriptionIds.Clear();
            flow.SelectedTenantId = DemoDataService.TenantId;
        }
    }

    public void ExitDemoMode()
    {
        _state.DemoMode = false;
        foreach (var flow in _state.Flows.Values)
        {
            flow.Scan = null;
            flow.LogAnalysis = null;
            flow.ScanError = null;
            flow.SelectedSubscriptionIds.Clear();
            flow.SelectedTenantId = null;
        }
    }

    public Task<Dictionary<string, WafSubscriptionSummary>> GetSummariesAsync(
        IReadOnlyCollection<string> subscriptionIds, string? tenantId, CancellationToken ct = default) =>
        _state.DemoMode
            ? Task.FromResult(DemoDataService.Summaries())
            : _discovery.GetSummariesAsync(subscriptionIds, tenantId, ct);

    public async Task<WafScanResult> ScanAsync(WafFlowKind flow, IProgress<string>? progress = null, CancellationToken ct = default)
    {
        var fs = _state.For(flow);
        var ids = fs.SelectedSubscriptionIds.ToList();
        WafScanResult result;

        if (_state.DemoMode)
        {
            progress?.Report("Loading sample estate…");
            await Task.Delay(600, ct);
            result = DemoDataService.Scan(flow, ids);
        }
        else
        {
            // Selections normally live in one tenant, but group defensively.
            var groups = Subscriptions
                .Where(s => fs.SelectedSubscriptionIds.Contains(s.SubscriptionId))
                .GroupBy(s => s.TenantId, StringComparer.OrdinalIgnoreCase)
                .ToList();
            result = new WafScanResult { Flow = flow };
            foreach (var g in groups)
                result.Merge(await _discovery.ScanAsync(flow, g.Select(s => s.SubscriptionId).ToList(), g.Key, progress, ct));
            result.CompletedAt = DateTime.Now;
        }

        fs.Scan = result;
        fs.LogAnalysis = null;
        fs.ScanError = null;
        return result;
    }

    public async Task<WafLogAnalysis> AnalyzeLogsAsync(WafFlowKind flow, string targetId, string targetName,
        IReadOnlyCollection<WafPolicyInfo> policies, string timeRange, CancellationToken ct = default)
    {
        var fs = _state.For(flow);
        WafLogAnalysis analysis;
        if (_state.DemoMode)
        {
            await Task.Delay(700, ct);
            analysis = DemoDataService.LogAnalysis(flow, targetId, targetName, policies, timeRange);
        }
        else
        {
            var subId = fs.Scan?.FrontDoors.FirstOrDefault(f => f.Id == targetId)?.SubscriptionId
                        ?? fs.Scan?.AppGateways.FirstOrDefault(g => g.Id == targetId)?.SubscriptionId;
            var tenantId = Subscriptions.FirstOrDefault(s => s.SubscriptionId.Equals(subId, StringComparison.OrdinalIgnoreCase))?.TenantId;
            analysis = await _logs.AnalyzeAsync(flow, targetId, targetName, policies, timeRange, tenantId, ct);
        }
        fs.LogAnalysis = analysis;
        return analysis;
    }

    /// <summary>Policies linked to an edge resource, as the rating engine sees them.</summary>
    public static List<WafPolicyInfo> LinkedPolicies(WafScanResult scan, string targetId)
    {
        var fd = scan.FrontDoors.FirstOrDefault(f => f.Id.Equals(targetId, StringComparison.OrdinalIgnoreCase));
        if (fd is not null)
            return scan.WafPolicies.Where(p =>
                    p.AssociationIds.Any(id => WafRatingService.MatchesResource(id, fd.Id)) ||
                    fd.AssociatedPolicyIds.Contains(p.Id, StringComparer.OrdinalIgnoreCase) ||
                    fd.Endpoints.Any(e => p.Id.Equals(e.WafPolicyId, StringComparison.OrdinalIgnoreCase)))
                .OrderBy(p => p.Name).ToList();

        var gw = scan.AppGateways.FirstOrDefault(g => g.Id.Equals(targetId, StringComparison.OrdinalIgnoreCase));
        if (gw is not null)
            return scan.WafPolicies.Where(p =>
                    p.AssociationIds.Any(id => WafRatingService.MatchesResource(id, gw.Id)) ||
                    p.Id.Equals(gw.FirewallPolicyId, StringComparison.OrdinalIgnoreCase) ||
                    gw.Listeners.Any(l => p.Id.Equals(l.WafPolicyId, StringComparison.OrdinalIgnoreCase)))
                .OrderBy(p => p.Name).ToList();

        return [];
    }

    public WafReportContext ReportContext(WafFlowKind flow)
    {
        var fs = _state.For(flow);
        var subs = Subscriptions.Where(s => fs.SelectedSubscriptionIds.Contains(s.SubscriptionId))
            .OrderBy(s => s.DisplayName, StringComparer.OrdinalIgnoreCase).ToList();
        var tenantId = subs.Select(s => s.TenantId).FirstOrDefault(t => !string.IsNullOrEmpty(t)) ?? fs.SelectedTenantId ?? "";
        var tenantName = string.IsNullOrEmpty(tenantId) ? "" : TenantName(tenantId);
        return new WafReportContext
        {
            Flow = flow,
            CustomerName = tenantName,
            TenantName = tenantName,
            ReportAuthor = Environment.UserName,
            ScanDate = fs.Scan?.CompletedAt ?? DateTime.Now,
            SubscriptionLines = subs.Select(s => $"{s.DisplayName} ({s.SubscriptionId})").ToList(),
            Scan = fs.Scan,
            LogAnalysis = fs.LogAnalysis
        };
    }
}
