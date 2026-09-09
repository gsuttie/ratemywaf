using System.Text;
using System.Text.Json;
using RateMyWaf.Models;
using RateMyWaf.Services.Azure;
using static RateMyWaf.Services.Azure.Json;

namespace RateMyWaf.Services;

/// <summary>
/// Queries the WAF logs of a Front Door or Application Gateway (resource-scoped Log Analytics),
/// compares the window against the preceding one, classifies rule activity as likely false positive
/// or real attack and produces report-only recommendations.
/// </summary>
public sealed class WafLogAnalysisService
{
    /// <summary>Supported analysis windows: key (valid KQL timespan) to display label.</summary>
    public static readonly IReadOnlyList<(string Key, string Label)> TimeRanges =
    [
        ("1h", "Last hour"),
        ("6h", "Last 6 hours"),
        ("24h", "Last 24 hours"),
        ("3d", "Last 3 days"),
        ("7d", "Last 7 days"),
        ("14d", "Last 14 days"),
        ("30d", "Last 30 days"),
    ];

    private static readonly Dictionary<string, string> DoubledTimeRanges = new()
    {
        ["1h"] = "2h", ["6h"] = "12h", ["24h"] = "48h", ["3d"] = "6d",
        ["7d"] = "14d", ["14d"] = "28d", ["30d"] = "60d"
    };

    // CRS/DRS rules that are well known for firing on legitimate traffic.
    internal static readonly HashSet<string> FalsePositiveProneRuleIds = new(StringComparer.Ordinal)
    {
        "942430", "942440", "942450", "942330", "942340", "942370", "942130", "942200",
        "920300", "920320", "920330", "931130", "932105", "933160", "920230", "942260", "942390"
    };

    internal static readonly string[] AttackUriPatterns =
    [
        ".env", ".git", "wp-login", "wp-admin", "phpmyadmin", "/etc/passwd", "..%2f", "../",
        "cmd=", "exec(", "union+select", "union%20select", "union select", "<script", "%3cscript",
        "eval(", "base64_decode", ".aws/", "config.php", "xmlrpc.php", "/vendor/phpunit",
        "/actuator", "/console", "jndi:", "/cgi-bin/", ".php?", "shell", "passwd"
    ];

    internal static readonly string[] ScannerSignatures =
    [
        "sqlmap", "nikto", "nuclei", "nmap", "masscan", "zgrab", "dirbuster", "gobuster",
        "wpscan", "acunetix", "burp", "havij", "hydra"
    ];

    internal static readonly string[] FpProneMatchVariables =
    [
        "cookie", "useragent", "user-agent", "referer", "authorization"
    ];

    private readonly IAzureApi _azure;
    private readonly ILogger<WafLogAnalysisService> _logger;

    public WafLogAnalysisService(IAzureApi azure, ILogger<WafLogAnalysisService> logger)
    {
        _azure = azure;
        _logger = logger;
    }

    public static string LabelFor(string timeRange) =>
        TimeRanges.FirstOrDefault(t => t.Key == timeRange).Label ?? timeRange;

    public async Task<WafLogAnalysis> AnalyzeAsync(
        WafFlowKind flow, string targetId, string targetName,
        IReadOnlyCollection<WafPolicyInfo> policies, string timeRange, string? tenantId, CancellationToken ct = default)
    {
        if (!DoubledTimeRanges.ContainsKey(timeRange))
            throw new ArgumentException($"Unsupported time range '{timeRange}'.");

        var analysis = new WafLogAnalysis
        {
            Flow = flow,
            TargetId = targetId,
            TargetName = targetName,
            PolicyNames = policies.Select(p => p.Name).ToList(),
            TimeRangeKey = timeRange,
            TimeRangeLabel = LabelFor(timeRange).ToLowerInvariant()
        };

        var (evidenceQuery, changesQuery) = BuildQueries(flow, policies, timeRange);

        List<Dictionary<string, JsonElement>> evidenceRows, changeRows;
        try
        {
            var evidenceTask = _azure.QueryLogAnalyticsAsync(targetId, evidenceQuery, tenantId, ct);
            var changesTask = _azure.QueryLogAnalyticsAsync(targetId, changesQuery, tenantId, ct);
            await Task.WhenAll(evidenceTask, changesTask);
            evidenceRows = evidenceTask.Result;
            changeRows = changesTask.Result;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex, "WAF log query failed for {Target}.", targetName);
            analysis.LogsQueryable = false;
            analysis.QueryError = ex.Message;
            return analysis;
        }

        Populate(analysis, policies, evidenceRows, changeRows);
        return analysis;
    }

    /// <summary>Builds the two KQL queries (aggregated evidence, and current-vs-previous period counts).</summary>
    internal static (string Evidence, string Changes) BuildQueries(WafFlowKind flow, IReadOnlyCollection<WafPolicyInfo> policies, string timeRange)
    {
        // Legacy inline configurations have no policy name in the logs, so do not filter on them.
        var namedPolicies = policies.Where(p => !p.IsLegacyInline).ToList();
        var policyFilter = namedPolicies.Count > 0 && namedPolicies.Count == policies.Count
            ? $"| where PolicyOut in~ ({string.Join(", ", namedPolicies.Select(p => $"'{p.Name.Replace("'", "\\'")}'"))})"
            : string.Empty;

        var union = flow == WafFlowKind.FrontDoor ? FrontDoorLogUnionQuery : AppGatewayLogUnionQuery;

        var evidence =
            $"{union}\n{policyFilter}\n" +
            $"| where TimeGenerated > ago({timeRange})\n" +
            "| summarize Count=count(), DistinctIps=dcount(IpOut), DistinctUris=dcount(UriOut),\n" +
            "    SampleIps=make_set(IpOut, 5), SampleUris=make_set(UriOut, 5),\n" +
            "    SampleMatch=take_any(MatchOut), SampleData=take_any(DataOut), SampleMsg=take_any(MsgOut),\n" +
            "    Blocked=countif(ActionOut in~ ('Block','Blocked')), Logged=countif(ActionOut in~ ('Log','Matched','Detected','AnomalyScoring')),\n" +
            "    Allowed=countif(ActionOut in~ ('Allow','Allowed')), Redirected=countif(ActionOut =~ 'Redirect')\n" +
            "    by RuleOut, PolicyOut\n" +
            "| order by Count desc\n" +
            "| take 100";

        var changes =
            $"{union}\n{policyFilter}\n" +
            $"| where TimeGenerated > ago({DoubledTimeRanges[timeRange]})\n" +
            $"| extend Period = iff(TimeGenerated > ago({timeRange}), 'current', 'previous')\n" +
            "| summarize Count=count() by RuleOut, ActionOut, Period";

        return (evidence, changes);
    }

    /// <summary>Pure aggregation + classification (testable without Azure).</summary>
    internal static void Populate(WafLogAnalysis analysis, IReadOnlyCollection<WafPolicyInfo> policies,
        List<Dictionary<string, JsonElement>> evidenceRows, List<Dictionary<string, JsonElement>> changeRows)
    {
        var policyModes = policies
            .GroupBy(p => p.Name, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First().Mode, StringComparer.OrdinalIgnoreCase);
        // Logs of a legacy inline config carry no policy name; fall back to the single mode when unambiguous.
        var fallbackMode = policies.Select(p => p.Mode).Distinct(StringComparer.OrdinalIgnoreCase).Count() == 1
            ? policies.First().Mode : "";

        foreach (var row in evidenceRows)
        {
            var activity = new WafRuleActivity
            {
                RuleName = Cell(row, "RuleOut"),
                PolicyName = Cell(row, "PolicyOut"),
                Count = CellInt(row, "Count"),
                DistinctIps = CellInt(row, "DistinctIps"),
                DistinctUris = CellInt(row, "DistinctUris"),
                SampleIps = CellList(row, "SampleIps"),
                SampleUris = CellList(row, "SampleUris"),
                SampleMatchVariable = Cell(row, "SampleMatch"),
                SampleMatchData = Cell(row, "SampleData"),
                SampleMessage = Cell(row, "SampleMsg"),
                Blocked = CellInt(row, "Blocked"),
                Logged = CellInt(row, "Logged"),
                Allowed = CellInt(row, "Allowed"),
                Redirected = CellInt(row, "Redirected")
            };
            if (string.IsNullOrEmpty(activity.RuleName)) activity.RuleName = "(no rule)";
            var mode = policyModes.TryGetValue(activity.PolicyName, out var m) ? m : fallbackMode;
            Classify(activity, mode);
            analysis.RuleActivities.Add(activity);
        }

        analysis.TotalEvents = analysis.RuleActivities.Sum(a => a.Count);
        analysis.BlockedCount = analysis.RuleActivities.Sum(a => a.Blocked);
        analysis.LoggedCount = analysis.RuleActivities.Sum(a => a.Logged);
        analysis.AllowedCount = analysis.RuleActivities.Sum(a => a.Allowed);
        analysis.RedirectedCount = analysis.RuleActivities.Sum(a => a.Redirected);
        analysis.DistinctRules = analysis.RuleActivities.Count;
        analysis.Changes = BuildChanges(changeRows);

        if (evidenceRows.Count == 100)
            analysis.Warnings.Add("Only the 100 most active rules are shown — narrow the time range for full coverage.");

        analysis.RuleActivities = analysis.RuleActivities
            .OrderBy(a => ClassificationOrder(a.Classification))
            .ThenByDescending(a => a.Count)
            .ToList();
    }

    public static int ClassificationOrder(string classification) => classification switch
    {
        "Likely real attack" => 0,
        "Possible false positive" => 1,
        _ => 2
    };

    // Normalises both log shapes (AzureDiagnostics + the resource-specific table) into one schema.
    internal const string FrontDoorLogUnionQuery =
        "union isfuzzy=true\n" +
        "(AzureDiagnostics\n" +
        "| where Category in ('FrontDoorWebApplicationFirewallLog','FrontdoorWebApplicationFirewallLog')\n" +
        "| project TimeGenerated,\n" +
        "    PolicyOut = column_ifexists('policy_s',''),\n" +
        "    RuleOut = column_ifexists('ruleName_s',''),\n" +
        "    ActionOut = column_ifexists('action_s',''),\n" +
        "    IpOut = column_ifexists('clientIP_s',''),\n" +
        "    UriOut = column_ifexists('requestUri_s',''),\n" +
        "    MatchOut = column_ifexists('details_matches_s',''),\n" +
        "    DataOut = column_ifexists('details_data_s',''),\n" +
        "    MsgOut = column_ifexists('details_msg_s','')),\n" +
        "(FrontDoorWebApplicationFirewallLog\n" +
        "| project TimeGenerated,\n" +
        "    PolicyOut = tostring(column_ifexists('Policy','')),\n" +
        "    RuleOut = tostring(column_ifexists('RuleName','')),\n" +
        "    ActionOut = tostring(column_ifexists('Action','')),\n" +
        "    IpOut = tostring(column_ifexists('ClientIP','')),\n" +
        "    UriOut = tostring(column_ifexists('RequestUri','')),\n" +
        "    MatchOut = tostring(column_ifexists('Details','')),\n" +
        "    DataOut = '',\n" +
        "    MsgOut = '')";

    internal const string AppGatewayLogUnionQuery =
        "union isfuzzy=true\n" +
        "(AzureDiagnostics\n" +
        "| where Category == 'ApplicationGatewayFirewallLog'\n" +
        "| project TimeGenerated,\n" +
        "    PolicyOut = column_ifexists('policyScopeName_s',''),\n" +
        "    RuleOut = column_ifexists('ruleId_s',''),\n" +
        "    ActionOut = column_ifexists('action_s',''),\n" +
        "    IpOut = column_ifexists('clientIp_s',''),\n" +
        "    UriOut = column_ifexists('requestUri_s',''),\n" +
        "    MatchOut = column_ifexists('details_message_s',''),\n" +
        "    DataOut = column_ifexists('details_data_s',''),\n" +
        "    MsgOut = column_ifexists('Message','')),\n" +
        "(AGWFirewallLogs\n" +
        "| project TimeGenerated,\n" +
        "    PolicyOut = tostring(column_ifexists('PolicyScopeName','')),\n" +
        "    RuleOut = tostring(column_ifexists('RuleId','')),\n" +
        "    ActionOut = tostring(column_ifexists('Action','')),\n" +
        "    IpOut = tostring(column_ifexists('ClientIp','')),\n" +
        "    UriOut = tostring(column_ifexists('RequestUri','')),\n" +
        "    MatchOut = tostring(column_ifexists('DetailedMessage','')),\n" +
        "    DataOut = tostring(column_ifexists('DetailedData','')),\n" +
        "    MsgOut = tostring(column_ifexists('Message','')))";

    // ── Classification ───────────────────────────────────────────────────────

    internal static void Classify(WafRuleActivity activity, string policyMode)
    {
        var fpScore = 0;
        var attackScore = 0;
        var fpReasons = new List<string>();
        var attackReasons = new List<string>();

        var ruleId = ExtractRuleId(activity.RuleName);
        var payload = (string.Join(' ', activity.SampleUris) + " " + activity.SampleMatchData + " " + activity.SampleMatchVariable)
            .ToLowerInvariant();
        var matchContext = (activity.SampleMatchVariable + " " + activity.SampleMessage).ToLowerInvariant();

        if (FalsePositiveProneRuleIds.Contains(ruleId))
        {
            fpScore += 2;
            fpReasons.Add($"rule {ruleId} is a well-known false-positive-prone CRS/DRS rule that frequently matches legitimate payloads");
        }
        if (FpProneMatchVariables.Any(v => matchContext.Contains(v)))
        {
            fpScore += 2;
            fpReasons.Add("the match occurred in cookies or headers, where legitimate values such as session tokens often resemble attack patterns");
        }
        if (activity.DistinctIps <= 3 && activity.Count >= 10)
        {
            fpScore += 1;
            fpReasons.Add($"only {activity.DistinctIps} client IP(s) triggered it repeatedly ({activity.Count} events), which points to a recurring legitimate application flow rather than an attack campaign");
        }
        if (activity.DistinctUris <= 2 && activity.Count >= 10 && !AttackUriPatterns.Any(payload.Contains))
        {
            fpScore += 1;
            fpReasons.Add("the events concentrate on a small set of application URLs with no known attack signatures in the request");
        }

        var uriHits = AttackUriPatterns.Where(payload.Contains).Take(4).ToList();
        if (uriHits.Count > 0)
        {
            attackScore += 2;
            attackReasons.Add($"the requests contain known attack or probing patterns ({string.Join(", ", uriHits)})");
        }
        var scanners = ScannerSignatures.Where(s => payload.Contains(s) || matchContext.Contains(s)).ToList();
        if (scanners.Count > 0)
        {
            attackScore += 2;
            attackReasons.Add($"security-scanner signatures were detected ({string.Join(", ", scanners)})");
        }
        if (activity.DistinctIps >= 10)
        {
            attackScore += 1;
            attackReasons.Add($"{activity.DistinctIps} distinct source IPs are involved, consistent with a distributed scan or botnet activity");
        }
        if (activity.DistinctUris >= 15)
        {
            attackScore += 1;
            attackReasons.Add($"{activity.DistinctUris} distinct URIs were probed, consistent with enumeration or fuzzing");
        }
        if (activity.RuleName.Contains("Bot", StringComparison.OrdinalIgnoreCase))
        {
            attackScore += 1;
            attackReasons.Add("the bot manager rule set identified the traffic as automated");
        }

        activity.Classification = attackScore >= fpScore + 2 ? "Likely real attack"
            : fpScore >= attackScore + 2 ? "Possible false positive"
            : "Needs review";

        var sb = new StringBuilder();
        sb.Append($"{activity.Count} event(s) from {activity.DistinctIps} IP(s) across {activity.DistinctUris} URI(s) — ");
        sb.Append($"{activity.Blocked} blocked, {activity.Logged} logged");
        if (activity.Allowed > 0) sb.Append($", {activity.Allowed} allowed");
        if (activity.Redirected > 0) sb.Append($", {activity.Redirected} redirected");
        sb.Append(". ");
        switch (activity.Classification)
        {
            case "Likely real attack":
                sb.Append("Assessed as a likely real attack because ").Append(JoinReasons(attackReasons)).Append('.');
                break;
            case "Possible false positive":
                sb.Append("Assessed as a possible false positive because ").Append(JoinReasons(fpReasons)).Append('.');
                break;
            default:
                if (attackReasons.Count == 0 && fpReasons.Count == 0)
                    sb.Append("No strong indicators either way — the volume and pattern look unremarkable, but the matched payloads should be reviewed to be sure.");
                else
                {
                    sb.Append("The signals are mixed: ");
                    if (attackReasons.Count > 0) sb.Append("suggesting an attack, ").Append(JoinReasons(attackReasons));
                    if (attackReasons.Count > 0 && fpReasons.Count > 0) sb.Append("; suggesting a false positive, ");
                    if (fpReasons.Count > 0) sb.Append(JoinReasons(fpReasons));
                    sb.Append('.');
                }
                break;
        }
        activity.Explanation = sb.ToString();

        var recs = activity.Recommendations;
        switch (activity.Classification)
        {
            case "Possible false positive":
                var variable = ExtractMatchVariableName(activity.SampleMatchVariable + " " + activity.SampleMatchData);
                recs.Add(variable is not null
                    ? $"Consider adding a managed-rule exclusion for '{variable}' scoped to rule {ruleId} — a scoped exclusion is much safer than disabling the rule."
                    : $"Consider a scoped managed-rule exclusion for rule {ruleId} (take the exact match variable from the log's matchVariableName field) rather than disabling the rule.");
                recs.Add("Confirm with the application team that the flagged requests correspond to legitimate behaviour before adding the exclusion.");
                if (policyMode.Equals("Prevention", StringComparison.OrdinalIgnoreCase) && activity.Blocked > 0)
                    recs.Add("These requests are currently being blocked — if users report errors on the affected URLs, this rule is the likely cause.");
                break;

            case "Likely real attack":
                if (policyMode.Equals("Detection", StringComparison.OrdinalIgnoreCase))
                    recs.Add($"Policy '{activity.PolicyName}' is in Detection mode, so this traffic is only being logged — plan a switch to Prevention once false positives are ruled out.");
                else if (activity.Logged > 0 && activity.Blocked == 0)
                    recs.Add("The events were logged but not blocked — review the rule action / anomaly-score threshold so this traffic is actually stopped.");
                else if (activity.Blocked > 0)
                    recs.Add("The WAF is blocking this traffic correctly — no configuration change needed for this rule.");
                if (activity.DistinctIps is >= 1 and <= 5 && activity.SampleIps.Count > 0)
                    recs.Add($"A small set of sources is responsible ({string.Join(", ", activity.SampleIps.Take(3))}) — a custom block rule or rate limit for these IPs would cut the noise at the edge.");
                break;

            default:
                recs.Add("Inspect a few raw log entries for this rule (use the trackingReference / transactionId field) to see whether the matched payloads are legitimate.");
                recs.Add($"If the traffic is legitimate, add a scoped exclusion for rule {ruleId}; if malicious, ensure the action blocks it.");
                break;
        }
    }

    private static string JoinReasons(List<string> reasons) => reasons.Count switch
    {
        0 => "of the observed pattern",
        1 => reasons[0],
        _ => string.Join("; ", reasons.Take(reasons.Count - 1)) + "; and " + reasons[^1]
    };

    internal static string ExtractRuleId(string ruleName)
    {
        var parts = ruleName.Split('-', StringSplitOptions.RemoveEmptyEntries);
        for (var i = parts.Length - 1; i >= 0; i--)
            if (parts[i].Length >= 3 && parts[i].All(char.IsDigit))
                return parts[i];
        return ruleName;
    }

    /// <summary>Pulls a match variable like "CookieValue:mycookie" out of raw match details text.</summary>
    internal static string? ExtractMatchVariableName(string matchText)
    {
        if (string.IsNullOrWhiteSpace(matchText)) return null;
        foreach (var prefix in new[]
                 {
                     "CookieValue", "HeaderValue", "PostArgValue", "QueryParamValue",
                     "MultipartFormDataValue", "JsonValue", "RequestBodyPostArgNames",
                     "RequestCookieNames", "RequestHeaderNames", "QueryStringArgNames",
                     "RequestCookieValues", "RequestHeaderValues", "RequestArgValues", "RequestArgNames"
                 })
        {
            var idx = matchText.IndexOf(prefix, StringComparison.OrdinalIgnoreCase);
            if (idx < 0) continue;
            var end = idx;
            while (end < matchText.Length && !"\",]} ".Contains(matchText[end])) end++;
            return matchText[idx..end].TrimEnd(':');
        }
        return null;
    }

    internal static List<WafLogChange> BuildChanges(List<Dictionary<string, JsonElement>> rows)
    {
        var perRule = new Dictionary<string, Dictionary<string, (int Blocked, int Logged, int Total)>>(StringComparer.OrdinalIgnoreCase);
        foreach (var row in rows)
        {
            var rule = Cell(row, "RuleOut");
            var action = Cell(row, "ActionOut");
            var period = Cell(row, "Period");
            var count = CellInt(row, "Count");
            if (string.IsNullOrEmpty(rule) || string.IsNullOrEmpty(period)) continue;

            if (!perRule.TryGetValue(rule, out var periods))
                perRule[rule] = periods = new Dictionary<string, (int, int, int)>(StringComparer.OrdinalIgnoreCase);

            periods.TryGetValue(period, out var agg);
            var isBlock = action.Equals("Block", StringComparison.OrdinalIgnoreCase) || action.Equals("Blocked", StringComparison.OrdinalIgnoreCase);
            var isLog = action.Equals("Log", StringComparison.OrdinalIgnoreCase) ||
                        action.Equals("Matched", StringComparison.OrdinalIgnoreCase) ||
                        action.Equals("Detected", StringComparison.OrdinalIgnoreCase) ||
                        action.Equals("AnomalyScoring", StringComparison.OrdinalIgnoreCase);
            periods[period] = (agg.Blocked + (isBlock ? count : 0), agg.Logged + (isLog ? count : 0), agg.Total + count);
        }

        var changes = new List<WafLogChange>();
        foreach (var (rule, periods) in perRule)
        {
            periods.TryGetValue("current", out var cur);
            periods.TryGetValue("previous", out var prev);

            if (prev.Total == 0 && cur.Total > 0)
            {
                changes.Add(new WafLogChange { ChangeType = "New", RuleName = rule,
                    Description = $"Started triggering this period ({cur.Total} events; none in the previous period) — new attack activity, an application change, or a policy change." });
                continue;
            }
            if (cur.Total == 0 && prev.Total > 0)
            {
                changes.Add(new WafLogChange { ChangeType = "Stopped", RuleName = rule,
                    Description = $"No events this period ({prev.Total} in the previous period) — the underlying issue may be fixed, the traffic stopped, or an exclusion/rule change now suppresses it." });
                continue;
            }

            if (cur.Blocked > 0 && prev.Blocked == 0 && prev.Logged > 0)
                changes.Add(new WafLogChange { ChangeType = "Now blocking", RuleName = rule,
                    Description = $"Was log-only in the previous period, now blocking ({cur.Blocked} blocked) — the policy mode or rule action was tightened." });
            else if (prev.Blocked > 0 && cur.Blocked == 0 && cur.Logged > 0)
                changes.Add(new WafLogChange { ChangeType = "Now log-only", RuleName = rule,
                    Description = $"Was blocking in the previous period ({prev.Blocked} blocked), now only logging — the policy mode or rule action was relaxed." });

            if (cur.Total >= prev.Total * 2 && cur.Total - prev.Total >= 10)
                changes.Add(new WafLogChange { ChangeType = "Increased", RuleName = rule,
                    Description = $"Activity increased from {prev.Total} to {cur.Total} events versus the previous period." });
            else if (prev.Total >= cur.Total * 2 && prev.Total - cur.Total >= 10)
                changes.Add(new WafLogChange { ChangeType = "Decreased", RuleName = rule,
                    Description = $"Activity decreased from {prev.Total} to {cur.Total} events versus the previous period." });
        }

        return changes
            .OrderBy(c => c.ChangeType switch { "New" => 0, "Now blocking" => 1, "Now log-only" => 2, "Stopped" => 3, "Increased" => 4, _ => 5 })
            .ThenBy(c => c.RuleName, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }
}
