namespace RateMyWaf.Models;

/// <summary>A Log Analytics workspace the signed-in identity can see, from any subscription.</summary>
public sealed class LogWorkspaceInfo
{
    /// <summary>ARM resource ID (what diagnostic settings reference).</summary>
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string ResourceGroup { get; set; } = string.Empty;
    public string SubscriptionId { get; set; } = string.Empty;
    public string Location { get; set; } = string.Empty;

    /// <summary>Workspace GUID used by the Log Analytics query API.</summary>
    public string CustomerId { get; set; } = string.Empty;
}

/// <summary>Result of analysing WAF logs for one edge resource over a time window.</summary>
public sealed class WafLogAnalysis
{
    public WafFlowKind Flow { get; set; }
    public string TargetId { get; set; } = string.Empty;
    public string TargetName { get; set; } = string.Empty;

    /// <summary>Workspace the query ran against; empty when the resource-centric (auto-detect) query was used.</summary>
    public string WorkspaceName { get; set; } = string.Empty;
    public List<string> PolicyNames { get; set; } = new();
    public string TimeRangeKey { get; set; } = string.Empty;
    public string TimeRangeLabel { get; set; } = string.Empty;

    public bool LogsQueryable { get; set; } = true;
    public string QueryError { get; set; } = string.Empty;

    public int TotalEvents { get; set; }
    public int BlockedCount { get; set; }
    public int LoggedCount { get; set; }
    public int AllowedCount { get; set; }
    public int RedirectedCount { get; set; }
    public int DistinctRules { get; set; }

    public List<WafRuleActivity> RuleActivities { get; set; } = new();
    public List<WafLogChange> Changes { get; set; } = new();
    public List<string> Warnings { get; set; } = new();
}

public sealed class WafRuleActivity
{
    public string RuleName { get; set; } = string.Empty;
    public string PolicyName { get; set; } = string.Empty;

    public int Count { get; set; }
    public int Blocked { get; set; }
    public int Logged { get; set; }
    public int Allowed { get; set; }
    public int Redirected { get; set; }
    public int DistinctIps { get; set; }
    public int DistinctUris { get; set; }

    public List<string> SampleIps { get; set; } = new();
    public List<string> SampleUris { get; set; } = new();
    public string SampleMatchVariable { get; set; } = string.Empty;
    public string SampleMatchData { get; set; } = string.Empty;
    public string SampleMessage { get; set; } = string.Empty;

    /// <summary>"Likely real attack", "Possible false positive" or "Needs review".</summary>
    public string Classification { get; set; } = "Needs review";
    public string Explanation { get; set; } = string.Empty;
    public List<string> Recommendations { get; set; } = new();
}

public sealed class WafLogChange
{
    /// <summary>"New", "Stopped", "Now blocking", "Now log-only", "Increased" or "Decreased".</summary>
    public string ChangeType { get; set; } = string.Empty;
    public string RuleName { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
}
