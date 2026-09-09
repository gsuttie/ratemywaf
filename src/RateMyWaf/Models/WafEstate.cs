namespace RateMyWaf.Models;

/// <summary>One protectable surface of an edge resource: a Front Door endpoint/domain or an Application Gateway listener.</summary>
public sealed class WafSurfaceInfo
{
    /// <summary>Resource ID (used to match security-policy domain associations / listener links).</summary>
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string HostName { get; set; } = string.Empty;

    /// <summary>Front Door Standard/Premium custom domain (as opposed to an endpoint).</summary>
    public bool IsCustomDomain { get; set; }

    /// <summary>Extra detail for display, e.g. "HTTPS :443".</summary>
    public string Detail { get; set; } = string.Empty;

    /// <summary>The WAF policy that covers this surface, or null when it has no WAF at all.</summary>
    public string? WafPolicyId { get; set; }

    public string Display => string.IsNullOrEmpty(HostName) ? Name : HostName;
}

public sealed class AppGatewayInfo
{
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string ResourceGroup { get; set; } = string.Empty;
    public string SubscriptionId { get; set; } = string.Empty;
    public string Location { get; set; } = string.Empty;

    /// <summary>SKU tier, e.g. "WAF_v2", "Standard_v2", "WAF", "Standard".</summary>
    public string Tier { get; set; } = string.Empty;

    /// <summary>Resource ID of the gateway-level WAF policy, if any.</summary>
    public string? FirewallPolicyId { get; set; }

    /// <summary>HTTP listeners: the attack surface of the gateway. A listener is covered by the gateway-level policy, its own policy or the legacy config.</summary>
    public List<WafSurfaceInfo> Listeners { get; set; } = new();

    /// <summary>WAF policy IDs attached to individual URL path rules (partial coverage; shown, not rated as a surface).</summary>
    public List<string> PathRulePolicyIds { get; set; } = new();

    // Legacy inline webApplicationFirewallConfiguration
    public bool LegacyWafPresent { get; set; }
    public bool LegacyWafConfigured { get; set; }   // present AND enabled
    public string LegacyWafMode { get; set; } = string.Empty;
    public string LegacyRuleSetType { get; set; } = string.Empty;
    public string LegacyRuleSetVersion { get; set; } = string.Empty;
    public int LegacyDisabledRuleCount { get; set; }
    public int LegacyExclusionCount { get; set; }
    public bool? LegacyRequestBodyCheck { get; set; }
    public int? LegacyMaxRequestBodySizeKb { get; set; }
    public int? LegacyFileUploadLimitMb { get; set; }

    public bool IsWafTier => Tier.Contains("WAF", StringComparison.OrdinalIgnoreCase);
    public bool HasWaf => FirewallPolicyId is not null || LegacyWafConfigured || Listeners.Any(l => l.WafPolicyId is not null);

    public bool? WafLogsEnabled { get; set; }
    public List<string> LogDestinations { get; set; } = new();

    /// <summary>ARM IDs of the Log Analytics workspaces that receive this resource's WAF firewall log.</summary>
    public List<string> LogWorkspaceIds { get; set; } = new();

    /// <summary>Synthetic ID used for the legacy inline configuration when it is rated as a policy.</summary>
    public string LegacyPolicyId => Id + "/webApplicationFirewallConfiguration";
}

public enum FrontDoorKind { Classic, Standard, Premium }

public sealed class FrontDoorInfo
{
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string ResourceGroup { get; set; } = string.Empty;
    public string SubscriptionId { get; set; } = string.Empty;
    public FrontDoorKind Kind { get; set; }
    public string SkuName { get; set; } = string.Empty;

    /// <summary>Classic frontend endpoints, or Standard/Premium endpoints + custom domains.</summary>
    public List<WafSurfaceInfo> Endpoints { get; set; } = new();

    /// <summary>WAF policy IDs associated with this profile (security policy links for Standard/Premium).</summary>
    public List<string> AssociatedPolicyIds { get; set; } = new();

    public bool HasWafAssociation => Kind == FrontDoorKind.Classic
        ? Endpoints.Any(e => !string.IsNullOrEmpty(e.WafPolicyId))
        : AssociatedPolicyIds.Count > 0;

    public bool? WafLogsEnabled { get; set; }
    public List<string> LogDestinations { get; set; } = new();

    /// <summary>ARM IDs of the Log Analytics workspaces that receive this resource's WAF firewall log.</summary>
    public List<string> LogWorkspaceIds { get; set; } = new();
}

public enum WafPolicyKind { FrontDoor, ApplicationGateway, Cdn }

public sealed class WafPolicyInfo
{
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string ResourceGroup { get; set; } = string.Empty;
    public string SubscriptionId { get; set; } = string.Empty;
    public WafPolicyKind Kind { get; set; }
    public string SkuName { get; set; } = string.Empty;

    /// <summary>"Prevention" or "Detection".</summary>
    public string Mode { get; set; } = string.Empty;

    /// <summary>"Enabled" or "Disabled".</summary>
    public string EnabledState { get; set; } = string.Empty;

    public string RequestBodyCheck { get; set; } = string.Empty;
    public int? MaxRequestBodySizeKb { get; set; }
    public int? FileUploadLimitMb { get; set; }
    public string RedirectUrl { get; set; } = string.Empty;
    public int? CustomBlockResponseStatusCode { get; set; }

    /// <summary>Policy-level exclusions (App Gateway policies keep these at managedRules level).</summary>
    public int ExclusionCount { get; set; }

    public List<WafCustomRule> CustomRules { get; set; } = new();
    public int CustomRuleCount => CustomRules.Count;

    public List<ManagedRuleSetInfo> ManagedRuleSets { get; set; } = new();

    /// <summary>Raw IDs of resources this policy is linked to.</summary>
    public List<string> AssociationIds { get; set; } = new();
    public List<WafAssociation> Associations { get; set; } = new();

    /// <summary>True for the synthetic policy built from an Application Gateway's legacy inline WAF configuration.</summary>
    public bool IsLegacyInline { get; set; }

    public IEnumerable<string> ProtectedResourceNames =>
        Associations.Select(a => a.TargetName).Distinct(StringComparer.OrdinalIgnoreCase);

    public string KindLabel => Kind switch
    {
        WafPolicyKind.FrontDoor => "Front Door",
        WafPolicyKind.ApplicationGateway => "App Gateway",
        _ => "CDN"
    };

    public bool IsEnabled => !EnabledState.Equals("Disabled", StringComparison.OrdinalIgnoreCase);
    public bool IsPrevention => Mode.Equals("Prevention", StringComparison.OrdinalIgnoreCase);
}

public sealed class ManagedRuleSetInfo
{
    public string RuleSetType { get; set; } = string.Empty;
    public string RuleSetVersion { get; set; } = string.Empty;
    public string? LatestVersion { get; set; }

    /// <summary>True = on latest, false = outdated, null = latest version could not be determined.</summary>
    public bool? IsLatest { get; set; }

    public int DisabledRuleCount { get; set; }
    public int ActionOverrideCount { get; set; }
    public int ExclusionCount { get; set; }
    public List<string> GroupOverrideSummaries { get; set; } = new();
}

public sealed class WafCustomRule
{
    public string Name { get; set; } = string.Empty;
    public int Priority { get; set; }
    public string RuleType { get; set; } = string.Empty;
    public string Action { get; set; } = string.Empty;
    public string EnabledState { get; set; } = string.Empty;
    public int? RateLimitThreshold { get; set; }
    public string RateLimitDuration { get; set; } = string.Empty;
    public List<string> Conditions { get; set; } = new();
}

public sealed class WafAssociation
{
    public string Id { get; set; } = string.Empty;
    public string TargetType { get; set; } = string.Empty;
    public string TargetName { get; set; } = string.Empty;
    public string Detail { get; set; } = string.Empty;
    public string Display => string.IsNullOrEmpty(Detail) ? TargetName : $"{TargetName} — {Detail}";
}

public sealed class WafFinding
{
    /// <summary>"High", "Medium" or "Info".</summary>
    public string Severity { get; set; } = "Info";
    public string Category { get; set; } = string.Empty;
    public string Message { get; set; } = string.Empty;
    public string ResourceName { get; set; } = string.Empty;
    public string ResourceId { get; set; } = string.Empty;
    public string SubscriptionId { get; set; } = string.Empty;

    /// <summary>Concrete guidance on how to fix the finding.</summary>
    public string Fix { get; set; } = string.Empty;
}

/// <summary>Complete result of a WAF estate scan for one flow across one or more subscriptions.</summary>
public sealed class WafScanResult
{
    public WafFlowKind Flow { get; set; }
    public List<AppGatewayInfo> AppGateways { get; set; } = new();
    public List<FrontDoorInfo> FrontDoors { get; set; } = new();
    public List<WafPolicyInfo> WafPolicies { get; set; } = new();
    public List<WafFinding> Findings { get; set; } = new();
    public List<WafRating> Ratings { get; set; } = new();
    public List<string> Warnings { get; set; } = new();
    public List<string> SubscriptionIds { get; set; } = new();
    public DateTime CompletedAt { get; set; } = DateTime.Now;

    public int EdgeCount => Flow == WafFlowKind.FrontDoor ? FrontDoors.Count : AppGateways.Count;

    public void Merge(WafScanResult other)
    {
        AppGateways.AddRange(other.AppGateways);
        FrontDoors.AddRange(other.FrontDoors);
        WafPolicies.AddRange(other.WafPolicies);
        Findings.AddRange(other.Findings);
        Ratings.AddRange(other.Ratings);
        Warnings.AddRange(other.Warnings);
        SubscriptionIds.AddRange(other.SubscriptionIds);
    }
}
