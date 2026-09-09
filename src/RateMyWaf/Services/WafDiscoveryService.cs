using System.Text.Json;
using RateMyWaf.Models;
using RateMyWaf.Services.Azure;
using static RateMyWaf.Services.Azure.Json;

namespace RateMyWaf.Services;

/// <summary>
/// Discovers the WAF estate of one flow (Front Doors or Application Gateways plus their WAF policies)
/// via Azure Resource Graph and ARM, resolves per-surface coverage, checks managed rule set versions
/// and diagnostic settings, produces findings and rates every edge resource A-F.
/// Strictly read-only: nothing here ever modifies an Azure resource.
/// </summary>
public sealed class WafDiscoveryService
{
    internal const string TypeAppGateway = "microsoft.network/applicationgateways";
    internal const string TypeFrontDoorClassic = "microsoft.network/frontdoors";
    internal const string TypeCdnProfile = "microsoft.cdn/profiles";
    internal const string TypeAppGwPolicy = "microsoft.network/applicationgatewaywebapplicationfirewallpolicies";
    internal const string TypeFdPolicy = "microsoft.network/frontdoorwebapplicationfirewallpolicies";
    internal const string TypeCdnPolicy = "microsoft.cdn/cdnwebapplicationfirewallpolicies";

    // Only CDN profiles with a Front Door SKU count as Front Doors (classic CDN profiles are excluded).
    private const string FrontDoorSkuFilter =
        "| where type !~ 'microsoft.cdn/profiles' or tostring(sku.name) in~ ('Standard_AzureFrontDoor','Premium_AzureFrontDoor')";

    private static readonly string SummaryQuery =
        $"Resources | where type in~ ('{TypeAppGateway}','{TypeFrontDoorClassic}','{TypeCdnProfile}','{TypeAppGwPolicy}','{TypeFdPolicy}','{TypeCdnPolicy}') " +
        FrontDoorSkuFilter +
        " | summarize cnt = count() by subscriptionId, type";

    private static string EdgeQuery(WafFlowKind flow) => flow == WafFlowKind.FrontDoor
        ? $"Resources | where type in~ ('{TypeFrontDoorClassic}','{TypeCdnProfile}') {FrontDoorSkuFilter} | project id, name, type, location, resourceGroup, subscriptionId, sku, properties"
        : $"Resources | where type =~ '{TypeAppGateway}' | project id, name, type, location, resourceGroup, subscriptionId, sku, properties";

    private static string PolicyQuery(WafFlowKind flow) => flow == WafFlowKind.FrontDoor
        ? $"Resources | where type in~ ('{TypeFdPolicy}','{TypeCdnPolicy}') | project id, name, type, location, resourceGroup, subscriptionId, sku, properties"
        : $"Resources | where type =~ '{TypeAppGwPolicy}' | project id, name, type, location, resourceGroup, subscriptionId, sku, properties";

    private const string SecurityPoliciesQuery =
        "cdnresources | where type =~ 'microsoft.cdn/profiles/securitypolicies' | project id, name, properties";

    private const string CustomDomainsQuery =
        "cdnresources | where type =~ 'microsoft.cdn/profiles/customdomains' | project id, name, properties";

    private readonly IAzureApi _azure;
    private readonly ILogger<WafDiscoveryService> _logger;

    public WafDiscoveryService(IAzureApi azure, ILogger<WafDiscoveryService> logger)
    {
        _azure = azure;
        _logger = logger;
    }

    // ── Public API ───────────────────────────────────────────────────────────

    /// <summary>Counts of WAF-related resources per subscription, so the scope step can highlight the relevant ones.</summary>
    public async Task<Dictionary<string, WafSubscriptionSummary>> GetSummariesAsync(
        IReadOnlyCollection<string> subscriptionIds, string? tenantId, CancellationToken ct = default)
    {
        var result = subscriptionIds.ToDictionary(
            id => id, id => new WafSubscriptionSummary { SubscriptionId = id }, StringComparer.OrdinalIgnoreCase);
        if (subscriptionIds.Count == 0) return result;

        var rows = await _azure.QueryResourceGraphAsync(SummaryQuery, subscriptionIds, tenantId, ct);
        foreach (var row in rows)
        {
            if (!result.TryGetValue(Str(row, "subscriptionId"), out var summary)) continue;
            var cnt = row.TryGetProperty("cnt", out var c) && c.TryGetInt32(out var n) ? n : 0;
            switch (Str(row, "type").ToLowerInvariant())
            {
                case TypeAppGateway: summary.AppGatewayCount += cnt; break;
                case TypeFrontDoorClassic:
                case TypeCdnProfile: summary.FrontDoorCount += cnt; break;
                case TypeAppGwPolicy: summary.AppGatewayPolicyCount += cnt; break;
                default: summary.FrontDoorPolicyCount += cnt; break;
            }
        }
        return result;
    }

    /// <summary>Full read-only scan of one flow across the supplied subscriptions (which must share a tenant).</summary>
    public async Task<WafScanResult> ScanAsync(
        WafFlowKind flow, IReadOnlyCollection<string> subscriptionIds, string? tenantId,
        IProgress<string>? progress = null, CancellationToken ct = default)
    {
        var result = new WafScanResult { Flow = flow, SubscriptionIds = subscriptionIds.ToList() };
        if (subscriptionIds.Count == 0) return result;

        progress?.Report("Querying Azure Resource Graph…");
        var edgeTask = _azure.QueryResourceGraphAsync(EdgeQuery(flow), subscriptionIds, tenantId, ct);
        var policyTask = _azure.QueryResourceGraphAsync(PolicyQuery(flow), subscriptionIds, tenantId, ct);
        await Task.WhenAll(edgeTask, policyTask);

        foreach (var row in edgeTask.Result)
        {
            switch (Str(row, "type").ToLowerInvariant())
            {
                case TypeAppGateway: result.AppGateways.Add(ParseAppGateway(row)); break;
                case TypeFrontDoorClassic: result.FrontDoors.Add(ParseClassicFrontDoor(row)); break;
                case TypeCdnProfile: result.FrontDoors.Add(ParseFrontDoorProfile(row)); break;
            }
        }
        foreach (var row in policyTask.Result)
            result.WafPolicies.Add(ParseWafPolicy(row));

        if (flow == WafFlowKind.FrontDoor)
        {
            progress?.Report("Resolving Front Door domains and security policies…");
            await ApplyProfileDomainCoverageAsync(result, subscriptionIds, tenantId, ct);
            LinkProfilesToPolicies(result);
        }
        else
        {
            ApplyGatewayCoverage(result);
        }

        progress?.Report("Checking managed rule set versions…");
        await ApplyLatestRuleSetVersionsAsync(result, subscriptionIds.First(), tenantId, ct);

        progress?.Report("Reading diagnostic settings…");
        await ApplyDiagnosticsAsync(result, tenantId, ct);

        progress?.Report("Rating…");
        Finalize(result);
        return result;
    }

    /// <summary>Findings + ratings. Split out so demo data and tests can reuse it on an already-populated result.</summary>
    public static void Finalize(WafScanResult result)
    {
        result.Findings = WafFindingsBuilder.Build(result);
        WafRatingService.RateAll(result);
        result.CompletedAt = DateTime.Now;
    }

    // ── Parsing ──────────────────────────────────────────────────────────────

    internal static AppGatewayInfo ParseAppGateway(JsonElement row)
    {
        var info = new AppGatewayInfo
        {
            Id = Str(row, "id"),
            Name = Str(row, "name"),
            ResourceGroup = Str(row, "resourceGroup"),
            SubscriptionId = Str(row, "subscriptionId"),
            Location = Str(row, "location")
        };

        var props = Obj(row, "properties");
        if (props.ValueKind != JsonValueKind.Object) return info;

        info.Tier = FirstNonEmpty(Str(Obj(props, "sku"), "tier"), Str(Obj(row, "sku"), "tier"));
        info.FirewallPolicyId = NullIfEmpty(Str(Obj(props, "firewallPolicy"), "id"));

        var legacy = Obj(props, "webApplicationFirewallConfiguration");
        if (legacy.ValueKind == JsonValueKind.Object)
        {
            info.LegacyWafPresent = true;
            info.LegacyWafConfigured = Bool(legacy, "enabled") == true;
            info.LegacyWafMode = Str(legacy, "firewallMode");
            info.LegacyRuleSetType = Str(legacy, "ruleSetType");
            info.LegacyRuleSetVersion = Str(legacy, "ruleSetVersion");
            info.LegacyRequestBodyCheck = Bool(legacy, "requestBodyCheck");
            info.LegacyMaxRequestBodySizeKb = Int(legacy, "maxRequestBodySizeInKb");
            info.LegacyFileUploadLimitMb = Int(legacy, "fileUploadLimitInMb");
            info.LegacyExclusionCount = ArrLen(legacy, "exclusions");
            foreach (var group in Arr(legacy, "disabledRuleGroups"))
            {
                // Listed rule IDs count individually; an empty list disables the whole group.
                var rules = ArrLen(group, "rules");
                info.LegacyDisabledRuleCount += rules > 0 ? rules : 2;
            }
        }

        foreach (var listener in Arr(props, "httpListeners"))
        {
            var lp = Obj(listener, "properties");
            var hosts = Arr(lp, "hostNames").Select(h => h.GetString() ?? "").Where(h => h.Length > 0).ToList();
            var host = FirstNonEmpty(Str(lp, "hostName"), hosts.Count > 0 ? string.Join(", ", hosts) : "");
            var protocol = Str(lp, "protocol");
            info.Listeners.Add(new WafSurfaceInfo
            {
                Id = Str(listener, "id"),
                Name = Str(listener, "name"),
                HostName = host,
                Detail = string.IsNullOrEmpty(protocol) ? "" : protocol.ToUpperInvariant(),
                WafPolicyId = NullIfEmpty(Str(Obj(lp, "firewallPolicy"), "id"))
            });
        }

        foreach (var map in Arr(props, "urlPathMaps"))
            foreach (var rule in Arr(Obj(map, "properties"), "pathRules"))
            {
                var pid = Str(Obj(Obj(rule, "properties"), "firewallPolicy"), "id");
                if (!string.IsNullOrEmpty(pid) && !info.PathRulePolicyIds.Contains(pid, StringComparer.OrdinalIgnoreCase))
                    info.PathRulePolicyIds.Add(pid);
            }

        return info;
    }

    internal static FrontDoorInfo ParseClassicFrontDoor(JsonElement row)
    {
        var info = new FrontDoorInfo
        {
            Id = Str(row, "id"),
            Name = Str(row, "name"),
            ResourceGroup = Str(row, "resourceGroup"),
            SubscriptionId = Str(row, "subscriptionId"),
            Kind = FrontDoorKind.Classic,
            SkuName = "Classic"
        };

        foreach (var ep in Arr(Obj(row, "properties"), "frontendEndpoints"))
        {
            var epProps = Obj(ep, "properties");
            info.Endpoints.Add(new WafSurfaceInfo
            {
                Id = Str(ep, "id"),
                Name = Str(ep, "name"),
                HostName = Str(epProps, "hostName"),
                WafPolicyId = NullIfEmpty(Str(Obj(epProps, "webApplicationFirewallPolicyLink"), "id"))
            });
        }
        return info;
    }

    internal static FrontDoorInfo ParseFrontDoorProfile(JsonElement row)
    {
        var skuName = Str(Obj(row, "sku"), "name");
        return new FrontDoorInfo
        {
            Id = Str(row, "id"),
            Name = Str(row, "name"),
            ResourceGroup = Str(row, "resourceGroup"),
            SubscriptionId = Str(row, "subscriptionId"),
            Kind = skuName.StartsWith("Premium", StringComparison.OrdinalIgnoreCase) ? FrontDoorKind.Premium : FrontDoorKind.Standard,
            SkuName = skuName
        };
    }

    internal static WafPolicyInfo ParseWafPolicy(JsonElement row)
    {
        var type = Str(row, "type").ToLowerInvariant();
        var info = new WafPolicyInfo
        {
            Id = Str(row, "id"),
            Name = Str(row, "name"),
            ResourceGroup = Str(row, "resourceGroup"),
            SubscriptionId = Str(row, "subscriptionId"),
            Kind = type switch
            {
                TypeAppGwPolicy => WafPolicyKind.ApplicationGateway,
                TypeCdnPolicy => WafPolicyKind.Cdn,
                _ => WafPolicyKind.FrontDoor
            },
            SkuName = Str(Obj(row, "sku"), "name")
        };

        var props = Obj(row, "properties");
        if (props.ValueKind != JsonValueKind.Object) return info;

        var settings = Obj(props, "policySettings");
        info.Mode = Str(settings, "mode");
        // App Gateway policies use "state"; Front Door and CDN policies use "enabledState".
        info.EnabledState = FirstNonEmpty(Str(settings, "state"), Str(settings, "enabledState"));

        if (settings.ValueKind == JsonValueKind.Object && settings.TryGetProperty("requestBodyCheck", out var rbc))
            info.RequestBodyCheck = rbc.ValueKind switch
            {
                JsonValueKind.True => "Enabled",
                JsonValueKind.False => "Disabled",
                JsonValueKind.String => rbc.GetString() ?? string.Empty,
                _ => string.Empty
            };
        info.MaxRequestBodySizeKb = Int(settings, "maxRequestBodySizeInKb");
        info.FileUploadLimitMb = Int(settings, "fileUploadLimitInMb");
        info.RedirectUrl = Str(settings, "redirectUrl");
        info.CustomBlockResponseStatusCode = Int(settings, "customBlockResponseStatusCode");

        var managed = Obj(props, "managedRules");
        if (managed.ValueKind == JsonValueKind.Object)
        {
            foreach (var rs in Arr(managed, "managedRuleSets"))
                info.ManagedRuleSets.Add(ParseManagedRuleSet(rs));
            // App Gateway policies keep exclusions at managedRules level.
            info.ExclusionCount = ArrLen(managed, "exclusions");
        }

        // Custom rules: App Gateway policies hold an array; Front Door/CDN wrap it in { rules: [...] }.
        if (props.TryGetProperty("customRules", out var custom))
        {
            var rulesArray = custom.ValueKind == JsonValueKind.Array
                ? custom
                : custom.ValueKind == JsonValueKind.Object && custom.TryGetProperty("rules", out var rules) && rules.ValueKind == JsonValueKind.Array
                    ? rules
                    : default;

            if (rulesArray.ValueKind == JsonValueKind.Array)
                foreach (var rule in rulesArray.EnumerateArray())
                    info.CustomRules.Add(ParseCustomRule(rule));

            info.CustomRules.Sort((a, b) => a.Priority.CompareTo(b.Priority));
        }

        foreach (var linkProp in new[]
                 {
                     "applicationGateways", "httpListeners", "pathBasedRules",          // App Gateway
                     "frontendEndpointLinks", "routingRuleLinks", "securityPolicyLinks", // Front Door
                     "endpointLinks"                                                     // CDN
                 })
        {
            foreach (var link in Arr(props, linkProp))
            {
                var id = Str(link, "id");
                if (string.IsNullOrEmpty(id)) continue;
                info.AssociationIds.Add(id);
                info.Associations.Add(ParseAssociation(id));
            }
        }
        return info;
    }

    internal static ManagedRuleSetInfo ParseManagedRuleSet(JsonElement rs)
    {
        var info = new ManagedRuleSetInfo
        {
            RuleSetType = Str(rs, "ruleSetType"),
            RuleSetVersion = Str(rs, "ruleSetVersion"),
            ExclusionCount = ArrLen(rs, "exclusions")
        };

        foreach (var group in Arr(rs, "ruleGroupOverrides"))
        {
            var groupName = Str(group, "ruleGroupName");
            int disabled = 0, actionOverrides = 0;
            info.ExclusionCount += ArrLen(group, "exclusions");

            foreach (var rule in Arr(group, "rules"))
            {
                // App Gateway uses "state", Front Door uses "enabledState".
                var state = FirstNonEmpty(Str(rule, "state"), Str(rule, "enabledState"));
                if (state.Equals("Disabled", StringComparison.OrdinalIgnoreCase)) disabled++;
                if (!string.IsNullOrEmpty(Str(rule, "action"))) actionOverrides++;
                info.ExclusionCount += ArrLen(rule, "exclusions");
            }

            info.DisabledRuleCount += disabled;
            info.ActionOverrideCount += actionOverrides;

            var parts = new List<string>();
            if (disabled > 0) parts.Add($"{disabled} rule{(disabled == 1 ? "" : "s")} disabled");
            if (actionOverrides > 0) parts.Add($"{actionOverrides} action override{(actionOverrides == 1 ? "" : "s")}");
            if (parts.Count > 0) info.GroupOverrideSummaries.Add($"{groupName}: {string.Join(", ", parts)}");
        }
        return info;
    }

    internal static WafCustomRule ParseCustomRule(JsonElement rule)
    {
        var info = new WafCustomRule
        {
            Name = Str(rule, "name"),
            Priority = Int(rule, "priority") ?? 0,
            RuleType = Str(rule, "ruleType"),
            Action = Str(rule, "action"),
            EnabledState = FirstNonEmpty(Str(rule, "state"), Str(rule, "enabledState"), "Enabled"),
            RateLimitThreshold = Int(rule, "rateLimitThreshold")
        };

        // Rate limit window: App Gateway has rateLimitDuration ("OneMin"), Front Door has rateLimitDurationInMinutes.
        var duration = Str(rule, "rateLimitDuration");
        if (string.IsNullOrEmpty(duration))
        {
            var minutes = Int(rule, "rateLimitDurationInMinutes");
            if (minutes.HasValue) duration = $"{minutes} min";
        }
        info.RateLimitDuration = duration;

        foreach (var cond in Arr(rule, "matchConditions"))
            info.Conditions.Add(BuildConditionText(cond));

        return info;
    }

    /// <summary>Renders one match condition as readable text, handling both API shapes.</summary>
    internal static string BuildConditionText(JsonElement cond)
    {
        var variables = new List<string>();
        var fdVariable = Str(cond, "matchVariable");
        if (!string.IsNullOrEmpty(fdVariable))
        {
            var selector = Str(cond, "selector");
            variables.Add(string.IsNullOrEmpty(selector) ? fdVariable : $"{fdVariable}.{selector}");
        }
        else
        {
            foreach (var v in Arr(cond, "matchVariables"))
            {
                var name = Str(v, "variableName");
                var selector = Str(v, "selector");
                variables.Add(string.IsNullOrEmpty(selector) ? name : $"{name}.{selector}");
            }
        }

        var op = Str(cond, "operator");
        var negated = new[] { "negateCondition", "negationConditon", "negationCondition" }
            .Any(p => Bool(cond, p) == true);

        var values = new List<string>();
        foreach (var prop in new[] { "matchValue", "matchValues" })
            foreach (var v in Arr(cond, prop))
                if (v.ValueKind == JsonValueKind.String) values.Add(v.GetString() ?? string.Empty);

        var valueText = values.Count switch
        {
            0 => string.Empty,
            <= 4 => $" [{string.Join(", ", values)}]",
            _ => $" [{string.Join(", ", values.Take(4))}, +{values.Count - 4} more]"
        };

        return $"{string.Join(", ", variables)} {(negated ? "NOT " : "")}{op}{valueText}".Trim();
    }

    internal static WafAssociation ParseAssociation(string id)
    {
        var assoc = new WafAssociation { Id = id, TargetName = id, TargetType = "Resource" };
        var segments = id.Split('/', StringSplitOptions.RemoveEmptyEntries);

        var providerIdx = Array.FindIndex(segments, s => s.Equals("providers", StringComparison.OrdinalIgnoreCase));
        if (providerIdx < 0 || segments.Length < providerIdx + 4) return assoc;

        var resourceType = segments[providerIdx + 2].ToLowerInvariant();
        assoc.TargetName = segments[providerIdx + 3];
        assoc.TargetType = resourceType switch
        {
            "applicationgateways" => "Application Gateway",
            "frontdoors" => "Front Door",
            "profiles" => "Front Door",
            _ => "CDN"
        };

        if (segments.Length >= providerIdx + 6)
        {
            var childType = segments[providerIdx + 4].ToLowerInvariant();
            var childName = segments[providerIdx + 5];
            assoc.Detail = childType switch
            {
                "httplisteners" => $"listener {childName}",
                "pathbasedrules" => $"path rule {childName}",
                "frontendendpoints" => $"endpoint {childName}",
                "routingrules" => $"routing rule {childName}",
                "securitypolicies" => $"security policy {childName}",
                "endpoints" or "afdendpoints" => $"endpoint {childName}",
                _ => $"{childType} {childName}"
            };
        }
        return assoc;
    }

    // ── Application Gateway coverage ─────────────────────────────────────────

    /// <summary>
    /// Resolves which policy covers each listener (gateway-level policy, per-listener policy or the
    /// legacy inline config) and turns a legacy inline configuration into a synthetic policy so it can
    /// be rated with the same engine.
    /// </summary>
    internal static void ApplyGatewayCoverage(WafScanResult result)
    {
        foreach (var gw in result.AppGateways)
        {
            WafPolicyInfo? legacy = null;
            if (gw.LegacyWafPresent && gw.FirewallPolicyId is null)
            {
                legacy = new WafPolicyInfo
                {
                    Id = gw.LegacyPolicyId,
                    Name = $"{gw.Name} (inline WAF configuration)",
                    ResourceGroup = gw.ResourceGroup,
                    SubscriptionId = gw.SubscriptionId,
                    Kind = WafPolicyKind.ApplicationGateway,
                    IsLegacyInline = true,
                    EnabledState = gw.LegacyWafConfigured ? "Enabled" : "Disabled",
                    Mode = gw.LegacyWafMode,
                    RequestBodyCheck = gw.LegacyRequestBodyCheck switch { true => "Enabled", false => "Disabled", null => "" },
                    MaxRequestBodySizeKb = gw.LegacyMaxRequestBodySizeKb,
                    FileUploadLimitMb = gw.LegacyFileUploadLimitMb,
                    AssociationIds = [gw.Id],
                    Associations = [ParseAssociation(gw.Id)]
                };
                if (!string.IsNullOrEmpty(gw.LegacyRuleSetType))
                    legacy.ManagedRuleSets.Add(new ManagedRuleSetInfo
                    {
                        RuleSetType = gw.LegacyRuleSetType,
                        RuleSetVersion = gw.LegacyRuleSetVersion,
                        DisabledRuleCount = gw.LegacyDisabledRuleCount,
                        ExclusionCount = gw.LegacyExclusionCount
                    });
                result.WafPolicies.Add(legacy);
            }

            foreach (var listener in gw.Listeners)
            {
                // Listener-specific policy wins, then gateway-level policy, then legacy config.
                listener.WafPolicyId ??= gw.FirewallPolicyId;
                if (listener.WafPolicyId is null && gw.LegacyWafConfigured && legacy is not null)
                    listener.WafPolicyId = legacy.Id;
            }

            // Make sure a gateway-level policy also lists the gateway as an association (Resource Graph usually has it, but be safe).
            if (gw.FirewallPolicyId is not null)
            {
                var policy = result.WafPolicies.FirstOrDefault(p => p.Id.Equals(gw.FirewallPolicyId, StringComparison.OrdinalIgnoreCase));
                if (policy is not null && !policy.AssociationIds.Any(a => WafRatingService.MatchesResource(a, gw.Id)))
                {
                    policy.AssociationIds.Add(gw.Id);
                    policy.Associations.Add(ParseAssociation(gw.Id));
                }
            }
        }
    }

    // ── Front Door Standard/Premium per-domain coverage ──────────────────────

    private static void LinkProfilesToPolicies(WafScanResult result)
    {
        var profiles = result.FrontDoors.Where(f => f.Kind != FrontDoorKind.Classic).ToList();
        if (profiles.Count == 0) return;

        foreach (var policy in result.WafPolicies.Where(p => p.Kind == WafPolicyKind.FrontDoor))
            foreach (var linkId in policy.AssociationIds)
            {
                var profile = profiles.FirstOrDefault(p => linkId.StartsWith(p.Id + "/", StringComparison.OrdinalIgnoreCase));
                if (profile is not null && !profile.AssociatedPolicyIds.Contains(policy.Id, StringComparer.OrdinalIgnoreCase))
                    profile.AssociatedPolicyIds.Add(policy.Id);
            }
    }

    private async Task ApplyProfileDomainCoverageAsync(
        WafScanResult result, IReadOnlyCollection<string> subscriptionIds, string? tenantId, CancellationToken ct)
    {
        var profiles = result.FrontDoors.Where(f => f.Kind != FrontDoorKind.Classic).ToList();
        if (profiles.Count == 0) return;

        var endpointTasks = profiles.Select(p => ReadProfileEndpointsAsync(p, tenantId, ct)).ToList();
        var securityPolicyTask = _azure.QueryResourceGraphAsync(SecurityPoliciesQuery, subscriptionIds, tenantId, ct);
        var customDomainTask = _azure.QueryResourceGraphAsync(CustomDomainsQuery, subscriptionIds, tenantId, ct);

        List<JsonElement> securityPolicyRows, customDomainRows;
        try
        {
            await Task.WhenAll(securityPolicyTask, customDomainTask);
            securityPolicyRows = securityPolicyTask.Result;
            customDomainRows = customDomainTask.Result;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not read Front Door security policies / custom domains.");
            result.Warnings.Add(
                "Front Door security policies and custom domains could not be read — per-domain WAF coverage cannot be assessed and profiles are rated on their policy association only.");
            await Task.WhenAll(endpointTasks);
            foreach (var profile in profiles) profile.Endpoints.Clear();
            return;
        }

        var endpointOutcomes = await Task.WhenAll(endpointTasks);
        var endpointFailures = endpointOutcomes.Count(ok => !ok);
        if (endpointFailures > 0)
            result.Warnings.Add(
                $"Endpoints could not be listed for {endpointFailures} Front Door profile(s) — their WAF coverage is rated on the domains that could be read.");

        ApplyProfileDomainCoverage(profiles, customDomainRows, securityPolicyRows);
    }

    /// <summary>Pure part of the domain-coverage resolution (testable without Azure).</summary>
    internal static void ApplyProfileDomainCoverage(
        List<FrontDoorInfo> profiles, List<JsonElement> customDomainRows, List<JsonElement> securityPolicyRows)
    {
        foreach (var row in customDomainRows)
        {
            var id = Str(row, "id");
            var profile = profiles.FirstOrDefault(p => id.StartsWith(p.Id + "/", StringComparison.OrdinalIgnoreCase));
            profile?.Endpoints.Add(new WafSurfaceInfo
            {
                Id = id,
                Name = Str(row, "name"),
                HostName = Str(Obj(row, "properties"), "hostName"),
                IsCustomDomain = true
            });
        }

        foreach (var row in securityPolicyRows)
        {
            var id = Str(row, "id");
            var profile = profiles.FirstOrDefault(p => id.StartsWith(p.Id + "/", StringComparison.OrdinalIgnoreCase));
            if (profile is null) continue;

            var parameters = Obj(Obj(row, "properties"), "parameters");
            if (!Str(parameters, "type").Equals("WebApplicationFirewall", StringComparison.OrdinalIgnoreCase)) continue;
            var wafPolicyId = NullIfEmpty(Str(Obj(parameters, "wafPolicy"), "id"));
            if (wafPolicyId is null) continue;

            if (!profile.AssociatedPolicyIds.Contains(wafPolicyId, StringComparer.OrdinalIgnoreCase))
                profile.AssociatedPolicyIds.Add(wafPolicyId);

            // A profile-level security policy covers every domain of the profile.
            if (Bool(parameters, "isProfileLevel") == true)
            {
                foreach (var entry in profile.Endpoints) entry.WafPolicyId ??= wafPolicyId;
                continue;
            }

            foreach (var association in Arr(parameters, "associations"))
                foreach (var domain in Arr(association, "domains"))
                {
                    var domainId = Str(domain, "id");
                    var entry = profile.Endpoints.FirstOrDefault(e => domainId.Equals(e.Id, StringComparison.OrdinalIgnoreCase));
                    if (entry is not null) entry.WafPolicyId ??= wafPolicyId;
                }
        }
    }

    /// <summary>Lists a Standard/Premium profile's endpoints via ARM (they are not in Resource Graph).</summary>
    private async Task<bool> ReadProfileEndpointsAsync(FrontDoorInfo profile, string? tenantId, CancellationToken ct)
    {
        try
        {
            var items = await _azure.GetArmListAsync($"{AzureApi.ArmBase}{profile.Id}/afdEndpoints?api-version=2024-02-01", tenantId, ct);
            foreach (var ep in items)
            {
                var props = Obj(ep, "properties");
                // A disabled endpoint serves no traffic, so it is not attack surface.
                if (Str(props, "enabledState").Equals("Disabled", StringComparison.OrdinalIgnoreCase)) continue;
                profile.Endpoints.Add(new WafSurfaceInfo
                {
                    Id = Str(ep, "id"),
                    Name = Str(ep, "name"),
                    HostName = Str(props, "hostName")
                });
            }
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not list endpoints for Front Door profile {ProfileId}.", profile.Id);
            return false;
        }
    }

    // ── Latest rule set versions ─────────────────────────────────────────────

    private async Task ApplyLatestRuleSetVersionsAsync(WafScanResult result, string subscriptionId, string? tenantId, CancellationToken ct)
    {
        var needsAppGw = result.WafPolicies.Any(p => p.Kind == WafPolicyKind.ApplicationGateway);
        var needsFd = result.WafPolicies.Any(p => p.Kind == WafPolicyKind.FrontDoor);
        var needsCdn = result.WafPolicies.Any(p => p.Kind == WafPolicyKind.Cdn);

        var appGwLatest = needsAppGw
            ? await GetLatestRuleSetVersionsAsync(
                $"{AzureApi.ArmBase}/subscriptions/{subscriptionId}/providers/Microsoft.Network/applicationGatewayAvailableWafRuleSets?api-version=2023-09-01",
                tenantId, "Application Gateway", result.Warnings, ct)
            : new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        var fdLatest = needsFd
            ? await GetLatestRuleSetVersionsAsync(
                $"{AzureApi.ArmBase}/subscriptions/{subscriptionId}/providers/Microsoft.Network/FrontDoorWebApplicationFirewallManagedRuleSets?api-version=2022-05-01",
                tenantId, "Front Door", result.Warnings, ct)
            : new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        var cdnLatest = needsCdn
            ? await GetLatestRuleSetVersionsAsync(
                $"{AzureApi.ArmBase}/subscriptions/{subscriptionId}/providers/Microsoft.Cdn/cdnWebApplicationFirewallManagedRuleSets?api-version=2024-02-01",
                tenantId, "CDN", result.Warnings, ct)
            : new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        ApplyLatestRuleSetVersions(result, appGwLatest, fdLatest, cdnLatest);
    }

    internal static void ApplyLatestRuleSetVersions(WafScanResult result,
        IReadOnlyDictionary<string, string> appGwLatest, IReadOnlyDictionary<string, string> fdLatest, IReadOnlyDictionary<string, string> cdnLatest)
    {
        foreach (var policy in result.WafPolicies)
        {
            var latestMap = policy.Kind switch
            {
                WafPolicyKind.ApplicationGateway => appGwLatest,
                WafPolicyKind.Cdn => cdnLatest,
                _ => fdLatest
            };
            foreach (var ruleSet in policy.ManagedRuleSets)
                if (latestMap.TryGetValue(ruleSet.RuleSetType, out var latest))
                {
                    ruleSet.LatestVersion = latest;
                    ruleSet.IsLatest = CompareVersions(ruleSet.RuleSetVersion, latest) >= 0;
                }
        }
    }

    private async Task<Dictionary<string, string>> GetLatestRuleSetVersionsAsync(
        string url, string? tenantId, string label, List<string> warnings, CancellationToken ct)
    {
        var latest = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (var item in await _azure.GetArmListAsync(url, tenantId, ct))
            {
                var props = Obj(item, "properties");
                var type = Str(props, "ruleSetType");
                var version = Str(props, "ruleSetVersion");
                if (string.IsNullOrEmpty(type) || string.IsNullOrEmpty(version)) continue;
                if (!latest.TryGetValue(type, out var current) || CompareVersions(version, current) > 0)
                    latest[type] = version;
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not retrieve available {Label} WAF rule sets.", label);
            warnings.Add($"Could not retrieve the available {label} rule set versions — 'latest version' checks for {label} policies are skipped.");
        }
        return latest;
    }

    /// <summary>Compares dotted version strings; falls back to ordinal comparison when unparsable.</summary>
    internal static int CompareVersions(string a, string b)
    {
        if (Version.TryParse(Normalize(a), out var va) && Version.TryParse(Normalize(b), out var vb))
            return va.CompareTo(vb);
        return string.Compare(a, b, StringComparison.OrdinalIgnoreCase);

        static string Normalize(string v) => v.Contains('.') ? v : v + ".0";
    }

    // ── Diagnostic settings (WAF logging) ────────────────────────────────────

    private async Task ApplyDiagnosticsAsync(WafScanResult result, string? tenantId, CancellationToken ct)
    {
        var tasks = new List<Task<bool>>();
        foreach (var gw in result.AppGateways)
            tasks.Add(ReadDiagnosticsAsync(gw.Id, tenantId, on => gw.WafLogsEnabled = on, d => gw.LogDestinations = d, ct));
        foreach (var fd in result.FrontDoors)
            tasks.Add(ReadDiagnosticsAsync(fd.Id, tenantId, on => fd.WafLogsEnabled = on, d => fd.LogDestinations = d, ct));
        if (tasks.Count == 0) return;

        var outcomes = await Task.WhenAll(tasks);
        var failures = outcomes.Count(ok => !ok);
        if (failures > 0)
            result.Warnings.Add($"Diagnostic settings could not be read for {failures} resource(s) — their WAF logging status is shown as Unknown.");
    }

    private async Task<bool> ReadDiagnosticsAsync(
        string resourceId, string? tenantId, Action<bool?> setEnabled, Action<List<string>> setDestinations, CancellationToken ct)
    {
        try
        {
            var settings = await _azure.GetArmListAsync(
                $"{AzureApi.ArmBase}{resourceId}/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview", tenantId, ct);
            var (enabled, destinations) = ParseDiagnosticSettings(settings);
            setEnabled(enabled);
            setDestinations(destinations);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not read diagnostic settings for {ResourceId}.", resourceId);
            setEnabled(null);
            return false;
        }
    }

    internal static (bool Enabled, List<string> Destinations) ParseDiagnosticSettings(IEnumerable<JsonElement> settings)
    {
        var enabled = false;
        var destinations = new List<string>();

        foreach (var setting in settings)
        {
            var props = Obj(setting, "properties");
            if (props.ValueKind != JsonValueKind.Object) continue;

            var wafLogOn = false;
            foreach (var log in Arr(props, "logs"))
            {
                if (Bool(log, "enabled") != true) continue;
                var category = Str(log, "category");
                var group = Str(log, "categoryGroup");
                // Matches ApplicationGatewayFirewallLog, FrontdoorWebApplicationFirewallLog and
                // FrontDoorWebApplicationFirewallLog; the "allLogs" category group includes them all.
                if (category.Contains("FirewallLog", StringComparison.OrdinalIgnoreCase) ||
                    group.Equals("allLogs", StringComparison.OrdinalIgnoreCase))
                {
                    wafLogOn = true;
                    break;
                }
            }
            if (!wafLogOn) continue;

            enabled = true;
            AddDestination(destinations, "Log Analytics", Str(props, "workspaceId"));
            AddDestination(destinations, "Storage", Str(props, "storageAccountId"));
            AddDestination(destinations, "Event Hub", FirstNonEmpty(Str(props, "eventHubName"), Str(props, "eventHubAuthorizationRuleId")));
            AddDestination(destinations, "Partner solution", Str(props, "marketplacePartnerId"));
        }
        return (enabled, destinations.Distinct().ToList());

        static void AddDestination(List<string> list, string label, string idOrName)
        {
            if (string.IsNullOrEmpty(idOrName)) return;
            list.Add($"{label}: {LastSegment(idOrName)}");
        }
    }
}
