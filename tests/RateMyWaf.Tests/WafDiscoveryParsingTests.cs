using System.Text.Json;
using RateMyWaf.Models;
using RateMyWaf.Services;
using Xunit;

namespace RateMyWaf.Tests;

/// <summary>Parsing of the raw Azure Resource Graph / ARM JSON shapes into the estate model.</summary>
public class WafDiscoveryParsingTests
{
    private static JsonElement J(string json) => JsonDocument.Parse(json).RootElement.Clone();

    private const string GwId = "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Network/applicationGateways/agw1";
    private const string GwPolicyId = "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/pol1";

    [Fact]
    public void ParseAppGateway_ReadsTierPolicyListenersAndPathRules()
    {
        var row = J($$"""
        {
          "id": "{{GwId}}", "name": "agw1", "type": "microsoft.network/applicationgateways",
          "location": "westeurope", "resourceGroup": "rg", "subscriptionId": "s1",
          "properties": {
            "sku": { "name": "WAF_v2", "tier": "WAF_v2" },
            "firewallPolicy": { "id": "{{GwPolicyId}}" },
            "httpListeners": [
              { "id": "{{GwId}}/httpListeners/https", "name": "https", "properties": { "protocol": "Https", "hostName": "www.contoso.com" } },
              { "id": "{{GwId}}/httpListeners/multi", "name": "multi", "properties": { "protocol": "Https", "hostNames": ["a.contoso.com", "b.contoso.com"], "firewallPolicy": { "id": "{{GwPolicyId}}-listener" } } }
            ],
            "urlPathMaps": [
              { "name": "map", "properties": { "pathRules": [ { "name": "api", "properties": { "firewallPolicy": { "id": "{{GwPolicyId}}-path" } } } ] } }
            ]
          }
        }
        """);

        var gw = WafDiscoveryService.ParseAppGateway(row);

        Assert.Equal("WAF_v2", gw.Tier);
        Assert.True(gw.IsWafTier);
        Assert.Equal(GwPolicyId, gw.FirewallPolicyId);
        Assert.Equal(2, gw.Listeners.Count);
        Assert.Equal("www.contoso.com", gw.Listeners[0].HostName);
        Assert.Equal("HTTPS", gw.Listeners[0].Detail);
        Assert.Null(gw.Listeners[0].WafPolicyId);
        Assert.Equal("a.contoso.com, b.contoso.com", gw.Listeners[1].HostName);
        Assert.Equal(GwPolicyId + "-listener", gw.Listeners[1].WafPolicyId);
        Assert.Single(gw.PathRulePolicyIds);
        Assert.False(gw.LegacyWafPresent);
    }

    [Fact]
    public void ParseAppGateway_ReadsLegacyInlineConfiguration()
    {
        var row = J($$"""
        {
          "id": "{{GwId}}", "name": "agw1", "type": "microsoft.network/applicationgateways", "resourceGroup": "rg", "subscriptionId": "s1",
          "properties": {
            "sku": { "tier": "WAF_v2" },
            "webApplicationFirewallConfiguration": {
              "enabled": true, "firewallMode": "Detection", "ruleSetType": "OWASP", "ruleSetVersion": "3.1",
              "requestBodyCheck": true, "maxRequestBodySizeInKb": 128, "fileUploadLimitInMb": 100,
              "disabledRuleGroups": [ { "ruleGroupName": "REQUEST-942-APPLICATION-ATTACK-SQLI", "rules": [942430, 942440, 942450] }, { "ruleGroupName": "REQUEST-920-PROTOCOL-ENFORCEMENT" } ],
              "exclusions": [ { "matchVariable": "RequestHeaderNames", "selector": "x-trace" } ]
            }
          }
        }
        """);

        var gw = WafDiscoveryService.ParseAppGateway(row);

        Assert.True(gw.LegacyWafPresent);
        Assert.True(gw.LegacyWafConfigured);
        Assert.Equal("Detection", gw.LegacyWafMode);
        Assert.Equal("OWASP", gw.LegacyRuleSetType);
        Assert.Equal("3.1", gw.LegacyRuleSetVersion);
        Assert.Equal(5, gw.LegacyDisabledRuleCount);       // 3 listed + 2 for a whole disabled group
        Assert.Equal(1, gw.LegacyExclusionCount);
        Assert.True(gw.LegacyRequestBodyCheck);
        Assert.Equal(128, gw.LegacyMaxRequestBodySizeKb);
    }

    [Fact]
    public void ApplyGatewayCoverage_SynthesisesLegacyPolicy_AndCoversListeners()
    {
        var gw = new AppGatewayInfo
        {
            Id = GwId, Name = "agw1", Tier = "WAF_v2",
            LegacyWafPresent = true, LegacyWafConfigured = true, LegacyWafMode = "Prevention",
            LegacyRuleSetType = "OWASP", LegacyRuleSetVersion = "3.2", LegacyRequestBodyCheck = true,
            Listeners = [new WafSurfaceInfo { Id = GwId + "/httpListeners/a", Name = "a" }, new WafSurfaceInfo { Id = GwId + "/httpListeners/b", Name = "b" }]
        };
        var result = new WafScanResult { Flow = WafFlowKind.ApplicationGateway, AppGateways = [gw] };

        WafDiscoveryService.ApplyGatewayCoverage(result);

        var legacy = Assert.Single(result.WafPolicies);
        Assert.True(legacy.IsLegacyInline);
        Assert.Equal(gw.LegacyPolicyId, legacy.Id);
        Assert.Equal("Prevention", legacy.Mode);
        Assert.Equal("Enabled", legacy.EnabledState);
        Assert.Equal("Enabled", legacy.RequestBodyCheck);
        Assert.Single(legacy.ManagedRuleSets);
        Assert.All(gw.Listeners, l => Assert.Equal(legacy.Id, l.WafPolicyId));
        Assert.True(gw.HasWaf);
        Assert.Equal("agw1", legacy.Associations.Single().TargetName);
    }

    [Fact]
    public void ApplyGatewayCoverage_GatewayPolicyCoversAllListeners_ListenerPolicyWins()
    {
        var gw = new AppGatewayInfo
        {
            Id = GwId, Name = "agw1", Tier = "WAF_v2", FirewallPolicyId = GwPolicyId,
            Listeners = [new WafSurfaceInfo { Id = GwId + "/httpListeners/a" }, new WafSurfaceInfo { Id = GwId + "/httpListeners/b", WafPolicyId = "other" }]
        };
        var policy = new WafPolicyInfo { Id = GwPolicyId, Name = "pol1", Kind = WafPolicyKind.ApplicationGateway };
        var result = new WafScanResult { AppGateways = [gw], WafPolicies = [policy] };

        WafDiscoveryService.ApplyGatewayCoverage(result);

        Assert.Equal(GwPolicyId, gw.Listeners[0].WafPolicyId);
        Assert.Equal("other", gw.Listeners[1].WafPolicyId);
        Assert.Contains(GwId, policy.AssociationIds);
        Assert.Single(result.WafPolicies); // no synthetic policy when a real one is attached
    }

    [Fact]
    public void ParseClassicFrontDoor_ReadsEndpointsAndPolicyLinks()
    {
        const string fdId = "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Network/frontdoors/fd1";
        var row = J($$"""
        {
          "id": "{{fdId}}", "name": "fd1", "type": "microsoft.network/frontdoors", "resourceGroup": "rg", "subscriptionId": "s1",
          "properties": { "frontendEndpoints": [
            { "id": "{{fdId}}/frontendEndpoints/ep1", "name": "ep1", "properties": { "hostName": "fd1.azurefd.net", "webApplicationFirewallPolicyLink": { "id": "/pol/1" } } },
            { "id": "{{fdId}}/frontendEndpoints/ep2", "name": "ep2", "properties": { "hostName": "www.contoso.com" } }
          ] }
        }
        """);

        var fd = WafDiscoveryService.ParseClassicFrontDoor(row);

        Assert.Equal(FrontDoorKind.Classic, fd.Kind);
        Assert.Equal(2, fd.Endpoints.Count);
        Assert.Equal("/pol/1", fd.Endpoints[0].WafPolicyId);
        Assert.Null(fd.Endpoints[1].WafPolicyId);
        Assert.True(fd.HasWafAssociation);
    }

    [Fact]
    public void ParseFrontDoorProfile_DetectsPremiumAndStandard()
    {
        var premium = WafDiscoveryService.ParseFrontDoorProfile(J("""{ "id": "/p", "name": "p", "sku": { "name": "Premium_AzureFrontDoor" } }"""));
        var standard = WafDiscoveryService.ParseFrontDoorProfile(J("""{ "id": "/s", "name": "s", "sku": { "name": "Standard_AzureFrontDoor" } }"""));
        Assert.Equal(FrontDoorKind.Premium, premium.Kind);
        Assert.Equal(FrontDoorKind.Standard, standard.Kind);
    }

    [Fact]
    public void ParseWafPolicy_FrontDoorShape()
    {
        var row = J("""
        {
          "id": "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Network/frontdoorwebapplicationfirewallpolicies/pol1",
          "name": "pol1", "type": "microsoft.network/frontdoorwebapplicationfirewallpolicies", "resourceGroup": "rg", "subscriptionId": "s1",
          "sku": { "name": "Premium_AzureFrontDoor" },
          "properties": {
            "policySettings": { "enabledState": "Enabled", "mode": "Prevention", "requestBodyCheck": "Enabled", "redirectUrl": "https://x", "customBlockResponseStatusCode": 403 },
            "customRules": { "rules": [
              { "name": "rl", "priority": 2, "ruleType": "RateLimitRule", "action": "Block", "enabledState": "Enabled", "rateLimitThreshold": 100, "rateLimitDurationInMinutes": 1,
                "matchConditions": [ { "matchVariable": "RequestUri", "operator": "Contains", "matchValue": ["/login"] } ] },
              { "name": "geo", "priority": 1, "ruleType": "MatchRule", "action": "Block",
                "matchConditions": [ { "matchVariable": "SocketAddr", "operator": "GeoMatch", "negateCondition": true, "matchValue": ["NL", "BE", "DE", "FR", "GB", "IE"] } ] }
            ] },
            "managedRules": { "managedRuleSets": [
              { "ruleSetType": "Microsoft_DefaultRuleSet", "ruleSetVersion": "2.1",
                "exclusions": [ { "matchVariable": "RequestHeaderNames", "selector": "x" } ],
                "ruleGroupOverrides": [ { "ruleGroupName": "SQLI", "rules": [ { "ruleId": "942430", "enabledState": "Disabled" }, { "ruleId": "942440", "enabledState": "Enabled", "action": "Log" } ] } ] },
              { "ruleSetType": "Microsoft_BotManagerRuleSet", "ruleSetVersion": "1.1" }
            ] },
            "securityPolicyLinks": [ { "id": "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Cdn/profiles/fd1/securitypolicies/sp1" } ]
          }
        }
        """);

        var p = WafDiscoveryService.ParseWafPolicy(row);

        Assert.Equal(WafPolicyKind.FrontDoor, p.Kind);
        Assert.Equal("Enabled", p.EnabledState);
        Assert.Equal("Prevention", p.Mode);
        Assert.Equal("Enabled", p.RequestBodyCheck);
        Assert.Equal(403, p.CustomBlockResponseStatusCode);
        Assert.Equal(2, p.CustomRules.Count);
        Assert.Equal("geo", p.CustomRules[0].Name); // sorted by priority
        Assert.Equal("SocketAddr NOT GeoMatch [NL, BE, DE, FR, +2 more]", p.CustomRules[0].Conditions[0]);
        Assert.Equal("1 min", p.CustomRules[1].RateLimitDuration);
        Assert.Equal(2, p.ManagedRuleSets.Count);
        Assert.Equal(1, p.ManagedRuleSets[0].DisabledRuleCount);
        Assert.Equal(1, p.ManagedRuleSets[0].ActionOverrideCount);
        Assert.Equal(1, p.ManagedRuleSets[0].ExclusionCount);
        Assert.Equal("SQLI: 1 rule disabled, 1 action override", p.ManagedRuleSets[0].GroupOverrideSummaries[0]);
        var assoc = Assert.Single(p.Associations);
        Assert.Equal("Front Door", assoc.TargetType);
        Assert.Equal("fd1 — security policy sp1", assoc.Display);
    }

    [Fact]
    public void ParseWafPolicy_AppGatewayShape()
    {
        var row = J($$"""
        {
          "id": "{{GwPolicyId}}", "name": "pol1", "type": "microsoft.network/applicationgatewaywebapplicationfirewallpolicies", "resourceGroup": "rg", "subscriptionId": "s1",
          "properties": {
            "policySettings": { "state": "Enabled", "mode": "Detection", "requestBodyCheck": true, "maxRequestBodySizeInKb": 128, "fileUploadLimitInMb": 100 },
            "customRules": [
              { "name": "block", "priority": 10, "ruleType": "MatchRule", "action": "Block", "state": "Disabled",
                "matchConditions": [ { "matchVariables": [ { "variableName": "RemoteAddr" } ], "operator": "IPMatch", "negationConditon": false, "matchValues": ["1.2.3.4"] } ] },
              { "name": "rl", "priority": 20, "ruleType": "RateLimitRule", "action": "Block", "rateLimitThreshold": 50, "rateLimitDuration": "OneMin", "matchConditions": [] }
            ],
            "managedRules": {
              "exclusions": [ { "matchVariable": "RequestCookieNames", "selectorMatchOperator": "Equals", "selector": "s" } ],
              "managedRuleSets": [ { "ruleSetType": "OWASP", "ruleSetVersion": "3.2", "ruleGroupOverrides": [ { "ruleGroupName": "REQUEST-942-APPLICATION-ATTACK-SQLI", "rules": [ { "ruleId": "942100", "state": "Disabled" } ] } ] } ]
            },
            "applicationGateways": [ { "id": "{{GwId}}" } ],
            "httpListeners": [ { "id": "{{GwId}}/httpListeners/https" } ]
          }
        }
        """);

        var p = WafDiscoveryService.ParseWafPolicy(row);

        Assert.Equal(WafPolicyKind.ApplicationGateway, p.Kind);
        Assert.Equal("Enabled", p.EnabledState);
        Assert.Equal("Detection", p.Mode);
        Assert.Equal("Enabled", p.RequestBodyCheck);
        Assert.Equal(1, p.ExclusionCount);
        Assert.Equal("Disabled", p.CustomRules[0].EnabledState);
        Assert.Equal("RemoteAddr IPMatch [1.2.3.4]", p.CustomRules[0].Conditions[0]);
        Assert.Equal("OneMin", p.CustomRules[1].RateLimitDuration);
        Assert.Equal("Enabled", p.CustomRules[1].EnabledState);
        Assert.Equal(1, p.ManagedRuleSets[0].DisabledRuleCount);
        Assert.Equal(2, p.Associations.Count);
        Assert.Equal("agw1 — listener https", p.Associations[1].Display);
    }

    [Fact]
    public void ApplyProfileDomainCoverage_MarksAssociatedDomains_AndProfileLevelPolicies()
    {
        const string profileId = "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Cdn/profiles/fd1";
        const string policyId = "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Network/frontdoorwebapplicationfirewallpolicies/pol1";
        var profile = new FrontDoorInfo
        {
            Id = profileId, Name = "fd1", Kind = FrontDoorKind.Premium,
            Endpoints = [new WafSurfaceInfo { Id = profileId + "/afdendpoints/ep1", Name = "ep1", HostName = "ep1.azurefd.net" }]
        };
        var customDomains = new List<JsonElement>
        {
            J($$"""{ "id": "{{profileId}}/customdomains/www", "name": "www", "properties": { "hostName": "www.contoso.com" } }"""),
            J($$"""{ "id": "{{profileId}}/customdomains/shop", "name": "shop", "properties": { "hostName": "shop.contoso.com" } }"""),
        };
        var securityPolicies = new List<JsonElement>
        {
            J($$"""
            { "id": "{{profileId}}/securitypolicies/sp1", "name": "sp1", "properties": { "parameters": { "type": "WebApplicationFirewall", "wafPolicy": { "id": "{{policyId}}" },
              "associations": [ { "domains": [ { "id": "{{profileId}}/afdendpoints/ep1" }, { "id": "{{profileId}}/customdomains/www" } ] } ] } } }
            """),
        };

        WafDiscoveryService.ApplyProfileDomainCoverage([profile], customDomains, securityPolicies);

        Assert.Equal(3, profile.Endpoints.Count);
        Assert.Equal(policyId, profile.Endpoints.Single(e => e.Name == "ep1").WafPolicyId);
        Assert.Equal(policyId, profile.Endpoints.Single(e => e.Name == "www").WafPolicyId);
        Assert.Null(profile.Endpoints.Single(e => e.Name == "shop").WafPolicyId);
        Assert.Contains(policyId, profile.AssociatedPolicyIds);

        // A profile-level security policy covers everything.
        var profileLevel = new List<JsonElement>
        {
            J($$"""{ "id": "{{profileId}}/securitypolicies/sp2", "name": "sp2", "properties": { "parameters": { "type": "WebApplicationFirewall", "isProfileLevel": true, "wafPolicy": { "id": "{{policyId}}-all" } } } }"""),
        };
        WafDiscoveryService.ApplyProfileDomainCoverage([profile], [], profileLevel);
        Assert.Equal(policyId + "-all", profile.Endpoints.Single(e => e.Name == "shop").WafPolicyId);
        Assert.Equal(policyId, profile.Endpoints.Single(e => e.Name == "www").WafPolicyId); // first association wins
    }

    [Fact]
    public void ParseDiagnosticSettings_DetectsFirewallLogAndDestinations()
    {
        var settings = new List<JsonElement>
        {
            J("""{ "name": "metrics-only", "properties": { "logs": [ { "category": "ApplicationGatewayAccessLog", "enabled": true } ], "workspaceId": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/law-a" } }"""),
            J("""{ "name": "waf", "properties": { "logs": [ { "category": "ApplicationGatewayFirewallLog", "enabled": true } ], "workspaceId": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/law-b", "storageAccountId": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/stlogs" } }"""),
            J("""{ "name": "all", "properties": { "logs": [ { "categoryGroup": "allLogs", "enabled": true } ], "eventHubName": "hub1" } }"""),
        };

        var (enabled, destinations, workspaceIds) = WafDiscoveryService.ParseDiagnosticSettings(settings);

        Assert.True(enabled);
        Assert.Equal(["Log Analytics: law-b", "Storage: stlogs", "Event Hub: hub1"], destinations);
        // Only the workspace that actually receives the firewall log is offered for querying.
        Assert.Equal(["/subscriptions/s/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/law-b"], workspaceIds);
    }

    [Fact]
    public void ParseDiagnosticSettings_NoFirewallLog_IsDisabled()
    {
        var settings = new List<JsonElement>
        {
            J("""{ "properties": { "logs": [ { "category": "FrontDoorWebApplicationFirewallLog", "enabled": false } ], "workspaceId": "/w/law" } }"""),
        };
        var (enabled, destinations, workspaceIds) = WafDiscoveryService.ParseDiagnosticSettings(settings);
        Assert.False(enabled);
        Assert.Empty(destinations);
        Assert.Empty(workspaceIds);
    }

    [Fact]
    public void ApplyLatestRuleSetVersions_FlagsOutdatedPerPolicyKind()
    {
        var fdPolicy = new WafPolicyInfo { Kind = WafPolicyKind.FrontDoor, ManagedRuleSets = [new() { RuleSetType = "Microsoft_DefaultRuleSet", RuleSetVersion = "2.0" }] };
        var gwPolicy = new WafPolicyInfo { Kind = WafPolicyKind.ApplicationGateway, ManagedRuleSets = [new() { RuleSetType = "OWASP", RuleSetVersion = "3.2" }, new() { RuleSetType = "Unknown", RuleSetVersion = "1" }] };
        var result = new WafScanResult { WafPolicies = [fdPolicy, gwPolicy] };

        WafDiscoveryService.ApplyLatestRuleSetVersions(result,
            new Dictionary<string, string> { ["OWASP"] = "3.2" },
            new Dictionary<string, string> { ["Microsoft_DefaultRuleSet"] = "2.1" },
            new Dictionary<string, string>());

        Assert.False(fdPolicy.ManagedRuleSets[0].IsLatest);
        Assert.Equal("2.1", fdPolicy.ManagedRuleSets[0].LatestVersion);
        Assert.True(gwPolicy.ManagedRuleSets[0].IsLatest);
        Assert.Null(gwPolicy.ManagedRuleSets[1].IsLatest);
    }

    [Theory]
    [InlineData("2.1", "2.1", 0)]
    [InlineData("2.0", "2.1", -1)]
    [InlineData("3.2", "3.1", 1)]
    [InlineData("1", "1.0", 0)]
    [InlineData("1.1", "1", 1)]
    public void CompareVersions_HandlesDottedAndBareVersions(string a, string b, int expectedSign) =>
        Assert.Equal(expectedSign, Math.Sign(WafDiscoveryService.CompareVersions(a, b)));
}
