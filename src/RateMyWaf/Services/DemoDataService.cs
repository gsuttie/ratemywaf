using RateMyWaf.Models;

namespace RateMyWaf.Services;

/// <summary>
/// A realistic sample estate for each flow so the app can be explored (and tested end to end)
/// without Azure credentials. Every grade band from A to F appears somewhere.
/// </summary>
public static class DemoDataService
{
    public const string TenantId = "00000000-0000-0000-0000-00000000demo";
    public const string SubProd = "11111111-1111-1111-1111-111111111111";
    public const string SubShared = "22222222-2222-2222-2222-222222222222";

    public static List<SubscriptionInfo> Subscriptions() =>
    [
        new() { SubscriptionId = SubProd, DisplayName = "Contoso Production", State = "Enabled", TenantId = TenantId },
        new() { SubscriptionId = SubShared, DisplayName = "Contoso Shared Services", State = "Enabled", TenantId = TenantId },
    ];

    public static Dictionary<string, TenantInfo> Tenants() => new(StringComparer.OrdinalIgnoreCase)
    {
        [TenantId] = new TenantInfo { TenantId = TenantId, DisplayName = "Contoso Ltd (demo)", DefaultDomain = "contoso.onmicrosoft.com" }
    };

    public static Dictionary<string, WafSubscriptionSummary> Summaries() => new(StringComparer.OrdinalIgnoreCase)
    {
        [SubProd] = new() { SubscriptionId = SubProd, FrontDoorCount = 2, FrontDoorPolicyCount = 2, AppGatewayCount = 2, AppGatewayPolicyCount = 1 },
        [SubShared] = new() { SubscriptionId = SubShared, FrontDoorCount = 1, FrontDoorPolicyCount = 1, AppGatewayCount = 1, AppGatewayPolicyCount = 1 },
    };

    private static string Rg(string sub, string rg) => $"/subscriptions/{sub}/resourceGroups/{rg}/providers";

    public static WafScanResult Scan(WafFlowKind flow, IReadOnlyCollection<string> subscriptionIds)
    {
        var result = flow == WafFlowKind.FrontDoor ? FrontDoorEstate() : AppGatewayEstate();
        result.SubscriptionIds = subscriptionIds.ToList();
        var subs = new HashSet<string>(subscriptionIds, StringComparer.OrdinalIgnoreCase);
        result.FrontDoors = result.FrontDoors.Where(f => subs.Contains(f.SubscriptionId)).ToList();
        result.AppGateways = result.AppGateways.Where(g => subs.Contains(g.SubscriptionId)).ToList();
        result.WafPolicies = result.WafPolicies.Where(p => subs.Contains(p.SubscriptionId)).ToList();
        WafDiscoveryService.Finalize(result);
        return result;
    }

    // ── Front Doors ──────────────────────────────────────────────────────────

    public static WafScanResult FrontDoorEstate()
    {
        var result = new WafScanResult { Flow = WafFlowKind.FrontDoor };

        // 1. Premium profile, everything right → A
        var prodId = $"{Rg(SubProd, "rg-edge-prod")}/Microsoft.Cdn/profiles/afd-contoso-prod";
        var prodPolicyId = $"{Rg(SubProd, "rg-edge-prod")}/Microsoft.Network/frontdoorwebapplicationfirewallpolicies/wafcontosoprod";
        var prod = new FrontDoorInfo
        {
            Id = prodId, Name = "afd-contoso-prod", ResourceGroup = "rg-edge-prod", SubscriptionId = SubProd,
            Kind = FrontDoorKind.Premium, SkuName = "Premium_AzureFrontDoor",
            AssociatedPolicyIds = [prodPolicyId],
            Endpoints =
            [
                new() { Id = prodId + "/afdendpoints/www", Name = "www", HostName = "www-contoso-prod.z01.azurefd.net", WafPolicyId = prodPolicyId },
                new() { Id = prodId + "/customdomains/www-contoso-com", Name = "www-contoso-com", HostName = "www.contoso.com", IsCustomDomain = true, WafPolicyId = prodPolicyId },
                new() { Id = prodId + "/customdomains/shop-contoso-com", Name = "shop-contoso-com", HostName = "shop.contoso.com", IsCustomDomain = true, WafPolicyId = prodPolicyId },
            ],
            WafLogsEnabled = true, LogDestinations = ["Log Analytics: law-contoso-prod"]
        };
        result.FrontDoors.Add(prod);
        result.WafPolicies.Add(new WafPolicyInfo
        {
            Id = prodPolicyId, Name = "wafcontosoprod", ResourceGroup = "rg-edge-prod", SubscriptionId = SubProd,
            Kind = WafPolicyKind.FrontDoor, SkuName = "Premium_AzureFrontDoor", EnabledState = "Enabled", Mode = "Prevention",
            RequestBodyCheck = "Enabled", MaxRequestBodySizeKb = 128, FileUploadLimitMb = 100,
            ManagedRuleSets =
            [
                new() { RuleSetType = "Microsoft_DefaultRuleSet", RuleSetVersion = "2.1", LatestVersion = "2.1", IsLatest = true, ExclusionCount = 1,
                        GroupOverrideSummaries = ["SQLI: 1 action override"], ActionOverrideCount = 1 },
                new() { RuleSetType = "Microsoft_BotManagerRuleSet", RuleSetVersion = "1.1", LatestVersion = "1.1", IsLatest = true },
            ],
            CustomRules =
            [
                new() { Name = "RateLimitLogin", Priority = 10, RuleType = "RateLimitRule", Action = "Block", EnabledState = "Enabled", RateLimitThreshold = 300, RateLimitDuration = "1 min", Conditions = ["RequestUri Contains [/account/login]"] },
                new() { Name = "GeoBlock", Priority = 20, RuleType = "MatchRule", Action = "Block", EnabledState = "Enabled", Conditions = ["SocketAddr GeoMatch [KP, IR, SY]"] },
            ],
            AssociationIds = [prodId + "/securitypolicies/waf-security-policy"],
            Associations = [WafDiscoveryService.ParseAssociation(prodId + "/securitypolicies/waf-security-policy")]
        });

        // 2. Standard profile, detection mode, custom rules only, one custom domain uncovered → D
        var mktId = $"{Rg(SubProd, "rg-edge-prod")}/Microsoft.Cdn/profiles/afd-contoso-marketing";
        var mktPolicyId = $"{Rg(SubProd, "rg-edge-prod")}/Microsoft.Network/frontdoorwebapplicationfirewallpolicies/wafmarketing";
        result.FrontDoors.Add(new FrontDoorInfo
        {
            Id = mktId, Name = "afd-contoso-marketing", ResourceGroup = "rg-edge-prod", SubscriptionId = SubProd,
            Kind = FrontDoorKind.Standard, SkuName = "Standard_AzureFrontDoor",
            AssociatedPolicyIds = [mktPolicyId],
            Endpoints =
            [
                new() { Id = mktId + "/afdendpoints/campaigns", Name = "campaigns", HostName = "campaigns-contoso.z01.azurefd.net", WafPolicyId = mktPolicyId },
                new() { Id = mktId + "/customdomains/promo-contoso-com", Name = "promo-contoso-com", HostName = "promo.contoso.com", IsCustomDomain = true, WafPolicyId = mktPolicyId },
                new() { Id = mktId + "/customdomains/events-contoso-com", Name = "events-contoso-com", HostName = "events.contoso.com", IsCustomDomain = true },
            ],
            WafLogsEnabled = true, LogDestinations = ["Storage: stcontosologs"]
        });
        result.WafPolicies.Add(new WafPolicyInfo
        {
            Id = mktPolicyId, Name = "wafmarketing", ResourceGroup = "rg-edge-prod", SubscriptionId = SubProd,
            Kind = WafPolicyKind.FrontDoor, SkuName = "Standard_AzureFrontDoor", EnabledState = "Enabled", Mode = "Detection",
            RequestBodyCheck = "Enabled",
            CustomRules =
            [
                new() { Name = "BlockBadAgents", Priority = 100, RuleType = "MatchRule", Action = "Log", EnabledState = "Enabled", Conditions = ["RequestHeader.User-Agent Contains [sqlmap, nikto]"] },
            ],
            AssociationIds = [mktId + "/securitypolicies/mkt-waf"],
            Associations = [WafDiscoveryService.ParseAssociation(mktId + "/securitypolicies/mkt-waf")]
        });

        // 3. Classic Front Door, outdated DRS, logging off, one endpoint unprotected → D-ish, plus disabled rules
        var legacyId = $"{Rg(SubShared, "rg-shared-edge")}/Microsoft.Network/frontdoors/fd-contoso-legacy";
        var legacyPolicyId = $"{Rg(SubShared, "rg-shared-edge")}/Microsoft.Network/frontdoorwebapplicationfirewallpolicies/waflegacy";
        result.FrontDoors.Add(new FrontDoorInfo
        {
            Id = legacyId, Name = "fd-contoso-legacy", ResourceGroup = "rg-shared-edge", SubscriptionId = SubShared,
            Kind = FrontDoorKind.Classic, SkuName = "Classic",
            Endpoints =
            [
                new() { Id = legacyId + "/frontendendpoints/fd-contoso-legacy-azurefd-net", Name = "fd-contoso-legacy-azurefd-net", HostName = "fd-contoso-legacy.azurefd.net", WafPolicyId = legacyPolicyId },
                new() { Id = legacyId + "/frontendendpoints/intranet", Name = "intranet", HostName = "intranet.contoso.com" },
            ],
            WafLogsEnabled = false, LogDestinations = []
        });
        result.WafPolicies.Add(new WafPolicyInfo
        {
            Id = legacyPolicyId, Name = "waflegacy", ResourceGroup = "rg-shared-edge", SubscriptionId = SubShared,
            Kind = WafPolicyKind.FrontDoor, SkuName = "Classic_AzureFrontDoor", EnabledState = "Enabled", Mode = "Prevention",
            RequestBodyCheck = "Disabled",
            ManagedRuleSets =
            [
                new() { RuleSetType = "Microsoft_DefaultRuleSet", RuleSetVersion = "1.1", LatestVersion = "2.1", IsLatest = false, DisabledRuleCount = 7, ExclusionCount = 4,
                        GroupOverrideSummaries = ["SQLI: 4 rules disabled", "XSS: 3 rules disabled"] },
            ],
            AssociationIds = [legacyId + "/frontendendpoints/fd-contoso-legacy-azurefd-net"],
            Associations = [WafDiscoveryService.ParseAssociation(legacyId + "/frontendendpoints/fd-contoso-legacy-azurefd-net")]
        });

        // 4. An orphaned policy
        var orphanId = $"{Rg(SubShared, "rg-shared-edge")}/Microsoft.Network/frontdoorwebapplicationfirewallpolicies/wafunused";
        result.WafPolicies.Add(new WafPolicyInfo
        {
            Id = orphanId, Name = "wafunused", ResourceGroup = "rg-shared-edge", SubscriptionId = SubShared,
            Kind = WafPolicyKind.FrontDoor, SkuName = "Standard_AzureFrontDoor", EnabledState = "Disabled", Mode = "Detection"
        });

        return result;
    }

    // ── Application Gateways ─────────────────────────────────────────────────

    public static WafScanResult AppGatewayEstate()
    {
        var result = new WafScanResult { Flow = WafFlowKind.ApplicationGateway };

        // 1. WAF_v2 with a good policy but an outdated rule set and no bot manager → B
        var prodId = $"{Rg(SubProd, "rg-app-prod")}/Microsoft.Network/applicationGateways/agw-contoso-prod";
        var prodPolicyId = $"{Rg(SubProd, "rg-app-prod")}/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/agwwaf-prod";
        result.AppGateways.Add(new AppGatewayInfo
        {
            Id = prodId, Name = "agw-contoso-prod", ResourceGroup = "rg-app-prod", SubscriptionId = SubProd, Location = "westeurope",
            Tier = "WAF_v2", FirewallPolicyId = prodPolicyId,
            Listeners =
            [
                new() { Id = prodId + "/httpListeners/https-portal", Name = "https-portal", HostName = "portal.contoso.com", Detail = "HTTPS" },
                new() { Id = prodId + "/httpListeners/https-api", Name = "https-api", HostName = "api.contoso.com", Detail = "HTTPS" },
                new() { Id = prodId + "/httpListeners/http-redirect", Name = "http-redirect", HostName = "portal.contoso.com", Detail = "HTTP" },
            ],
            WafLogsEnabled = true, LogDestinations = ["Log Analytics: law-contoso-prod"]
        });
        result.WafPolicies.Add(new WafPolicyInfo
        {
            Id = prodPolicyId, Name = "agwwaf-prod", ResourceGroup = "rg-app-prod", SubscriptionId = SubProd,
            Kind = WafPolicyKind.ApplicationGateway, EnabledState = "Enabled", Mode = "Prevention",
            RequestBodyCheck = "Enabled", MaxRequestBodySizeKb = 128, FileUploadLimitMb = 100, ExclusionCount = 2,
            ManagedRuleSets =
            [
                new() { RuleSetType = "OWASP", RuleSetVersion = "3.1", LatestVersion = "3.2", IsLatest = false, DisabledRuleCount = 2,
                        GroupOverrideSummaries = ["REQUEST-942-APPLICATION-ATTACK-SQLI: 2 rules disabled"] },
            ],
            CustomRules =
            [
                new() { Name = "AllowOffice", Priority = 1, RuleType = "MatchRule", Action = "Allow", EnabledState = "Enabled", Conditions = ["RemoteAddr IPMatch [203.0.113.0/24]"] },
                new() { Name = "RateLimitApi", Priority = 5, RuleType = "RateLimitRule", Action = "Block", EnabledState = "Enabled", RateLimitThreshold = 500, RateLimitDuration = "OneMin", Conditions = ["RequestUri Contains [/api/]"] },
            ],
            AssociationIds = [prodId],
            Associations = [WafDiscoveryService.ParseAssociation(prodId)]
        });

        // 2. Standard_v2, no WAF possible → F
        var intranetId = $"{Rg(SubProd, "rg-app-prod")}/Microsoft.Network/applicationGateways/agw-contoso-intranet";
        result.AppGateways.Add(new AppGatewayInfo
        {
            Id = intranetId, Name = "agw-contoso-intranet", ResourceGroup = "rg-app-prod", SubscriptionId = SubProd, Location = "westeurope",
            Tier = "Standard_v2",
            Listeners = [new() { Id = intranetId + "/httpListeners/https-intranet", Name = "https-intranet", HostName = "intranet.contoso.com", Detail = "HTTPS" }],
            WafLogsEnabled = false
        });

        // 3. WAF_v2 with legacy inline config in Detection mode, logging to storage only → C
        var legacyId = $"{Rg(SubShared, "rg-shared-app")}/Microsoft.Network/applicationGateways/agw-contoso-legacy";
        result.AppGateways.Add(new AppGatewayInfo
        {
            Id = legacyId, Name = "agw-contoso-legacy", ResourceGroup = "rg-shared-app", SubscriptionId = SubShared, Location = "northeurope",
            Tier = "WAF_v2",
            LegacyWafPresent = true, LegacyWafConfigured = true, LegacyWafMode = "Detection",
            LegacyRuleSetType = "OWASP", LegacyRuleSetVersion = "3.0", LegacyDisabledRuleCount = 3, LegacyExclusionCount = 1,
            LegacyRequestBodyCheck = true, LegacyMaxRequestBodySizeKb = 128, LegacyFileUploadLimitMb = 100,
            Listeners =
            [
                new() { Id = legacyId + "/httpListeners/https-hr", Name = "https-hr", HostName = "hr.contoso.com", Detail = "HTTPS" },
                new() { Id = legacyId + "/httpListeners/https-finance", Name = "https-finance", HostName = "finance.contoso.com", Detail = "HTTPS" },
            ],
            WafLogsEnabled = true, LogDestinations = ["Storage: stcontosologs"]
        });

        // 4. A shared-services policy, Detection mode, attached to nothing
        var sharedPolicyId = $"{Rg(SubShared, "rg-shared-app")}/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/agwwaf-shared";
        result.WafPolicies.Add(new WafPolicyInfo
        {
            Id = sharedPolicyId, Name = "agwwaf-shared", ResourceGroup = "rg-shared-app", SubscriptionId = SubShared,
            Kind = WafPolicyKind.ApplicationGateway, EnabledState = "Enabled", Mode = "Detection", RequestBodyCheck = "Enabled",
            ManagedRuleSets =
            [
                new() { RuleSetType = "Microsoft_DefaultRuleSet", RuleSetVersion = "2.1", LatestVersion = "2.1", IsLatest = true },
                new() { RuleSetType = "Microsoft_BotManagerRuleSet", RuleSetVersion = "1.0", LatestVersion = "1.1", IsLatest = false },
            ]
        });

        WafDiscoveryService.ApplyGatewayCoverage(result);
        // Legacy synthetic policy gets its latest-version check like the live scan would.
        WafDiscoveryService.ApplyLatestRuleSetVersions(result,
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["OWASP"] = "3.2", ["Microsoft_DefaultRuleSet"] = "2.1", ["Microsoft_BotManagerRuleSet"] = "1.1"
            },
            new Dictionary<string, string>(), new Dictionary<string, string>());
        return result;
    }

    // ── Log analysis ─────────────────────────────────────────────────────────

    public static WafLogAnalysis LogAnalysis(WafFlowKind flow, string targetId, string targetName, IReadOnlyCollection<WafPolicyInfo> policies, string timeRange)
    {
        var policyName = policies.FirstOrDefault()?.Name ?? "";
        var mode = policies.FirstOrDefault()?.Mode ?? "Prevention";
        var fd = flow == WafFlowKind.FrontDoor;

        var analysis = new WafLogAnalysis
        {
            Flow = flow, TargetId = targetId, TargetName = targetName,
            PolicyNames = policies.Select(p => p.Name).ToList(),
            TimeRangeKey = timeRange, TimeRangeLabel = WafLogAnalysisService.LabelFor(timeRange).ToLowerInvariant()
        };

        var activities = new List<WafRuleActivity>
        {
            new()
            {
                RuleName = fd ? "Microsoft_DefaultRuleSet-2.1-SQLI-942100" : "942100", PolicyName = policyName,
                Count = 1834, Blocked = 1834, DistinctIps = 212, DistinctUris = 87,
                SampleIps = ["198.51.100.23", "203.0.113.77", "192.0.2.140", "198.51.100.9", "203.0.113.5"],
                SampleUris = ["/wp-login.php", "/.env", "/index.php?id=1%20union%20select%201,2,3", "/phpmyadmin/", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"],
                SampleMatchVariable = "QueryParamValue:id", SampleMatchData = "1 union select 1,2,3", SampleMessage = "SQL Injection Attack Detected via libinjection"
            },
            new()
            {
                RuleName = fd ? "Microsoft_DefaultRuleSet-2.1-SQLI-942430" : "942430", PolicyName = policyName,
                Count = 412, Blocked = mode == "Prevention" ? 412 : 0, Logged = mode == "Prevention" ? 0 : 412, DistinctIps = 2, DistinctUris = 1,
                SampleIps = ["10.20.30.40", "10.20.30.41"], SampleUris = ["/api/orders/search"],
                SampleMatchVariable = "CookieValue:.AspNetCore.Session", SampleMatchData = "CfDJ8N+q7v2Q3kZ1kY0=(...)", SampleMessage = "Restricted SQL Character Anomaly Detection (args): # of special characters exceeded (12)"
            },
            new()
            {
                RuleName = fd ? "Microsoft_DefaultRuleSet-2.1-PROTOCOL-ENFORCEMENT-920350" : "920350", PolicyName = policyName,
                Count = 96, Logged = 96, DistinctIps = 6, DistinctUris = 4,
                SampleIps = ["172.16.4.10", "172.16.4.11"], SampleUris = ["/healthz", "/api/status", "/metrics"],
                SampleMatchVariable = "RequestHeaderValues:Host", SampleMatchData = "203.0.113.10", SampleMessage = "Host header is a numeric IP address"
            },
            new()
            {
                RuleName = fd ? "BotManager-1.1-BadBots-Bot100200" : "Bot100200", PolicyName = policyName,
                Count = 2210, Blocked = 2210, DistinctIps = 640, DistinctUris = 33,
                SampleIps = ["45.155.205.233", "185.220.101.4", "89.248.165.1"], SampleUris = ["/", "/robots.txt", "/sitemap.xml", "/.git/config"],
                SampleMatchVariable = "", SampleMatchData = "", SampleMessage = "Known malicious bot"
            },
            new()
            {
                RuleName = fd ? "Microsoft_DefaultRuleSet-2.1-XSS-941100" : "941100", PolicyName = policyName,
                Count = 14, Blocked = 14, DistinctIps = 5, DistinctUris = 6,
                SampleIps = ["192.0.2.55", "198.51.100.200"], SampleUris = ["/search?q=%3Cscript%3Ealert(1)%3C/script%3E", "/contact"],
                SampleMatchVariable = "QueryParamValue:q", SampleMatchData = "<script>alert(1)</script>", SampleMessage = "XSS Attack Detected via libinjection"
            },
        };

        foreach (var a in activities)
        {
            WafLogAnalysisService.Classify(a, mode);
            analysis.RuleActivities.Add(a);
        }

        analysis.TotalEvents = activities.Sum(a => a.Count);
        analysis.BlockedCount = activities.Sum(a => a.Blocked);
        analysis.LoggedCount = activities.Sum(a => a.Logged);
        analysis.AllowedCount = activities.Sum(a => a.Allowed);
        analysis.RedirectedCount = activities.Sum(a => a.Redirected);
        analysis.DistinctRules = activities.Count;
        analysis.RuleActivities = analysis.RuleActivities
            .OrderBy(a => WafLogAnalysisService.ClassificationOrder(a.Classification)).ThenByDescending(a => a.Count).ToList();

        analysis.Changes =
        [
            new() { ChangeType = "New", RuleName = activities[4].RuleName, Description = "Started triggering this period (14 events; none in the previous period) — new attack activity, an application change, or a policy change." },
            new() { ChangeType = "Increased", RuleName = activities[3].RuleName, Description = "Activity increased from 640 to 2210 events versus the previous period." },
            new() { ChangeType = "Decreased", RuleName = activities[2].RuleName, Description = "Activity decreased from 310 to 96 events versus the previous period." },
        ];
        return analysis;
    }
}
