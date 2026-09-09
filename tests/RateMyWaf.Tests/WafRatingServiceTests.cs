using RateMyWaf.Models;
using RateMyWaf.Services;
using Xunit;

namespace RateMyWaf.Tests;

/// <summary>
/// Scoring edge cases. The Front Door cases are the WAFFLOW reference cases and must keep producing
/// identical scores, grades, caps and improvement points; the Application Gateway cases prove the
/// same engine applies to gateways.
/// </summary>
public class WafRatingServiceTests
{
    private const string FdId = "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Cdn/profiles/fd1";
    private const string PolicyId = "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Network/frontdoorwebapplicationfirewallpolicies/pol1";

    private const string GwId = "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Network/applicationGateways/agw1";
    private const string GwPolicyId = "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/agwpol1";

    // ── Builders ─────────────────────────────────────────────────────────────

    private static FrontDoorInfo PremiumFrontDoor() => new()
    {
        Id = FdId,
        Name = "fd1",
        SubscriptionId = "s1",
        Kind = FrontDoorKind.Premium,
        SkuName = "Premium_AzureFrontDoor",
        AssociatedPolicyIds = [PolicyId],
        WafLogsEnabled = true,
        LogDestinations = ["Log Analytics: la-workspace"]
    };

    /// <summary>A policy that earns full marks in every category.</summary>
    private static WafPolicyInfo PerfectPolicy(string id = PolicyId, string name = "pol1", WafPolicyKind kind = WafPolicyKind.FrontDoor, string association = FdId + "/securitypolicies/sp1") => new()
    {
        Id = id,
        Name = name,
        SubscriptionId = "s1",
        Kind = kind,
        SkuName = kind == WafPolicyKind.FrontDoor ? "Premium_AzureFrontDoor" : "",
        EnabledState = "Enabled",
        Mode = "Prevention",
        RequestBodyCheck = "Enabled",
        AssociationIds = [association],
        ManagedRuleSets =
        [
            new ManagedRuleSetInfo { RuleSetType = "Microsoft_DefaultRuleSet", RuleSetVersion = "2.1", LatestVersion = "2.1", IsLatest = true },
            new ManagedRuleSetInfo { RuleSetType = "Microsoft_BotManagerRuleSet", RuleSetVersion = "1.1", LatestVersion = "1.1", IsLatest = true },
        ],
        CustomRules =
        [
            new WafCustomRule { Name = "rate", RuleType = "RateLimitRule", Action = "Block", EnabledState = "Enabled", RateLimitThreshold = 100 },
            new WafCustomRule { Name = "geo", RuleType = "MatchRule", Action = "Block", EnabledState = "Enabled", Conditions = ["GeoMatch: not in [NL, BE]"] },
        ]
    };

    private static AppGatewayInfo WafV2Gateway() => new()
    {
        Id = GwId,
        Name = "agw1",
        SubscriptionId = "s1",
        Tier = "WAF_v2",
        FirewallPolicyId = GwPolicyId,
        Listeners =
        [
            new WafSurfaceInfo { Id = GwId + "/httpListeners/https", Name = "https", HostName = "www.contoso.com", WafPolicyId = GwPolicyId },
            new WafSurfaceInfo { Id = GwId + "/httpListeners/api", Name = "api", HostName = "api.contoso.com", WafPolicyId = GwPolicyId },
        ],
        WafLogsEnabled = true,
        LogDestinations = ["Log Analytics: la-workspace"]
    };

    private static WafPolicyInfo PerfectGatewayPolicy() =>
        PerfectPolicy(GwPolicyId, "agwpol1", WafPolicyKind.ApplicationGateway, GwId);

    // ── Front Door reference cases ───────────────────────────────────────────

    [Fact]
    public void FullyConfiguredPremium_ScoresHundred_GradeA()
    {
        var rating = WafRatingService.RateFrontDoor(PremiumFrontDoor(), [PerfectPolicy()]);

        Assert.Equal(100, rating.Score);
        Assert.Equal("A", rating.Grade);
        Assert.Equal("Excellent", rating.GradeLabel);
        Assert.Null(rating.CapReason);
        Assert.Empty(rating.Improvements);
        Assert.Equal(100, rating.Categories.Sum(c => c.Possible));
        Assert.Equal(WafFlowKind.FrontDoor, rating.TargetKind);
    }

    [Fact]
    public void NoWafPolicy_IsAutomaticF()
    {
        var fd = PremiumFrontDoor();
        fd.AssociatedPolicyIds = [];

        var rating = WafRatingService.RateFrontDoor(fd, []);

        Assert.Equal("F", rating.Grade);
        Assert.Equal(0, rating.Categories.Single(c => c.Name == WafRatingService.CoverageCategory).Earned);
        Assert.Contains(rating.Improvements, i => i.PointsGained == 30);
    }

    [Fact]
    public void DisabledPolicy_CountsAsUnprotected_GradeF()
    {
        var policy = PerfectPolicy();
        policy.EnabledState = "Disabled";

        var rating = WafRatingService.RateFrontDoor(PremiumFrontDoor(), [policy]);

        Assert.Equal("F", rating.Grade);
    }

    [Fact]
    public void DetectionOnly_IsCappedAtC()
    {
        var policy = PerfectPolicy();
        policy.Mode = "Detection";

        var rating = WafRatingService.RateFrontDoor(PremiumFrontDoor(), [policy]);

        // 100 - 20 prevention points = 80 (grade B on score), capped to C.
        Assert.Equal(80, rating.Score);
        Assert.Equal("C", rating.Grade);
        Assert.NotNull(rating.CapReason);

        var fix = rating.Improvements.Single(i => i.Action.Contains("Prevention"));
        Assert.Equal(20, fix.PointsGained);
        Assert.Equal("A", fix.ResultingGrade);
    }

    [Fact]
    public void LoggingDisabled_LosesLoggingPoints_AndCannotExceedB()
    {
        var fd = PremiumFrontDoor();
        fd.WafLogsEnabled = false;
        fd.LogDestinations = [];

        var rating = WafRatingService.RateFrontDoor(fd, [PerfectPolicy()]);

        Assert.Equal(85, rating.Score);
        Assert.Equal("B", rating.Grade);
        Assert.Contains(rating.Improvements, i => i.PointsGained == 10);
    }

    [Fact]
    public void LoggingUnknown_AwardsHalfPoints_NoCap()
    {
        var fd = PremiumFrontDoor();
        fd.WafLogsEnabled = null;

        var rating = WafRatingService.RateFrontDoor(fd, [PerfectPolicy()]);

        Assert.Equal(95, rating.Score);
        Assert.Equal("A", rating.Grade);
        Assert.Null(rating.CapReason);
    }

    [Fact]
    public void NoManagedRuleSets_IsCappedAtC()
    {
        var policy = PerfectPolicy();
        policy.ManagedRuleSets = [];

        var rating = WafRatingService.RateFrontDoor(PremiumFrontDoor(), [policy]);

        Assert.Equal(80, rating.Score);
        Assert.Equal("C", rating.Grade);
        Assert.NotNull(rating.CapReason);
        Assert.Contains(rating.Improvements, i => i.Action.Contains("Default Rule Set") && i.PointsGained == 15);
    }

    [Fact]
    public void StandardSku_NoManagedRules_MentionsPremiumUpgrade()
    {
        var fd = PremiumFrontDoor();
        fd.Kind = FrontDoorKind.Standard;
        fd.SkuName = "Standard_AzureFrontDoor";
        var policy = PerfectPolicy();
        policy.ManagedRuleSets = [];

        var rating = WafRatingService.RateFrontDoor(fd, [policy]);

        Assert.Contains(rating.Improvements, i => i.Action.Contains("upgrading the Front Door to Premium"));
    }

    [Fact]
    public void OutdatedDefaultRuleSet_LosesLatestPoints()
    {
        var policy = PerfectPolicy();
        policy.ManagedRuleSets[0] = new ManagedRuleSetInfo
        {
            RuleSetType = "Microsoft_DefaultRuleSet",
            RuleSetVersion = "2.1",
            LatestVersion = "2.2",
            IsLatest = false
        };

        var rating = WafRatingService.RateFrontDoor(PremiumFrontDoor(), [policy]);

        Assert.Equal(95, rating.Score);
        Assert.Equal("A", rating.Grade);
        Assert.Contains(rating.Improvements, i => i.Action.Contains("2.2") && i.PointsGained == 5);
    }

    [Fact]
    public void UnknownLatestVersion_DoesNotDeduct()
    {
        var policy = PerfectPolicy();
        policy.ManagedRuleSets[0].IsLatest = null;
        policy.ManagedRuleSets[0].LatestVersion = null;

        var rating = WafRatingService.RateFrontDoor(PremiumFrontDoor(), [policy]);

        Assert.Equal(100, rating.Score);
    }

    [Fact]
    public void PremiumPartialDomainCoverage_IsCappedAtD_WorseThanDetectionOnly()
    {
        var fd = PremiumFrontDoor();
        fd.Endpoints =
        [
            new WafSurfaceInfo { Id = FdId + "/afdendpoints/ep1", Name = "ep1", HostName = "a.azurefd.net", WafPolicyId = PolicyId },
            new WafSurfaceInfo { Id = FdId + "/customdomains/cd1", Name = "cd1", HostName = "www.contoso.com", IsCustomDomain = true, WafPolicyId = null },
        ];

        var rating = WafRatingService.RateFrontDoor(fd, [PerfectPolicy()]);

        Assert.Equal(15, rating.Categories.Single(c => c.Name == WafRatingService.CoverageCategory).Earned);
        Assert.Equal("D", rating.Grade);
        Assert.NotNull(rating.CapReason);

        var detectionPolicy = PerfectPolicy();
        detectionPolicy.Mode = "Detection";
        var detectionRating = WafRatingService.RateFrontDoor(PremiumFrontDoor(), [detectionPolicy]);
        Assert.True(string.CompareOrdinal(rating.Grade, detectionRating.Grade) > 0);

        var fix = rating.Improvements.Single(i => i.Action.Contains("domain"));
        Assert.Equal(15, fix.PointsGained);
        Assert.Equal("A", fix.ResultingGrade);
    }

    [Fact]
    public void PremiumWithNoCoveredDomain_IsAutomaticF_DespiteAssociatedPolicy()
    {
        var fd = PremiumFrontDoor();
        fd.Endpoints =
        [
            new WafSurfaceInfo { Id = FdId + "/afdendpoints/ep1", Name = "ep1", HostName = "a.azurefd.net", WafPolicyId = null },
            new WafSurfaceInfo { Id = FdId + "/customdomains/cd1", Name = "cd1", HostName = "www.contoso.com", IsCustomDomain = true, WafPolicyId = null },
        ];

        var rating = WafRatingService.RateFrontDoor(fd, [PerfectPolicy()]);

        Assert.Equal("F", rating.Grade);
        Assert.Equal(0, rating.Categories.Single(c => c.Name == WafRatingService.CoverageCategory).Earned);
    }

    [Fact]
    public void PremiumMostlyUncovered_KeepsAtLeastOneCoveragePoint_SoTheCapIsLiftable()
    {
        var fd = PremiumFrontDoor();
        fd.Endpoints = [new WafSurfaceInfo { Id = FdId + "/afdendpoints/ep0", Name = "ep0", HostName = "ep0.azurefd.net", WafPolicyId = PolicyId }];
        for (var i = 1; i < 40; i++)
            fd.Endpoints.Add(new WafSurfaceInfo { Id = $"{FdId}/customdomains/cd{i}", Name = $"cd{i}", HostName = $"cd{i}.contoso.com", IsCustomDomain = true });

        var rating = WafRatingService.RateFrontDoor(fd, [PerfectPolicy()]);

        Assert.Equal(1, rating.Categories.Single(c => c.Name == WafRatingService.CoverageCategory).Earned);
        Assert.Equal("D", rating.Grade);
        Assert.Contains(rating.Improvements, i => i.PointsGained == 29 && i.ResultingGrade == "A");
    }

    [Fact]
    public void ClassicFrontDoor_PartialEndpointCoverage_ScoresProportionally()
    {
        var policy = PerfectPolicy();
        var fd = PremiumFrontDoor();
        fd.Kind = FrontDoorKind.Classic;
        fd.SkuName = "Classic_AzureFrontDoor";
        fd.AssociatedPolicyIds = [];
        fd.Endpoints =
        [
            new WafSurfaceInfo { Name = "ep1", HostName = "a.azurefd.net", WafPolicyId = PolicyId },
            new WafSurfaceInfo { Name = "ep2", HostName = "b.azurefd.net", WafPolicyId = null },
        ];
        policy.AssociationIds = [FdId + "/frontendendpoints/ep1"];

        var rating = WafRatingService.RateFrontDoor(fd, [policy]);

        Assert.Equal(15, rating.Categories.Single(c => c.Name == WafRatingService.CoverageCategory).Earned);
        Assert.Contains(rating.Improvements, i => i.PointsGained == 15 && i.Action.Contains("endpoint"));
    }

    [Fact]
    public void TuningDeductions_ReduceHygieneScore()
    {
        var policy = PerfectPolicy();
        policy.ManagedRuleSets[0].DisabledRuleCount = 4;   // -2
        policy.ManagedRuleSets[0].ExclusionCount = 3;      // + policy-level 1 = 4 exclusions -> -2
        policy.ExclusionCount = 1;

        var rating = WafRatingService.RateFrontDoor(PremiumFrontDoor(), [policy]);

        var hygiene = rating.Categories.Single(c => c.Name == WafRatingService.HygieneCategory);
        Assert.Equal(6, hygiene.Earned);
        Assert.Contains(rating.Improvements, i => i.Action.Contains("tuning", StringComparison.OrdinalIgnoreCase) && i.PointsGained == 4);
    }

    [Fact]
    public void HygieneDeduction_IsCappedAtTenPoints()
    {
        var policy = PerfectPolicy();
        policy.ManagedRuleSets[0].DisabledRuleCount = 100;
        policy.ManagedRuleSets[0].ActionOverrideCount = 100;
        policy.ManagedRuleSets[0].ExclusionCount = 100;

        var rating = WafRatingService.RateFrontDoor(PremiumFrontDoor(), [policy]);

        Assert.Equal(0, rating.Categories.Single(c => c.Name == WafRatingService.HygieneCategory).Earned);
        Assert.Equal(90, rating.Score);
    }

    [Fact]
    public void MissingExtras_LoseFivePoints()
    {
        var policy = PerfectPolicy();
        policy.CustomRules = [];
        policy.RequestBodyCheck = "Disabled";

        var rating = WafRatingService.RateFrontDoor(PremiumFrontDoor(), [policy]);

        Assert.Equal(95, rating.Score);
        Assert.Equal(0, rating.Categories.Single(c => c.Name == WafRatingService.ExtrasCategory).Earned);
        Assert.Equal(3, rating.Improvements.Count);
    }

    [Fact]
    public void Improvements_AreSortedByPointsDescending()
    {
        var fd = PremiumFrontDoor();
        fd.WafLogsEnabled = false;
        fd.LogDestinations = [];
        var policy = PerfectPolicy();
        policy.Mode = "Detection";
        policy.ManagedRuleSets = [];

        var rating = WafRatingService.RateFrontDoor(fd, [policy]);

        var points = rating.Improvements.Select(i => i.PointsGained).ToList();
        Assert.Equal(points.OrderByDescending(p => p), points);
        Assert.True(rating.Improvements.Count >= 3);
    }

    [Fact]
    public void RateAll_ProducesOneRatingPerResource_AndMergePreservesThem()
    {
        var result = new WafScanResult
        {
            FrontDoors = [PremiumFrontDoor()],
            AppGateways = [WafV2Gateway()],
            WafPolicies = [PerfectPolicy(), PerfectGatewayPolicy()]
        };
        WafRatingService.RateAll(result);
        Assert.Equal(2, result.Ratings.Count);
        Assert.All(result.Ratings, r => Assert.Equal("A", r.Grade));

        var merged = new WafScanResult();
        merged.Merge(result);
        Assert.Equal(2, merged.Ratings.Count);
    }

    [Theory]
    [InlineData(95, "A")]
    [InlineData(90, "A")]
    [InlineData(89, "B")]
    [InlineData(75, "B")]
    [InlineData(60, "C")]
    [InlineData(45, "D")]
    [InlineData(30, "E")]
    [InlineData(29, "F")]
    [InlineData(0, "F")]
    public void GradeBands_MatchTheLegend(int score, string expected) =>
        Assert.Equal(expected, WafRatingService.GradeForScore(score));

    [Fact]
    public void Worst_PicksTheLowestGrade()
    {
        var a = new WafRating { Grade = "A", Score = 100 };
        var c = new WafRating { Grade = "C", Score = 80 };
        var c2 = new WafRating { Grade = "C", Score = 60 };
        Assert.Same(c2, WafRatingService.Worst([a, c, c2]));
        Assert.Null(WafRatingService.Worst([]));
    }

    // ── Application Gateway cases ────────────────────────────────────────────

    [Fact]
    public void FullyConfiguredGateway_ScoresHundred_GradeA()
    {
        var rating = WafRatingService.RateAppGateway(WafV2Gateway(), [PerfectGatewayPolicy()]);

        Assert.Equal(100, rating.Score);
        Assert.Equal("A", rating.Grade);
        Assert.Empty(rating.Improvements);
        Assert.Equal(WafFlowKind.ApplicationGateway, rating.TargetKind);
        Assert.Contains("2 of 2 listener(s)", rating.Categories[0].Details[0]);
    }

    [Fact]
    public void StandardTierGateway_IsAutomaticF_WithUpgradeAdvice()
    {
        var gw = WafV2Gateway();
        gw.Tier = "Standard_v2";
        gw.FirewallPolicyId = null;
        foreach (var l in gw.Listeners) l.WafPolicyId = null;

        var rating = WafRatingService.RateAppGateway(gw, [PerfectGatewayPolicy()]);

        Assert.Equal("F", rating.Grade);
        // Logging (15) and clean hygiene (10) still score, exactly as a Front Door without a WAF does; coverage is 0.
        Assert.Equal(25, rating.Score);
        Assert.Equal(0, rating.Categories[0].Earned);
        Assert.Contains("does not support", rating.Categories[0].Details[0]);
        var fix = rating.Improvements.Single();
        Assert.Equal(30, fix.PointsGained);
        Assert.Contains("WAF_v2", fix.Action);
    }

    [Fact]
    public void WafTierGateway_NoPolicy_IsAutomaticF()
    {
        var gw = WafV2Gateway();
        gw.FirewallPolicyId = null;
        foreach (var l in gw.Listeners) l.WafPolicyId = null;

        var rating = WafRatingService.RateAppGateway(gw, []);

        Assert.Equal("F", rating.Grade);
        Assert.Equal(0, rating.Categories[0].Earned);
        Assert.Contains(rating.Improvements, i => i.PointsGained == 30 && i.Action.Contains("listener"));
    }

    [Fact]
    public void GatewayWithOneUnprotectedListener_IsCappedAtD()
    {
        var gw = WafV2Gateway();
        gw.FirewallPolicyId = null;                 // per-listener policies only
        gw.Listeners[1].WafPolicyId = null;

        var rating = WafRatingService.RateAppGateway(gw, [PerfectGatewayPolicy()]);

        Assert.Equal(15, rating.Categories[0].Earned);
        Assert.Equal("D", rating.Grade);
        Assert.Contains("listener", rating.CapReason);
        var fix = rating.Improvements.Single(i => i.Action.Contains("listener"));
        Assert.Equal("A", fix.ResultingGrade);
    }

    [Fact]
    public void GatewayWithoutParsedListeners_FallsBackToPolicyAssociation()
    {
        var gw = WafV2Gateway();
        gw.Listeners = [];

        var rating = WafRatingService.RateAppGateway(gw, [PerfectGatewayPolicy()]);

        Assert.Equal(100, rating.Score);
        Assert.Contains("attached: agwpol1", rating.Categories[0].Details[0]);
    }

    [Fact]
    public void LegacyInlineConfig_IsRatedAsAPolicy()
    {
        var gw = WafV2Gateway();
        gw.FirewallPolicyId = null;
        gw.LegacyWafPresent = true;
        gw.LegacyWafConfigured = true;
        gw.LegacyWafMode = "Detection";
        gw.LegacyRuleSetType = "OWASP";
        gw.LegacyRuleSetVersion = "3.1";
        foreach (var l in gw.Listeners) l.WafPolicyId = gw.LegacyPolicyId;

        var legacy = new WafPolicyInfo
        {
            Id = gw.LegacyPolicyId,
            Name = "agw1 (inline WAF configuration)",
            Kind = WafPolicyKind.ApplicationGateway,
            IsLegacyInline = true,
            EnabledState = "Enabled",
            Mode = "Detection",
            RequestBodyCheck = "Enabled",
            ManagedRuleSets = [new ManagedRuleSetInfo { RuleSetType = "OWASP", RuleSetVersion = "3.1", LatestVersion = "3.2", IsLatest = false }]
        };

        var rating = WafRatingService.RateAppGateway(gw, [legacy]);

        // 30 coverage + 0 prevention + (10 DRS + 0 latest + 0 bot) + 15 logging + 10 hygiene + 2 body = 67, capped to C by detection mode.
        Assert.Equal(67, rating.Score);
        Assert.Equal("C", rating.Grade);
        Assert.Contains(rating.Improvements, i => i.Action.Contains("Prevention") && i.PointsGained == 20 && i.ResultingGrade == "B");
        Assert.Contains(rating.Improvements, i => i.Action.Contains("OWASP to 3.2"));
    }

    [Fact]
    public void GatewayDetectionMode_IsCappedAtC()
    {
        var policy = PerfectGatewayPolicy();
        policy.Mode = "Detection";

        var rating = WafRatingService.RateAppGateway(WafV2Gateway(), [policy]);

        Assert.Equal(80, rating.Score);
        Assert.Equal("C", rating.Grade);
    }

    [Fact]
    public void GatewayNoManagedRules_UsesGatewaySpecificAdvice()
    {
        var policy = PerfectGatewayPolicy();
        policy.ManagedRuleSets = [];

        var rating = WafRatingService.RateAppGateway(WafV2Gateway(), [policy]);

        Assert.Equal("C", rating.Grade);
        Assert.Contains(rating.Improvements, i => i.Action.Contains("OWASP CRS 3.2") && i.PointsGained == 15);
    }

    [Fact]
    public void FrontDoorPolicy_DoesNotLeakIntoGatewayRating()
    {
        var gw = WafV2Gateway();
        gw.FirewallPolicyId = null;
        foreach (var l in gw.Listeners) l.WafPolicyId = null;

        var rating = WafRatingService.RateAppGateway(gw, [PerfectPolicy()]);

        Assert.Equal("F", rating.Grade);
    }
}
