using System.Text.Json;
using RateMyWaf.Models;
using RateMyWaf.Services;
using Xunit;

namespace RateMyWaf.Tests;

public class WafLogAnalysisServiceTests
{
    private static Dictionary<string, JsonElement> Row(params (string Key, object Value)[] cells)
    {
        var dict = new Dictionary<string, JsonElement>(StringComparer.OrdinalIgnoreCase);
        foreach (var (k, v) in cells)
            dict[k] = JsonSerializer.SerializeToElement(v);
        return dict;
    }

    [Fact]
    public void Classify_ScannerAndAttackPatterns_IsLikelyRealAttack()
    {
        var a = new WafRuleActivity
        {
            RuleName = "Microsoft_DefaultRuleSet-2.1-SQLI-942100", Count = 500, Blocked = 500, DistinctIps = 40, DistinctUris = 30,
            SampleUris = ["/.env", "/wp-login.php"], SampleMatchData = "union select 1,2", SampleMessage = "sqlmap probe"
        };
        WafLogAnalysisService.Classify(a, "Prevention");

        Assert.Equal("Likely real attack", a.Classification);
        Assert.Contains("known attack or probing patterns", a.Explanation);
        Assert.Contains(a.Recommendations, r => r.Contains("blocking this traffic correctly"));
    }

    [Fact]
    public void Classify_FpProneRuleInCookie_FewIps_IsPossibleFalsePositive()
    {
        var a = new WafRuleActivity
        {
            RuleName = "Microsoft_DefaultRuleSet-2.1-SQLI-942430", Count = 120, Blocked = 120, DistinctIps = 2, DistinctUris = 1,
            SampleUris = ["/api/orders"], SampleMatchVariable = "CookieValue:session", SampleMatchData = "abc==", SampleMessage = "Restricted SQL Character Anomaly"
        };
        WafLogAnalysisService.Classify(a, "Prevention");

        Assert.Equal("Possible false positive", a.Classification);
        Assert.Contains(a.Recommendations, r => r.Contains("exclusion for 'CookieValue:session' scoped to rule 942430"));
        Assert.Contains(a.Recommendations, r => r.Contains("currently being blocked"));
    }

    [Fact]
    public void Classify_NoSignals_NeedsReview()
    {
        var a = new WafRuleActivity { RuleName = "941100", Count = 3, Logged = 3, DistinctIps = 5, DistinctUris = 5 };
        WafLogAnalysisService.Classify(a, "Detection");

        Assert.Equal("Needs review", a.Classification);
        Assert.Contains("No strong indicators", a.Explanation);
        Assert.Equal(2, a.Recommendations.Count);
    }

    [Fact]
    public void Classify_AttackInDetectionMode_RecommendsPrevention()
    {
        var a = new WafRuleActivity { RuleName = "Bot100200", PolicyName = "pol", Count = 900, Logged = 900, DistinctIps = 300, DistinctUris = 40, SampleUris = ["/.git/config"] };
        WafLogAnalysisService.Classify(a, "Detection");

        Assert.Equal("Likely real attack", a.Classification);
        Assert.Contains(a.Recommendations, r => r.Contains("Detection mode"));
    }

    [Theory]
    [InlineData("Microsoft_DefaultRuleSet-2.1-SQLI-942430", "942430")]
    [InlineData("942100", "942100")]
    [InlineData("BotManager-1.1-BadBots-Bot100200", "BotManager-1.1-BadBots-Bot100200")]
    public void ExtractRuleId_FindsTrailingNumericSegment(string ruleName, string expected) =>
        Assert.Equal(expected, WafLogAnalysisService.ExtractRuleId(ruleName));

    [Fact]
    public void ExtractMatchVariableName_PullsVariableWithSelector()
    {
        Assert.Equal("CookieValue:mycookie", WafLogAnalysisService.ExtractMatchVariableName("[{\"matchVariableName\":\"CookieValue:mycookie\",\"matchVariableValue\":\"x\"}]"));
        Assert.Equal("RequestHeaderNames", WafLogAnalysisService.ExtractMatchVariableName("RequestHeaderNames Accept"));
        Assert.Null(WafLogAnalysisService.ExtractMatchVariableName(""));
    }

    [Fact]
    public void BuildChanges_DetectsNewStoppedModeSwitchesAndVolumeShifts()
    {
        var rows = new List<Dictionary<string, JsonElement>>
        {
            Row(("RuleOut", "new"), ("ActionOut", "Block"), ("Period", "current"), ("Count", 12)),
            Row(("RuleOut", "gone"), ("ActionOut", "Block"), ("Period", "previous"), ("Count", 40)),
            Row(("RuleOut", "tightened"), ("ActionOut", "Log"), ("Period", "previous"), ("Count", 30)),
            Row(("RuleOut", "tightened"), ("ActionOut", "Block"), ("Period", "current"), ("Count", 30)),
            Row(("RuleOut", "relaxed"), ("ActionOut", "Blocked"), ("Period", "previous"), ("Count", 30)),
            Row(("RuleOut", "relaxed"), ("ActionOut", "Matched"), ("Period", "current"), ("Count", 30)),
            Row(("RuleOut", "spike"), ("ActionOut", "Block"), ("Period", "previous"), ("Count", 10)),
            Row(("RuleOut", "spike"), ("ActionOut", "Block"), ("Period", "current"), ("Count", 100)),
            Row(("RuleOut", "drop"), ("ActionOut", "Block"), ("Period", "previous"), ("Count", 100)),
            Row(("RuleOut", "drop"), ("ActionOut", "Block"), ("Period", "current"), ("Count", 10)),
            Row(("RuleOut", "steady"), ("ActionOut", "Block"), ("Period", "previous"), ("Count", 50)),
            Row(("RuleOut", "steady"), ("ActionOut", "Block"), ("Period", "current"), ("Count", 55)),
        };

        var changes = WafLogAnalysisService.BuildChanges(rows);

        Assert.Equal(["New", "Now blocking", "Now log-only", "Stopped", "Increased", "Decreased"], changes.Select(c => c.ChangeType).ToList());
        Assert.DoesNotContain(changes, c => c.RuleName == "steady");
    }

    [Fact]
    public void Populate_AggregatesTotals_AndSortsAttacksFirst()
    {
        var analysis = new WafLogAnalysis();
        var policies = new[] { new WafPolicyInfo { Name = "pol", Mode = "Prevention" } };
        var evidence = new List<Dictionary<string, JsonElement>>
        {
            Row(("RuleOut", "942430"), ("PolicyOut", "pol"), ("Count", 100), ("DistinctIps", 1), ("DistinctUris", 1), ("SampleIps", new[] { "1.1.1.1" }), ("SampleUris", "[\"/api\"]"),
                ("SampleMatch", "CookieValue:s"), ("SampleData", ""), ("SampleMsg", ""), ("Blocked", 100), ("Logged", 0), ("Allowed", 0), ("Redirected", 0)),
            Row(("RuleOut", "Bot100200"), ("PolicyOut", "pol"), ("Count", 50), ("DistinctIps", 30), ("DistinctUris", 20), ("SampleIps", new[] { "2.2.2.2" }), ("SampleUris", new[] { "/.env" }),
                ("SampleMatch", ""), ("SampleData", ""), ("SampleMsg", ""), ("Blocked", 40), ("Logged", 10), ("Allowed", 0), ("Redirected", 0)),
        };

        WafLogAnalysisService.Populate(analysis, policies, evidence, []);

        Assert.Equal(150, analysis.TotalEvents);
        Assert.Equal(140, analysis.BlockedCount);
        Assert.Equal(10, analysis.LoggedCount);
        Assert.Equal(2, analysis.DistinctRules);
        Assert.Equal("Bot100200", analysis.RuleActivities[0].RuleName); // attack sorted first despite lower count
        Assert.Equal(["/api"], analysis.RuleActivities[1].SampleUris);   // encoded-string dynamic column parsed
        Assert.Empty(analysis.Warnings);
    }

    [Fact]
    public void BuildQueries_UsesProductSpecificTables_AndPolicyFilter()
    {
        var policies = new[] { new WafPolicyInfo { Name = "pol'1" } };

        var (fdEvidence, fdChanges) = WafLogAnalysisService.BuildQueries(WafFlowKind.FrontDoor, policies, "24h");
        Assert.Contains("FrontDoorWebApplicationFirewallLog", fdEvidence);
        Assert.Contains("PolicyOut in~ ('pol\\'1')", fdEvidence);
        Assert.Contains("ago(48h)", fdChanges);

        var (gwEvidence, _) = WafLogAnalysisService.BuildQueries(WafFlowKind.ApplicationGateway, policies, "7d");
        Assert.Contains("AGWFirewallLogs", gwEvidence);
        Assert.Contains("ApplicationGatewayFirewallLog", gwEvidence);
        Assert.Contains("ago(7d)", gwEvidence);

        // A workspace-wide query is pinned to the resource in every branch of the union.
        const string gwId = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/applicationGateways/agw";
        var (scoped, scopedChanges) = WafLogAnalysisService.BuildQueries(WafFlowKind.ApplicationGateway, policies, "24h", gwId);
        Assert.Equal(2, scoped.Split($"| where _ResourceId =~ '{gwId}'").Length - 1);
        Assert.Contains($"_ResourceId =~ '{gwId}'", scopedChanges);
        Assert.DoesNotContain("_ResourceId", gwEvidence);

        // A legacy inline config has no policy name in the logs: no filter.
        var (legacyEvidence, _) = WafLogAnalysisService.BuildQueries(WafFlowKind.ApplicationGateway, [new WafPolicyInfo { Name = "x", IsLegacyInline = true }], "1h");
        Assert.DoesNotContain("PolicyOut in~", legacyEvidence);
    }

    [Fact]
    public void TimeRanges_AllHaveLabels()
    {
        foreach (var (key, label) in WafLogAnalysisService.TimeRanges)
        {
            Assert.False(string.IsNullOrEmpty(label));
            Assert.Equal(label, WafLogAnalysisService.LabelFor(key));
            var (e, c) = WafLogAnalysisService.BuildQueries(WafFlowKind.FrontDoor, [], key);
            Assert.Contains($"ago({key})", e);
            Assert.Contains("Period", c);
        }
    }
}
