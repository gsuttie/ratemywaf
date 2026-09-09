using System.IO.Compression;
using System.Text.RegularExpressions;
using RateMyWaf.Models;
using RateMyWaf.Services;
using Xunit;

namespace RateMyWaf.Tests;

public class FixScriptTests
{
    private static WafRuleActivity Attack() => new()
    {
        RuleName = "Microsoft_DefaultRuleSet-2.1-SQLI-942100", PolicyName = "waf-prod", Classification = "Likely real attack",
        SampleIps = ["1.2.3.4", "5.6.7.8"], SampleUris = ["/.env?x=1"]
    };

    private static WafRuleActivity FalsePositive() => new()
    {
        RuleName = "942430", PolicyName = "agw-waf", Classification = "Possible false positive",
        SampleMatchVariable = "CookieValue:session", SampleMatchData = "abc", SampleUris = ["/api/orders?id=1"]
    };

    [Fact]
    public void FrontDoor_AttackScript_BlocksIpsAndSwitchesToPrevention()
    {
        var (explanation, options) = FixScriptService.Describe(Attack(), WafFlowKind.FrontDoor);
        Assert.Contains("custom block rule", explanation);
        var script = FixScriptService.Generate(Attack(), WafFlowKind.FrontDoor, options);

        Assert.Contains("New-AzFrontDoorWafCustomRuleObject", script);
        Assert.Contains("\"1.2.3.4\", \"5.6.7.8\"", script);
        Assert.Contains("-Mode Prevention", script);
        Assert.Contains("$policyName = \"waf-prod\"", script);
    }

    [Fact]
    public void AppGateway_FalsePositiveScript_AddsScopedExclusion()
    {
        var (_, options) = FixScriptService.Describe(FalsePositive(), WafFlowKind.ApplicationGateway);
        var script = FixScriptService.Generate(FalsePositive(), WafFlowKind.ApplicationGateway, options);

        Assert.Contains("New-AzApplicationGatewayFirewallPolicyExclusion", script);
        Assert.Contains("-MatchVariable \"CookieValue\"", script);
        Assert.Contains("-Selector \"session\"", script);
        Assert.Contains("$ruleId = \"942430\"", script);
        Assert.Contains("Seen on URI: /api/orders", script);
        Assert.Contains("Set-AzApplicationGatewayFirewallPolicy", script);
    }

    [Fact]
    public void NoOptions_ProducesPlaceholderScript()
    {
        var (_, options) = FixScriptService.Describe(Attack(), WafFlowKind.FrontDoor);
        var none = options.Select(o => o with { Enabled = false });
        var script = FixScriptService.Generate(Attack(), WafFlowKind.FrontDoor, none);
        Assert.Contains("No options selected", script);
        Assert.DoesNotContain("Update-AzFrontDoorWafPolicy -Name", script);
    }

    [Fact]
    public void NeedsReview_OffersDetectionMode()
    {
        var a = new WafRuleActivity { RuleName = "920300", PolicyName = "p", Classification = "Needs review" };
        var (_, options) = FixScriptService.Describe(a, WafFlowKind.ApplicationGateway);
        Assert.Contains(options, o => o.Key == "detectionMode" && o.Enabled);
        Assert.Contains(options, o => o.Key == "exclusion" && !o.Enabled);
        Assert.Contains("$policy.PolicySettings.Mode = \"Detection\"", FixScriptService.Generate(a, WafFlowKind.ApplicationGateway, options));
    }
}

public class ReportTests
{
    private static WafReportContext Context(WafFlowKind flow, bool withLogs)
    {
        var scan = DemoDataService.Scan(flow, [DemoDataService.SubProd, DemoDataService.SubShared]);
        var target = flow == WafFlowKind.FrontDoor ? scan.FrontDoors[0].Name : scan.AppGateways[0].Name;
        var targetId = flow == WafFlowKind.FrontDoor ? scan.FrontDoors[0].Id : scan.AppGateways[0].Id;
        return new WafReportContext
        {
            Flow = flow,
            CustomerName = "Contoso",
            TenantName = "Contoso Ltd",
            ReportAuthor = "tester",
            ScanDate = new DateTime(2026, 9, 7, 10, 30, 0),
            SubscriptionLines = ["Contoso Production (1111)"],
            Scan = scan,
            LogAnalysis = withLogs ? DemoDataService.LogAnalysis(flow, targetId, target, WafFlowService.LinkedPolicies(scan, targetId), "24h") : null
        };
    }

    private static string DocxText(byte[] bytes)
    {
        using var zip = new ZipArchive(new MemoryStream(bytes));
        using var reader = new StreamReader(zip.GetEntry("word/document.xml")!.Open());
        return Regex.Replace(reader.ReadToEnd(), "<[^>]+>", " ");
    }

    [Theory]
    [InlineData(WafFlowKind.FrontDoor)]
    [InlineData(WafFlowKind.ApplicationGateway)]
    public void SummaryReport_ContainsGradesFindingsAndRecommendations(WafFlowKind flow)
    {
        var ctx = Context(flow, withLogs: true);

        var html = WafReportService.SummaryHtml(ctx);
        var docx = DocxText(WafReportService.SummaryDocx(ctx));

        foreach (var text in new[] { flow.Label() + " WAF — Summary Report", "Executive summary", "security rating", "Rule set compliance", "Recommendations", "Contoso Ltd", "EXCELLENT", "UNACCEPTABLE" })
        {
            Assert.Contains(text, html);
            Assert.Contains(text, docx);
        }
        foreach (var r in ctx.Scan!.Ratings)
        {
            Assert.Contains(r.TargetName, html);
            Assert.Contains(r.TargetName, docx);
        }
        Assert.Contains("WAF event(s) across", docx);
    }

    [Theory]
    [InlineData(WafFlowKind.FrontDoor)]
    [InlineData(WafFlowKind.ApplicationGateway)]
    public void FindingsReport_ContainsInventoryAndLogSections(WafFlowKind flow)
    {
        var ctx = Context(flow, withLogs: true);

        var html = WafReportService.FindingsHtml(ctx);
        var docx = DocxText(WafReportService.FindingsDocx(ctx));

        foreach (var text in new[] { "Detailed Findings", "WAF policy inventory", "Protected resources", "Alert assessment", "Tuning and exclusion recommendations", "Likely real attack", "Possible false positive" })
        {
            Assert.Contains(text, html);
            Assert.Contains(text, docx);
        }
        foreach (var p in ctx.Scan!.WafPolicies)
            Assert.Contains(p.Name, docx);
        foreach (var f in ctx.Scan.Findings)
            Assert.Contains(System.Net.WebUtility.HtmlEncode(f.Fix), html);
    }

    [Fact]
    public void Reports_WithoutScan_StillRender()
    {
        var ctx = new WafReportContext { Flow = WafFlowKind.FrontDoor };
        Assert.Contains("No scan data", WafReportService.SummaryHtml(ctx));
        Assert.Contains("No scan data", DocxText(WafReportService.FindingsDocx(ctx)));
        Assert.Contains("no log analysis has been run", WafReportService.FindingsHtml(ctx));
    }

    [Fact]
    public void HtmlPreview_EncodesUserContent()
    {
        var scan = new WafScanResult { Flow = WafFlowKind.FrontDoor };
        scan.FrontDoors.Add(new FrontDoorInfo { Id = "/fd", Name = "<script>alert(1)</script>", Kind = FrontDoorKind.Premium });
        WafDiscoveryService.Finalize(scan);
        var html = WafReportService.SummaryHtml(new WafReportContext { Flow = WafFlowKind.FrontDoor, Scan = scan });
        Assert.DoesNotContain("<script>", html);
        Assert.Contains("&lt;script&gt;", html);
    }

    [Fact]
    public void FileName_IsSafeAndDescriptive()
    {
        var ctx = new WafReportContext { Flow = WafFlowKind.ApplicationGateway, CustomerName = "Contoso Ltd / EU", ScanDate = new DateTime(2026, 9, 7) };
        Assert.Equal("ContosoLtdEU-AppGateway-WAF-Findings-20260907.docx", WafReportService.FileName(ctx, findings: true));
        Assert.Equal("WAF-FrontDoor-WAF-Summary-20260907.docx", WafReportService.FileName(new WafReportContext { Flow = WafFlowKind.FrontDoor, ScanDate = new DateTime(2026, 9, 7) }, false));
    }
}

public class DemoDataTests
{
    [Fact]
    public void FrontDoorEstate_CoversSeveralGradeBands()
    {
        var scan = DemoDataService.Scan(WafFlowKind.FrontDoor, [DemoDataService.SubProd, DemoDataService.SubShared]);
        var grades = scan.Ratings.ToDictionary(r => r.TargetName, r => r.Grade);

        Assert.Equal("A", grades["afd-contoso-prod"]);
        Assert.Equal("E", grades["afd-contoso-marketing"]);   // detection-only, no managed rules, uncovered domain: 42 points
        Assert.Equal("D", grades["fd-contoso-legacy"]);       // 49 points; unprotected classic endpoint also caps at D
        Assert.Equal(3, scan.Ratings.Count);
        Assert.NotEmpty(scan.Findings);
    }

    [Fact]
    public void AppGatewayEstate_CoversSeveralGradeBands()
    {
        var scan = DemoDataService.Scan(WafFlowKind.ApplicationGateway, [DemoDataService.SubProd, DemoDataService.SubShared]);
        var ratings = scan.Ratings.ToDictionary(r => r.TargetName);

        Assert.Equal("B", ratings["agw-contoso-prod"].Grade);
        Assert.Equal("F", ratings["agw-contoso-intranet"].Grade);
        Assert.Equal("D", ratings["agw-contoso-legacy"].Grade);   // 59 points: detection mode, outdated OWASP 3.0, storage-only logs
        Assert.Contains(scan.WafPolicies, p => p.IsLegacyInline);
        Assert.All(scan.AppGateways.First(g => g.Name == "agw-contoso-legacy").Listeners, l => Assert.NotNull(l.WafPolicyId));
    }

    [Fact]
    public void Scan_FiltersBySubscription()
    {
        var scan = DemoDataService.Scan(WafFlowKind.FrontDoor, [DemoDataService.SubProd]);
        Assert.All(scan.FrontDoors, f => Assert.Equal(DemoDataService.SubProd, f.SubscriptionId));
        Assert.All(scan.WafPolicies, p => Assert.Equal(DemoDataService.SubProd, p.SubscriptionId));
        Assert.Equal(2, scan.Ratings.Count);
    }

    [Fact]
    public void LogAnalysis_ProducesAllThreeClassifications()
    {
        var scan = DemoDataService.Scan(WafFlowKind.FrontDoor, [DemoDataService.SubProd]);
        var fd = scan.FrontDoors[0];
        var la = DemoDataService.LogAnalysis(WafFlowKind.FrontDoor, fd.Id, fd.Name, WafFlowService.LinkedPolicies(scan, fd.Id), "24h");

        Assert.True(la.LogsQueryable);
        Assert.Equal(la.RuleActivities.Sum(a => a.Count), la.TotalEvents);
        Assert.Contains(la.RuleActivities, a => a.Classification == "Likely real attack");
        Assert.Contains(la.RuleActivities, a => a.Classification == "Possible false positive");
        Assert.Contains(la.RuleActivities, a => a.Classification == "Needs review");
        Assert.All(la.RuleActivities, a => Assert.NotEmpty(a.Recommendations));
    }
}
