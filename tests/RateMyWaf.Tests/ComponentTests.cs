using Bunit;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using RateMyWaf.Components.Shared;
using RateMyWaf.Models;
using RateMyWaf.Services;
using RateMyWaf.Services.Azure;
using System.Text.Json;
using Xunit;

namespace RateMyWaf.Tests;

/// <summary>Rendering tests for the UI components, driven by the sample estate (no Azure).</summary>
public class ComponentTests : BunitContext
{
    /// <summary>An IAzureApi that must never be called: the demo mode keeps everything local.</summary>
    private sealed class ThrowingAzureApi : IAzureApi
    {
        public Task<List<JsonElement>> QueryResourceGraphAsync(string query, IReadOnlyCollection<string> subscriptionIds, string? tenantId, CancellationToken ct = default) => throw new InvalidOperationException("Azure must not be called in demo mode");
        public Task<List<JsonElement>> GetArmListAsync(string url, string? tenantId, CancellationToken ct = default) => throw new InvalidOperationException("Azure must not be called in demo mode");
        public Task<List<Dictionary<string, JsonElement>>> QueryLogAnalyticsAsync(string resourceId, string query, string? tenantId, CancellationToken ct = default) => throw new InvalidOperationException("Azure must not be called in demo mode");
    }

    private WafFlowService Flows { get; }

    public ComponentTests()
    {
        var credential = new global::Azure.Identity.AzureCliCredential();
        Services.AddSingleton<global::Azure.Core.TokenCredential>(credential);
        Services.AddSingleton<IAzureApi, ThrowingAzureApi>();
        Services.AddSingleton(new WafDiscoveryService(new ThrowingAzureApi(), NullLogger<WafDiscoveryService>.Instance));
        Services.AddSingleton(new WafLogAnalysisService(new ThrowingAzureApi(), NullLogger<WafLogAnalysisService>.Instance));
        Services.AddScoped(_ => new AzureSubscriptionService(credential, NullLogger<AzureSubscriptionService>.Instance));
        Services.AddScoped<SessionState>();
        Services.AddScoped<WafFlowService>();
        JSInterop.Mode = JSRuntimeMode.Loose;

        Flows = Services.GetRequiredService<WafFlowService>();
        Flows.EnterDemoMode();
    }

    private async Task ScanAsync(WafFlowKind flow)
    {
        var fs = Flows.State.For(flow);
        fs.SelectedSubscriptionIds.Add(DemoDataService.SubProd);
        fs.SelectedSubscriptionIds.Add(DemoDataService.SubShared);
        await Flows.ScanAsync(flow);
    }

    [Fact]
    public void GradeBadge_RendersLetterAndColour()
    {
        var cut = Render<GradeBadge>(p => p.Add(x => x.Grade, "B").Add(x => x.Large, true));
        var span = cut.Find("span.grade-badge");
        Assert.Equal("B", span.TextContent);
        Assert.Contains("lg", span.ClassName);
        Assert.Contains("#7CB342", span.GetAttribute("style"));
        Assert.Contains("Good", span.GetAttribute("title"));
    }

    [Fact]
    public void StepBar_LocksLaterStepsUntilThereIsAScan()
    {
        var locked = Render<StepBar>(p => p.Add(x => x.Route, "front-door").Add(x => x.Current, "scope").Add(x => x.HasScan, false));
        Assert.Equal(2, locked.FindAll("li.step.locked").Count);
        Assert.Empty(locked.FindAll("li.step a"));

        var open = Render<StepBar>(p => p.Add(x => x.Route, "front-door").Add(x => x.Current, "grades").Add(x => x.HasScan, true).Add(x => x.HasLogTargets, true));
        Assert.Empty(open.FindAll("li.step.locked"));
        Assert.Contains(open.FindAll("li.step a"), a => a.GetAttribute("href") == "/front-door/logs");
        Assert.Single(open.FindAll("li.step.active"));
    }

    [Fact]
    public async Task GradesStep_FrontDoor_ShowsOverallGradeRatingsFindingsAndPolicies()
    {
        await ScanAsync(WafFlowKind.FrontDoor);
        var cut = Render<GradesStep>(p => p.Add(x => x.Flow, WafFlowKind.FrontDoor));

        // The weakest Front Door sets the overall grade.
        Assert.Equal("E", cut.Find(".overall .grade-badge.lg").TextContent);
        Assert.Equal(3, cut.FindAll("article.rating").Count);
        Assert.Contains("afd-contoso-prod", cut.Markup);
        Assert.Contains("fd-contoso-legacy", cut.Markup);

        // The weakest resource is expanded by default with its breakdown and improvements.
        var open = cut.Find("article.rating.open");
        Assert.Contains("Score breakdown", open.TextContent);
        Assert.Contains("How to improve", open.TextContent);
        Assert.Equal(6, open.QuerySelectorAll("table.cats tr").Length);

        // Findings with fixes, and the policy table.
        Assert.Contains("Findings", cut.Markup);
        Assert.NotEmpty(cut.FindAll("ul.findings li"));
        Assert.Equal(4, cut.FindAll("tr.policy-row").Count);
    }

    [Fact]
    public async Task GradesStep_ExpandingFindingShowsFix_AndPolicyRowShowsDetail()
    {
        await ScanAsync(WafFlowKind.ApplicationGateway);
        var cut = Render<GradesStep>(p => p.Add(x => x.Flow, WafFlowKind.ApplicationGateway));

        Assert.Equal("F", cut.Find(".overall .grade-badge.lg").TextContent);
        Assert.Contains("legacy inline", cut.Markup);

        Assert.Empty(cut.FindAll(".fix"));
        cut.FindAll("ul.findings li button.link")[0].Click();
        Assert.Single(cut.FindAll(".fix"));

        Assert.Empty(cut.FindAll(".policy-detail"));
        cut.FindAll("tr.policy-row")[0].Click();
        var detail = cut.Find(".policy-detail");
        Assert.Contains("Settings", detail.TextContent);
        Assert.Contains("Managed rule sets", detail.TextContent);
    }

    [Fact]
    public async Task LogsStep_RunsDemoAnalysis_AndShowsAssessment()
    {
        await ScanAsync(WafFlowKind.FrontDoor);
        var cut = Render<LogsStep>(p => p.Add(x => x.Flow, WafFlowKind.FrontDoor));

        Assert.NotEmpty(cut.FindAll("select option"));
        Assert.Empty(cut.FindAll("article.activity"));

        await cut.Find("button.btn-primary").ClickAsync(new());
        cut.WaitForState(() => cut.FindAll("article.activity").Count > 0, TimeSpan.FromSeconds(5));

        Assert.Contains("Alert assessment", cut.Markup);
        Assert.Contains("Likely real attack", cut.Markup);
        Assert.Contains("Possible false positive", cut.Markup);
        Assert.NotNull(Flows.State.For(WafFlowKind.FrontDoor).LogAnalysis);

        // Fix script modal opens with a generated script.
        cut.FindAll("article.activity button.btn")[0].Click();
        Assert.Contains("generated by RateMyWAF", cut.Find("pre.script").TextContent);
    }

    [Fact]
    public async Task WafFlow_FallsBackToScopeWhenThereIsNoScan()
    {
        var cut = Render<WafFlow>(p => p.Add(x => x.Flow, WafFlowKind.FrontDoor).Add(x => x.Step, "grades"));
        Assert.Contains("Choose what to scan", cut.Markup);

        await ScanAsync(WafFlowKind.FrontDoor);
        var grades = Render<WafFlow>(p => p.Add(x => x.Flow, WafFlowKind.FrontDoor).Add(x => x.Step, "grades"));
        Assert.Contains("Findings", grades.Markup);
        Assert.DoesNotContain("Choose what to scan", grades.Markup);
    }

    [Fact]
    public void ScopeStep_DemoMode_ListsSampleSubscriptionsAndCounts()
    {
        var cut = Render<ScopeStep>(p => p.Add(x => x.Flow, WafFlowKind.ApplicationGateway));
        cut.WaitForState(() => cut.FindAll("li.sub-row").Count == 2, TimeSpan.FromSeconds(5));
        cut.WaitForAssertion(() => Assert.Contains("Application Gateways", cut.Find(".sub-count").TextContent), TimeSpan.FromSeconds(5));

        Assert.True(cut.Find("button.btn-primary").HasAttribute("disabled"));
        cut.FindAll("li.sub-row input")[0].Change(true);
        Assert.False(cut.Find("button.btn-primary").HasAttribute("disabled"));
        Assert.Contains("Scan 1 subscription", cut.Find("button.btn-primary").TextContent);
    }
}
