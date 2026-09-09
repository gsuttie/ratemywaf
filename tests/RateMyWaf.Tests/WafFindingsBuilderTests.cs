using RateMyWaf.Models;
using RateMyWaf.Services;
using Xunit;

namespace RateMyWaf.Tests;

public class WafFindingsBuilderTests
{
    [Fact]
    public void EveryFindingHasAFix_AndIsOrderedBySeverity()
    {
        var fd = DemoDataService.FrontDoorEstate();
        var gw = DemoDataService.AppGatewayEstate();
        var findings = WafFindingsBuilder.Build(fd).Concat(WafFindingsBuilder.Build(gw)).ToList();

        Assert.NotEmpty(findings);
        Assert.All(findings, f => Assert.False(string.IsNullOrWhiteSpace(f.Fix)));
        Assert.All(findings, f => Assert.NotEqual(WafFindingsBuilder.FixFor("nonexistent"), f.Fix));

        var fdFindings = WafFindingsBuilder.Build(fd);
        var order = fdFindings.Select(f => WafFindingsBuilder.SeverityOrder(f.Severity)).ToList();
        Assert.Equal(order.OrderBy(o => o), order);
    }

    [Fact]
    public void FrontDoor_ProducesExpectedCategories()
    {
        var categories = WafFindingsBuilder.Build(DemoDataService.FrontDoorEstate()).Select(f => f.Category).ToHashSet();

        Assert.Contains("Unprotected domains", categories);   // marketing profile, events.contoso.com uncovered
        Assert.Contains("Unprotected endpoint", categories);  // classic intranet endpoint
        Assert.Contains("WAF logging disabled", categories);  // classic front door
        Assert.Contains("Outdated rule set", categories);     // DRS 1.1
        Assert.Contains("Detection mode", categories);
        Assert.Contains("No managed rules", categories);
        Assert.Contains("Policy disabled", categories);
        Assert.Contains("Unassociated policy", categories);
    }

    [Fact]
    public void AppGateway_ProducesExpectedCategories()
    {
        var findings = WafFindingsBuilder.Build(DemoDataService.AppGatewayEstate());
        var categories = findings.Select(f => f.Category).ToHashSet();

        Assert.Contains("No WAF SKU", categories);
        Assert.Contains("Legacy WAF config", categories);
        Assert.Contains("Outdated rule set", categories);
        Assert.Contains("Detection mode", categories);
        Assert.Contains("Unassociated policy", categories);
        Assert.DoesNotContain(findings, f => f.Category == "Unassociated policy" && f.ResourceName.Contains("inline"));
        Assert.Equal("High", findings.Single(f => f.Category == "No WAF SKU").Severity);
    }

    [Fact]
    public void AppGateway_UnprotectedListeners_IsHigh()
    {
        const string id = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/applicationGateways/gw";
        var result = new WafScanResult
        {
            AppGateways =
            [
                new AppGatewayInfo
                {
                    Id = id, Name = "gw", Tier = "WAF_v2",
                    Listeners = [new() { Name = "a", HostName = "a.contoso.com", WafPolicyId = "/p" }, new() { Name = "b", HostName = "b.contoso.com" }]
                }
            ]
        };

        var f = Assert.Single(WafFindingsBuilder.Build(result));
        Assert.Equal("Unprotected listeners", f.Category);
        Assert.Equal("High", f.Severity);
        Assert.Contains("b.contoso.com", f.Message);
    }

    [Fact]
    public void CleanEstate_HasNoFindings()
    {
        var result = new WafScanResult
        {
            FrontDoors = [new FrontDoorInfo { Id = "/fd", Name = "fd", Kind = FrontDoorKind.Premium, AssociatedPolicyIds = ["/p"], WafLogsEnabled = true }],
            WafPolicies = [new WafPolicyInfo { Id = "/p", Name = "p", EnabledState = "Enabled", Mode = "Prevention", AssociationIds = ["/fd/securitypolicies/sp"],
                ManagedRuleSets = [new() { RuleSetType = "Microsoft_DefaultRuleSet", RuleSetVersion = "2.1", IsLatest = true }] }]
        };
        Assert.Empty(WafFindingsBuilder.Build(result));
    }
}
