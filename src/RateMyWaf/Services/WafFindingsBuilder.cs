using RateMyWaf.Models;

namespace RateMyWaf.Services;

/// <summary>Report-only findings for a scan result, each with concrete remediation guidance attached.</summary>
public static class WafFindingsBuilder
{
    public static readonly IReadOnlyDictionary<string, string> FixByCategory = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        ["Policy disabled"] = "Enable the WAF policy (Policy → Overview → set State to Enabled) so it starts inspecting traffic again.",
        ["Detection mode"] = "Once custom rules and exclusions are confirmed not to cause false positives, switch the policy from Detection to Prevention mode (Policy → Settings → Mode) so matching requests are actually blocked.",
        ["No managed rules"] = "Attach a managed rule set — the Microsoft Default Rule Set (DRS) or OWASP CRS — under Policy → Managed rules → Assign.",
        ["Outdated rule set"] = "Upgrade to the latest managed rule set version shown in the scan (Policy → Managed rules → change version). Test in Detection mode first if the policy has exclusions, since rule IDs can shift between versions.",
        ["Unassociated policy"] = "Associate this policy with a Front Door endpoint/security policy or Application Gateway, or remove it if it is no longer needed — an unused policy provides no protection.",
        ["No WAF SKU"] = "Upgrade the Application Gateway to the WAF_v2 SKU — the current tier does not support the Web Application Firewall at all.",
        ["Unprotected gateway"] = "Attach a WAF policy to this Application Gateway (Gateway → Web application firewall → Associate policy).",
        ["Unprotected listeners"] = "Attach the WAF policy at gateway level, or associate a policy with each unprotected listener (Gateway → Web application firewall → Associated resources).",
        ["Legacy WAF config"] = "Migrate from the legacy inline WAF configuration to a standalone WAF policy resource — it is easier to manage centrally and required for newer rule set versions.",
        ["WAF logging disabled"] = "Add a diagnostic setting that sends the WAF firewall logs to a Log Analytics workspace (Resource → Diagnostic settings → Add diagnostic setting → enable the WAF log category), so attacks and false positives become visible.",
        ["Unprotected endpoint"] = "Link a WAF policy to this Front Door (classic) endpoint's routing rule.",
        ["Unprotected profile"] = "Create or update a security policy on this Front Door profile associating a WAF policy with the relevant domains.",
        ["Unprotected domains"] = "Add the uncovered domains to the security policy's associations (or create a profile-level security policy) so every domain is inspected.",
    };

    public static string FixFor(string category) =>
        FixByCategory.TryGetValue(category, out var fix)
            ? fix
            : "Review this finding in the Azure Portal and adjust the WAF configuration accordingly.";

    public static List<WafFinding> Build(WafScanResult result)
    {
        var findings = new List<WafFinding>();

        void Add(string severity, string category, string message, string name, string id, string subId) =>
            findings.Add(new WafFinding
            {
                Severity = severity, Category = category, Message = message,
                ResourceName = name, ResourceId = id, SubscriptionId = subId, Fix = FixFor(category)
            });

        foreach (var policy in result.WafPolicies)
        {
            var label = policy.IsLegacyInline ? "Inline WAF configuration" : $"WAF policy '{policy.Name}'";

            if (!policy.IsEnabled)
                Add("High", "Policy disabled",
                    $"{label} is disabled — it is not inspecting any traffic.",
                    policy.Name, policy.Id, policy.SubscriptionId);

            if (policy.Mode.Equals("Detection", StringComparison.OrdinalIgnoreCase))
                Add("Info", "Detection mode",
                    $"{label} runs in Detection mode — threats are logged but not blocked.",
                    policy.Name, policy.Id, policy.SubscriptionId);

            if (policy.ManagedRuleSets.Count == 0)
                Add("Medium", "No managed rules",
                    $"{label} has no managed rule sets configured.",
                    policy.Name, policy.Id, policy.SubscriptionId);

            foreach (var rs in policy.ManagedRuleSets.Where(r => r.IsLatest == false))
                Add("Medium", "Outdated rule set",
                    $"{label} uses {rs.RuleSetType} {rs.RuleSetVersion} — the latest available version is {rs.LatestVersion}.",
                    policy.Name, policy.Id, policy.SubscriptionId);

            if (policy.AssociationIds.Count == 0 && !policy.IsLegacyInline)
                Add("Info", "Unassociated policy",
                    $"{label} is not linked to any Front Door, Application Gateway or endpoint.",
                    policy.Name, policy.Id, policy.SubscriptionId);
        }

        foreach (var gw in result.AppGateways)
        {
            if (!gw.IsWafTier)
                Add("High", "No WAF SKU",
                    $"Application Gateway '{gw.Name}' uses the {(string.IsNullOrEmpty(gw.Tier) ? "Standard" : gw.Tier)} tier, which does not support WAF.",
                    gw.Name, gw.Id, gw.SubscriptionId);
            else if (!gw.HasWaf)
                Add("High", "Unprotected gateway",
                    $"Application Gateway '{gw.Name}' is a WAF tier but has no WAF policy or configuration attached.",
                    gw.Name, gw.Id, gw.SubscriptionId);
            else
            {
                var uncovered = gw.Listeners.Where(l => string.IsNullOrEmpty(l.WafPolicyId)).ToList();
                if (uncovered.Count > 0)
                {
                    var sample = string.Join(", ", uncovered.Take(5).Select(l => l.Display));
                    var more = uncovered.Count > 5 ? $" (+{uncovered.Count - 5} more)" : "";
                    Add("High", "Unprotected listeners",
                        $"Application Gateway '{gw.Name}' has a WAF, but {uncovered.Count} of {gw.Listeners.Count} listener(s) are not covered by any WAF policy: {sample}{more}.",
                        gw.Name, gw.Id, gw.SubscriptionId);
                }
            }

            if (gw.LegacyWafPresent && gw.FirewallPolicyId is null)
                Add("Info", "Legacy WAF config",
                    $"Application Gateway '{gw.Name}' uses the legacy inline WAF configuration ({gw.LegacyRuleSetType} {gw.LegacyRuleSetVersion}, {gw.LegacyWafMode} mode) — consider migrating to a WAF policy.",
                    gw.Name, gw.Id, gw.SubscriptionId);

            if (gw.HasWaf && gw.WafLogsEnabled == false)
                Add("Medium", "WAF logging disabled",
                    $"Application Gateway '{gw.Name}' has a WAF but no diagnostic setting sends its firewall logs anywhere.",
                    gw.Name, gw.Id, gw.SubscriptionId);
        }

        foreach (var fd in result.FrontDoors)
        {
            if (fd.Kind == FrontDoorKind.Classic)
            {
                foreach (var ep in fd.Endpoints.Where(e => string.IsNullOrEmpty(e.WafPolicyId)))
                    Add("Medium", "Unprotected endpoint",
                        $"Front Door '{fd.Name}' endpoint '{ep.HostName}' has no WAF policy linked.",
                        fd.Name, fd.Id, fd.SubscriptionId);
            }
            else if (!fd.HasWafAssociation)
            {
                Add("Medium", "Unprotected profile",
                    $"Front Door profile '{fd.Name}' ({fd.SkuName}) has no WAF policy associated via a security policy.",
                    fd.Name, fd.Id, fd.SubscriptionId);
            }
            else
            {
                var uncovered = fd.Endpoints.Where(e => string.IsNullOrEmpty(e.WafPolicyId)).ToList();
                if (uncovered.Count > 0)
                {
                    var sample = string.Join(", ", uncovered.Take(5).Select(e => e.Display));
                    var more = uncovered.Count > 5 ? $" (+{uncovered.Count - 5} more)" : "";
                    Add("High", "Unprotected domains",
                        $"Front Door profile '{fd.Name}' has a WAF, but {uncovered.Count} of {fd.Endpoints.Count} domain(s) are not covered by any WAF security policy: {sample}{more}.",
                        fd.Name, fd.Id, fd.SubscriptionId);
                }
            }

            if (fd.HasWafAssociation && fd.WafLogsEnabled == false)
                Add("Medium", "WAF logging disabled",
                    $"Front Door '{fd.Name}' has a WAF policy but no diagnostic setting sends its firewall logs anywhere.",
                    fd.Name, fd.Id, fd.SubscriptionId);
        }

        return findings
            .OrderBy(f => SeverityOrder(f.Severity))
            .ThenBy(f => f.ResourceName, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    public static int SeverityOrder(string severity) => severity switch { "High" => 0, "Medium" => 1, _ => 2 };
}
