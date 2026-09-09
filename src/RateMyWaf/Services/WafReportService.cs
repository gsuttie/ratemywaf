using RateMyWaf.Models;
using RateMyWaf.Services.Reports;

namespace RateMyWaf.Services;

/// <summary>Everything the reports need that isn't in the scan / log analysis results themselves.</summary>
public sealed class WafReportContext
{
    public WafFlowKind Flow { get; init; }
    public string CustomerName { get; init; } = "";
    public string TenantName { get; init; } = "";
    public string ReportAuthor { get; init; } = "";
    public DateTime ScanDate { get; init; } = DateTime.Now;
    public List<string> SubscriptionLines { get; init; } = new();
    public WafScanResult? Scan { get; init; }
    public WafLogAnalysis? LogAnalysis { get; init; }
}

/// <summary>Builds the summary and detailed-findings reports (as a ReportDoc) for one flow.</summary>
public static class WafReportService
{
    public static byte[] SummaryDocx(WafReportContext ctx) => DocxReportRenderer.Render(BuildSummary(ctx));
    public static byte[] FindingsDocx(WafReportContext ctx) => DocxReportRenderer.Render(BuildFindings(ctx));
    public static string SummaryHtml(WafReportContext ctx) => HtmlReportRenderer.Render(BuildSummary(ctx));
    public static string FindingsHtml(WafReportContext ctx) => HtmlReportRenderer.Render(BuildFindings(ctx));

    public static string FileName(WafReportContext ctx, bool findings)
    {
        var scope = ctx.Flow == WafFlowKind.FrontDoor ? "FrontDoor" : "AppGateway";
        var customer = string.Concat((ctx.CustomerName ?? "").Where(c => char.IsLetterOrDigit(c) || c is '-' or '_'));
        if (string.IsNullOrEmpty(customer)) customer = "WAF";
        return $"{customer}-{scope}-WAF-{(findings ? "Findings" : "Summary")}-{ctx.ScanDate:yyyyMMdd}.docx";
    }

    // ── Summary report ───────────────────────────────────────────────────────

    public static ReportDoc BuildSummary(WafReportContext ctx)
    {
        var product = ctx.Flow.Label();
        var scan = ctx.Scan;
        var la = ctx.LogAnalysis;
        var policies = scan?.WafPolicies ?? [];
        var findings = scan?.Findings ?? [];

        int currentRuleSets = policies.Sum(p => p.ManagedRuleSets.Count(r => r.IsLatest == true));
        int outdatedRuleSets = policies.Sum(p => p.ManagedRuleSets.Count(r => r.IsLatest == false));
        int unprotected = (scan?.AppGateways.Count(g => !g.HasWaf) ?? 0) + (scan?.FrontDoors.Count(f => !f.HasWafAssociation) ?? 0);
        int loggingGaps = (scan?.AppGateways.Count(g => g.WafLogsEnabled == false) ?? 0) + (scan?.FrontDoors.Count(f => f.WafLogsEnabled == false) ?? 0);

        var doc = new ReportDoc { Title = $"{product} WAF — Summary Report" };

        doc.H1("1. Document information");
        DocInfo(doc, ctx);

        doc.H1("2. Executive summary");
        if (scan is null)
        {
            doc.P("No scan data was available when this report was generated — run a scan to populate the estate sections.");
        }
        else
        {
            var high = findings.Count(f => f.Severity == "High");
            var medium = findings.Count(f => f.Severity == "Medium");
            var info = findings.Count(f => f.Severity == "Info");
            doc.P($"The scan covered {ctx.SubscriptionLines.Count} subscription(s) and found {scan.EdgeCount} {ctx.Flow.PluralLabel()} " +
                  $"and {policies.Count} WAF polic{(policies.Count == 1 ? "y" : "ies")}. " +
                  $"It produced {findings.Count} finding(s): {high} High, {medium} Medium and {info} Info.");
            var concerns = new List<string>();
            if (unprotected > 0) concerns.Add($"{unprotected} resource(s) have no WAF protection");
            if (outdatedRuleSets > 0) concerns.Add($"{outdatedRuleSets} managed rule set(s) are not on the latest version");
            if (loggingGaps > 0) concerns.Add($"{loggingGaps} resource(s) do not ship WAF logs to any destination");
            if (concerns.Count > 0) doc.P($"The most significant gaps: {string.Join("; ", concerns)}.");
        }
        if (la is { LogsQueryable: true })
            doc.P($"WAF logs for {product} '{la.TargetName}' ({string.Join(", ", la.PolicyNames)}) were analysed over the {la.TimeRangeLabel}: " +
                  $"{la.TotalEvents} WAF event(s) across {la.DistinctRules} rule(s) — {la.BlockedCount} blocked, {la.LoggedCount} logged, " +
                  $"{la.AllowedCount} allowed, {la.RedirectedCount} redirected. {Classified(la)}");
        doc.Note("This report is the output of a read-only scan; no changes were made to any Azure resource.");

        doc.H1($"3. {product} security rating");
        RatingSection(doc, ctx);

        doc.H1("4. WAF estate overview");
        doc.Table(["Metric", "Value"],
        [
            [ctx.Flow.PluralLabel(), Count(scan, scan?.EdgeCount ?? 0)],
            ["WAF policies", Count(scan, policies.Count)],
            ["Managed rule sets on the latest version", Count(scan, currentRuleSets)],
            ["Outdated managed rule sets", Count(scan, outdatedRuleSets)],
            ["Resources without WAF protection", Count(scan, unprotected)],
            ["Resources without WAF logging", Count(scan, loggingGaps)],
            ["Total findings", Count(scan, findings.Count)],
        ], "No scan data available.");

        doc.H1("5. Findings summary");
        doc.Table(["Severity", "Category", "Finding", "Resource"],
            findings.OrderBy(f => WafFindingsBuilder.SeverityOrder(f.Severity)).Select(f => new[] { f.Severity, f.Category, f.Message, f.ResourceName }).ToList(),
            scan is null ? "No scan data available." : "No findings — the WAF estate matches the checks performed.",
            findings.Select(f => new string?[] { SeverityColor(f.Severity), null, null, null }).ToList());

        doc.H1("6. Rule set compliance");
        doc.Table(["Policy", "Rule set", "In use", "Latest", "Status"],
            policies.SelectMany(p => p.ManagedRuleSets.Select(rs => new[]
            {
                p.Name, rs.RuleSetType, rs.RuleSetVersion, rs.LatestVersion ?? "Unknown",
                rs.IsLatest switch { true => "Current", false => "Outdated", null => "Unknown" }
            })).ToList(),
            scan is null ? "No scan data available." : "No managed rule sets found.");

        doc.H1("7. WAF logging");
        var loggingRows = new List<string[]>();
        foreach (var fd in scan?.FrontDoors ?? [])
            loggingRows.Add([fd.Name, $"Front Door ({fd.SkuName})", LogState(fd.WafLogsEnabled), Destinations(fd.LogDestinations)]);
        foreach (var gw in scan?.AppGateways ?? [])
            loggingRows.Add([gw.Name, $"Application Gateway ({gw.Tier})", LogState(gw.WafLogsEnabled), Destinations(gw.LogDestinations)]);
        doc.Table(["Resource", "Type", "WAF logs", "Destination(s)"], loggingRows,
            scan is null ? "No scan data available." : $"No {ctx.Flow.PluralLabel()} in scope.");

        doc.H1("8. Recommendations");
        var recs = new List<string>();
        foreach (var f in findings.Where(f => f.Severity == "High").Take(5))
            recs.Add($"{f.Message} ({f.ResourceName})");
        if (outdatedRuleSets > 0)
            recs.Add($"Upgrade the {outdatedRuleSets} outdated managed rule set(s) to the latest version after validating against representative traffic.");
        if (loggingGaps > 0)
            recs.Add($"Enable WAF diagnostic logging on the {loggingGaps} resource(s) currently not shipping logs, so attacks and false positives become visible.");
        if (unprotected > 0)
            recs.Add($"Attach a WAF policy to the {unprotected} unprotected resource(s).");
        if (la is not null)
            recs.AddRange(la.RuleActivities
                .OrderBy(r => WafLogAnalysisService.ClassificationOrder(r.Classification))
                .SelectMany(r => r.Recommendations).Distinct().Take(5));
        if (recs.Count == 0)
            recs.Add("No immediate actions required — continue periodic scans and log reviews to maintain the current posture.");
        doc.Bullets(recs.Distinct().Take(10));
        doc.Note("All recommendations are advisory. RateMyWAF does not modify WAF policies, rule sets, exclusions or diagnostic settings.");

        return doc;
    }

    // ── Detailed findings report ─────────────────────────────────────────────

    public static ReportDoc BuildFindings(WafReportContext ctx)
    {
        var product = ctx.Flow.Label();
        var scan = ctx.Scan;
        var la = ctx.LogAnalysis;
        var doc = new ReportDoc { Title = $"{product} WAF — Detailed Findings" };

        doc.H1("1. Document information");
        DocInfo(doc, ctx);

        doc.H1($"2. {product} security rating");
        RatingSection(doc, ctx);

        doc.H1("3. Detailed findings");
        if (scan is null)
            doc.P("No scan data was available when this report was generated.");
        else if (scan.Findings.Count == 0)
            doc.P("No findings — the WAF estate matches the checks performed.");
        else
            foreach (var group in scan.Findings.GroupBy(f => f.Severity).OrderBy(g => WafFindingsBuilder.SeverityOrder(g.Key)))
            {
                doc.P($"{group.Key} ({group.Count()})", bold: true, color: SeverityColor(group.Key));
                doc.Bullets(group.Select(f => $"{f.Category}: {f.Message} — {f.ResourceName}. Fix: {f.Fix}"));
            }

        doc.H1("4. WAF policy inventory");
        if (scan is null) doc.P("No scan data available.");
        else if (scan.WafPolicies.Count == 0) doc.P("No WAF policies in scope.");
        else
            foreach (var p in scan.WafPolicies.OrderBy(p => p.Name, StringComparer.OrdinalIgnoreCase))
            {
                doc.P($"{p.Name} ({p.KindLabel})", bold: true);
                var settings = new List<string> { $"State: {Fallback(p.EnabledState, "Unknown")} • Mode: {Fallback(p.Mode, "Unknown")}" };
                if (!string.IsNullOrEmpty(p.RequestBodyCheck)) settings.Add($"Request body check: {p.RequestBodyCheck}");
                if (p.MaxRequestBodySizeKb is { } mb) settings.Add($"Max request body: {mb} KB");
                if (p.FileUploadLimitMb is { } fu) settings.Add($"File upload limit: {fu} MB");
                if (p.ExclusionCount > 0) settings.Add($"Policy-level exclusions: {p.ExclusionCount}");
                doc.P(string.Join(" • ", settings));

                if (p.ManagedRuleSets.Count > 0)
                    doc.Bullets(p.ManagedRuleSets.Select(rs =>
                    {
                        var status = rs.IsLatest switch { true => "current", false => $"outdated — latest is {rs.LatestVersion}", null => "latest unknown" };
                        var extras = new List<string>();
                        if (rs.DisabledRuleCount > 0) extras.Add($"{rs.DisabledRuleCount} rule(s) disabled");
                        if (rs.ActionOverrideCount > 0) extras.Add($"{rs.ActionOverrideCount} action override(s)");
                        if (rs.ExclusionCount > 0) extras.Add($"{rs.ExclusionCount} exclusion(s)");
                        return $"Rule set {rs.RuleSetType} {rs.RuleSetVersion} — {status}{(extras.Count > 0 ? $" ({string.Join(", ", extras)})" : "")}";
                    }));

                if (p.CustomRules.Count > 0)
                    doc.Bullets(p.CustomRules.OrderBy(r => r.Priority).Select(r =>
                        $"Custom rule '{r.Name}' (priority {r.Priority}, {r.RuleType}, action {r.Action}, {r.EnabledState})" +
                        (r.Conditions.Count > 0 ? $": {string.Join("; ", r.Conditions)}" : "")));

                doc.P(p.Associations.Count > 0
                    ? $"Protects: {string.Join(", ", p.Associations.Select(a => a.Display).Distinct())}"
                    : "Not linked to any resource.");
            }

        doc.H1("5. Protected resources");
        if (scan is null) doc.P("No scan data available.");
        else
        {
            var items = new List<string>();
            foreach (var fd in scan.FrontDoors.OrderBy(f => f.Name, StringComparer.OrdinalIgnoreCase))
            {
                var names = scan.WafPolicies.Where(p => fd.AssociatedPolicyIds.Contains(p.Id, StringComparer.OrdinalIgnoreCase)
                                                       || fd.Endpoints.Any(e => p.Id.Equals(e.WafPolicyId, StringComparison.OrdinalIgnoreCase)))
                    .Select(p => p.Name).Distinct().ToList();
                var protection = fd.HasWafAssociation
                    ? (names.Count > 0 ? $"WAF policy: {string.Join(", ", names)}" : "WAF policy attached")
                    : "NO WAF POLICY";
                var surfaces = fd.Endpoints.Count > 0
                    ? $" — {fd.Endpoints.Count(e => e.WafPolicyId is not null)} of {fd.Endpoints.Count} domain(s) covered"
                    : "";
                items.Add($"{fd.Name} (Front Door, {fd.SkuName}) — {protection}{surfaces} — WAF logs {LogState(fd.WafLogsEnabled)}{DestSuffix(fd.LogDestinations)}");
            }
            foreach (var gw in scan.AppGateways.OrderBy(g => g.Name, StringComparer.OrdinalIgnoreCase))
            {
                var protection = gw.FirewallPolicyId is not null ? $"WAF policy: {Azure.Json.LastSegment(gw.FirewallPolicyId)}"
                    : gw.LegacyWafConfigured ? $"legacy inline WAF ({gw.LegacyWafMode} {gw.LegacyRuleSetType} {gw.LegacyRuleSetVersion})"
                    : gw.Listeners.Any(l => l.WafPolicyId is not null) ? "per-listener WAF policies"
                    : gw.IsWafTier ? "WAF tier but NO policy" : "NO WAF (standard tier)";
                var surfaces = gw.Listeners.Count > 0
                    ? $" — {gw.Listeners.Count(l => l.WafPolicyId is not null)} of {gw.Listeners.Count} listener(s) covered"
                    : "";
                items.Add($"{gw.Name} (Application Gateway, {gw.Tier}) — {protection}{surfaces} — WAF logs {LogState(gw.WafLogsEnabled)}{DestSuffix(gw.LogDestinations)}");
            }
            if (items.Count == 0) doc.P($"No {ctx.Flow.PluralLabel()} in scope.");
            else doc.Bullets(items);
        }

        doc.H1("6. WAF log analysis");
        doc.P("Scope: " + (la is null
            ? "no log analysis has been run"
            : $"{product} '{la.TargetName}', polic{(la.PolicyNames.Count == 1 ? "y" : "ies")} {string.Join(", ", la.PolicyNames)}, {la.TimeRangeLabel}"));

        doc.H2("6.1 Activity summary");
        if (la is null) doc.P("No log analysis available — run one from the Logs step.");
        else if (!la.LogsQueryable) doc.P($"WAF logs could not be queried: {la.QueryError}");
        else
        {
            doc.P($"{la.TotalEvents} WAF event(s) in the {la.TimeRangeLabel}: {la.BlockedCount} blocked, {la.LoggedCount} logged, " +
                  $"{la.AllowedCount} allowed and {la.RedirectedCount} redirected, across {la.DistinctRules} distinct rule(s). {Classified(la)}");
            foreach (var w in la.Warnings) doc.P($"Warning: {w}");
        }

        doc.H2("6.2 Changes versus the previous period");
        if (la is not { LogsQueryable: true }) doc.P("Not available.");
        else if (la.Changes.Count == 0) doc.P("No significant changes — the same rules triggered at similar volumes in both periods.");
        else doc.Bullets(la.Changes.Select(c => $"{c.ChangeType}: {c.RuleName} — {c.Description}"));

        doc.H2("6.3 Alert assessment");
        if (la is not { LogsQueryable: true } || la.RuleActivities.Count == 0)
            doc.P(la is { LogsQueryable: true } ? "No rule activity was recorded in the analysis window." : "Not available.");
        else
            foreach (var r in la.RuleActivities)
            {
                doc.P($"{r.Classification} — {r.RuleName} (policy {Fallback(r.PolicyName, "n/a")})", bold: true, color: ClassificationColor(r.Classification));
                doc.P(r.Explanation);
                var evidence = new List<string>();
                if (r.SampleIps.Count > 0) evidence.Add($"Sample IPs: {string.Join(", ", r.SampleIps)}");
                if (r.SampleUris.Count > 0) evidence.Add($"Sample URIs: {string.Join(" ; ", r.SampleUris.Take(3))}");
                if (!string.IsNullOrEmpty(r.SampleMatchVariable) || !string.IsNullOrEmpty(r.SampleMatchData))
                    evidence.Add($"Match detail: {r.SampleMatchVariable} {r.SampleMatchData}".Trim());
                if (evidence.Count > 0) doc.Bullets(evidence);
            }

        doc.H2("6.4 Tuning and exclusion recommendations");
        var withRecs = la is { LogsQueryable: true } ? la.RuleActivities.Where(r => r.Recommendations.Count > 0).ToList() : [];
        if (withRecs.Count == 0)
            doc.P(la is { LogsQueryable: true } ? "No tuning or exclusion recommendations arose from the analysed window." : "Not available.");
        else
            foreach (var r in withRecs)
            {
                doc.P($"{r.RuleName} ({r.Classification})", bold: true);
                doc.Bullets(r.Recommendations);
            }

        return doc;
    }

    // ── Shared sections ──────────────────────────────────────────────────────

    private static void DocInfo(ReportDoc doc, WafReportContext ctx) =>
        doc.Table(null,
        [
            ["Customer", Fallback(ctx.CustomerName, "Unknown")],
            ["Prepared by", Fallback(ctx.ReportAuthor, "RateMyWAF")],
            ["Scan date", ctx.ScanDate.ToString("yyyy-MM-dd HH:mm")],
            ["Tenant", Fallback(ctx.TenantName, "Unknown")],
            ["Subscriptions in scope", ctx.SubscriptionLines.Count > 0 ? string.Join("\n", ctx.SubscriptionLines) : "None"],
            ["Generated by", $"RateMyWAF — {ctx.Flow.Label()} WAF assessment (read-only)"],
        ], "", firstColHeader: true);

    private static void RatingSection(ReportDoc doc, WafReportContext ctx)
    {
        var ratings = ctx.Scan?.Ratings ?? [];
        var product = ctx.Flow.Label();
        if (ratings.Count == 0)
        {
            doc.P(ctx.Scan is null ? "No scan data available." : $"No {ctx.Flow.PluralLabel()} in scope — no rating produced.");
            doc.Legend();
            return;
        }

        var worst = WafRatingService.Worst(ratings)!;
        var avg = (int)Math.Round(ratings.Average(r => r.Score));
        doc.Grade(worst.Grade, worst.GradeLabel, ratings.Count == 1
            ? $"{product} '{worst.TargetName}' scores {worst.Score}/100." + (worst.CapReason is null ? "" : $" Grade capped: {worst.CapReason}")
            : $"Set by the weakest {product} '{worst.TargetName}' ({worst.Score}/100). Average score {avg}/100 across {ratings.Count} {ctx.Flow.PluralLabel()}.");

        var rows = new List<string[]>();
        var colors = new List<string?[]>();
        foreach (var r in ratings.OrderBy(r => r.TargetName, StringComparer.OrdinalIgnoreCase))
        {
            rows.Add([r.TargetName, $"{r.Grade} — {r.GradeLabel}", $"{r.Score}/100", r.CapReason ?? r.Improvements.FirstOrDefault()?.Action ?? "No gaps identified."]);
            var c = WafRatingService.ColorForGrade(r.Grade);
            colors.Add([null, c, c, null]);
        }
        doc.Table([product, "Grade", "Score", "Biggest gap"], rows, "", colors);

        doc.P("Scoring model: WAF coverage & state 30 · Prevention mode 20 · Managed rule protection 20 · Logging & monitoring 15 · Tuning hygiene 10 · Hardening extras 5. " +
              "Grade bands: A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 45, E ≥ 30, F < 30. Caps: no enabled WAF = F; partially unprotected = max D; detection-only = max C; no managed rules = max C; logging off = max B.");
        doc.Legend();

        var any = false;
        foreach (var r in ratings.OrderByDescending(r => r.Grade, StringComparer.Ordinal).ThenBy(r => r.TargetName, StringComparer.OrdinalIgnoreCase))
        {
            if (r.Improvements.Count == 0) continue;
            any = true;
            doc.P($"{r.TargetName} (grade {r.Grade}, {r.Score}/100)", bold: true, color: WafRatingService.ColorForGrade(r.Grade));
            doc.Bullets(r.Improvements.Select(i => $"+{i.PointsGained} pts — {i.Action}" +
                (WafRatingService.WorstGrade(i.ResultingGrade, r.Grade) != i.ResultingGrade ? $" (raises the grade to {i.ResultingGrade})" : "")));
        }
        if (!any) doc.P($"No improvements required — every {product} in scope earns full marks.");
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static string Fallback(string value, string fallback) => string.IsNullOrWhiteSpace(value) ? fallback : value;
    private static string Count(WafScanResult? scan, int count) => scan is null ? "—" : count.ToString();
    private static string LogState(bool? enabled) => enabled switch { true => "enabled", false => "disabled", null => "unknown" };
    private static string Destinations(List<string> d) => d.Count > 0 ? string.Join(", ", d) : "None";
    private static string DestSuffix(List<string> d) => d.Count > 0 ? $" → {string.Join(", ", d)}" : "";

    public static string SeverityColor(string severity) => severity switch
    {
        "High" => "#D32F2F",
        "Medium" => "#F57C00",
        _ => "#1976D2"
    };

    public static string ClassificationColor(string classification) => classification switch
    {
        "Likely real attack" => "#D32F2F",
        "Possible false positive" => "#F57C00",
        _ => "#1976D2"
    };

    private static string Classified(WafLogAnalysis la)
    {
        if (la.RuleActivities.Count == 0) return "";
        var parts = la.RuleActivities.GroupBy(r => r.Classification)
            .OrderBy(g => WafLogAnalysisService.ClassificationOrder(g.Key))
            .Select(g => $"{g.Count()} rule(s) classified '{g.Key}'");
        return $"Assessment: {string.Join(", ", parts)}.";
    }
}
