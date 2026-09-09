using RateMyWaf.Models;

namespace RateMyWaf.Services;

/// <summary>
/// Pure, deterministic A-F rating calculator for a Front Door's or Application Gateway's WAF setup.
/// The weights follow Microsoft's Azure WAF best practices, most important first:
/// being protected at all, actually blocking, up-to-date managed rules, visibility, tuning quality, hardening extras.
///
/// 100 points across six categories, mapped to grades
/// (A >= 90, B >= 75, C >= 60, D >= 45, E >= 30, F below), with hard caps:
/// no enabled WAF policy = F; some surfaces (endpoints/domains/listeners) without any WAF = max D
/// (no WAF at all is worse than a detection-only one); Detection-only = max C;
/// no managed rule set = max C; WAF logging off = max B.
/// </summary>
public static class WafRatingService
{
    // Category weights (sum = 100).
    public const int CoveragePts   = 30;
    public const int PreventionPts = 20;
    public const int ManagedPts    = 20; // DRS 10 + latest 5 + bot manager 5
    public const int LoggingPts    = 15; // enabled 10 + Log Analytics 5
    public const int HygienePts    = 10;
    public const int ExtrasPts     = 5;  // rate limit 2 + geo/IP 1 + body inspection 2

    public const string CoverageCategory   = "WAF coverage & state";
    public const string PreventionCategory = "Prevention mode";
    public const string ManagedCategory    = "Managed rule protection";
    public const string LoggingCategory    = "Logging & monitoring";
    public const string HygieneCategory    = "Tuning hygiene";
    public const string ExtrasCategory     = "Hardening extras";

    /// <summary>Computes and stores one rating per Front Door / Application Gateway on the scan result.</summary>
    public static void RateAll(WafScanResult result) =>
        result.Ratings = result.FrontDoors
            .Select(fd => RateFrontDoor(fd, result.WafPolicies))
            .Concat(result.AppGateways.Select(gw => RateAppGateway(gw, result.WafPolicies)))
            .ToList();

    /// <summary>Grade letter for a raw 0-100 score, before caps.</summary>
    public static string GradeForScore(int score) => score switch
    {
        >= 90 => "A",
        >= 75 => "B",
        >= 60 => "C",
        >= 45 => "D",
        >= 30 => "E",
        _ => "F"
    };

    public static string LabelForGrade(string grade) => grade switch
    {
        "A" => "Excellent",
        "B" => "Good",
        "C" => "Average",
        "D" => "Below Average",
        "E" => "Poor",
        _ => "Unacceptable"
    };

    /// <summary>Traffic-light colour for a grade (hex, with leading '#'). Green to dark red.</summary>
    public static string ColorForGrade(string grade) => grade switch
    {
        "A" => "#388E3C",
        "B" => "#7CB342",
        "C" => "#FBC02D",
        "D" => "#F57C00",
        "E" => "#E64A19",
        _ => "#C62828"
    };

    /// <summary>The A-F legend shown in the app and in the reports.</summary>
    public static readonly (string Grade, string Label, string Description)[] Legend =
    [
        ("A", "EXCELLENT", "Outstanding — exceeds expectations"),
        ("B", "GOOD", "Above average — meets most expectations"),
        ("C", "AVERAGE", "Satisfactory — meets basic expectations"),
        ("D", "BELOW AVERAGE", "Below expectations — needs improvement"),
        ("E", "POOR", "Far below expectations — significant improvement needed"),
        ("F", "UNACCEPTABLE", "Unacceptable — does not meet minimum requirements"),
    ];

    /// <summary>The worse (further down the alphabet) of two grades.</summary>
    public static string WorstGrade(string a, string b) =>
        string.CompareOrdinal(a, b) >= 0 ? a : b;

    /// <summary>Overall grade for a set of ratings: the weakest resource sets the grade.</summary>
    public static WafRating? Worst(IEnumerable<WafRating> ratings) =>
        ratings.OrderByDescending(r => r.Grade, StringComparer.Ordinal).ThenBy(r => r.Score).FirstOrDefault();

    // ── Public entry points ──────────────────────────────────────────────────

    public static WafRating RateFrontDoor(FrontDoorInfo fd, IReadOnlyList<WafPolicyInfo> allPolicies) =>
        Rate(RatingSubject.For(fd), allPolicies);

    public static WafRating RateAppGateway(AppGatewayInfo gw, IReadOnlyList<WafPolicyInfo> allPolicies) =>
        Rate(RatingSubject.For(gw), allPolicies);

    // ── Rating subject: what differs between a Front Door and an App Gateway ─

    internal sealed class RatingSubject
    {
        public required WafFlowKind Kind { get; init; }
        public required string Id { get; init; }
        public required string Name { get; init; }
        public required string SubscriptionId { get; init; }
        public required string TypeLabel { get; init; }

        /// <summary>"endpoint", "domain" or "listener".</summary>
        public required string Unit { get; init; }
        public required List<WafSurfaceInfo> Surfaces { get; init; }
        public required Func<WafPolicyInfo, bool> IsLinked { get; init; }

        public required Func<int, int, string> CoverageDetail { get; init; }
        public required string NoSurfaceCapReason { get; init; }
        public required Func<List<WafPolicyInfo>, List<WafPolicyInfo>, string> NoSurfaceDetail { get; init; }
        public required string AssociateAction { get; init; }
        public required string EnableDrsAction { get; init; }

        public bool? WafLogsEnabled { get; init; }
        public required List<string> LogDestinations { get; init; }

        /// <summary>Set when the resource cannot host a WAF at all (non-WAF Application Gateway tier).</summary>
        public string? WafUnsupportedReason { get; init; }
        public string? WafUnsupportedAction { get; init; }

        public static RatingSubject For(FrontDoorInfo fd)
        {
            var unit = fd.Kind == FrontDoorKind.Classic ? "endpoint" : "domain";
            var premiumNote = fd.SkuName.Contains("Standard", StringComparison.OrdinalIgnoreCase)
                ? " (requires upgrading the Front Door to Premium)"
                : "";
            return new RatingSubject
            {
                Kind = WafFlowKind.FrontDoor,
                Id = fd.Id,
                Name = fd.Name,
                SubscriptionId = fd.SubscriptionId,
                TypeLabel = "Front Door",
                Unit = unit,
                Surfaces = fd.Endpoints,
                IsLinked = p =>
                    p.AssociationIds.Any(id => MatchesResource(id, fd.Id)) ||
                    fd.AssociatedPolicyIds.Any(pid => pid.Equals(p.Id, StringComparison.OrdinalIgnoreCase)) ||
                    fd.Endpoints.Any(ep => p.Id.Equals(ep.WafPolicyId, StringComparison.OrdinalIgnoreCase)),
                CoverageDetail = (covered, total) => fd.Kind == FrontDoorKind.Classic
                    ? $"{covered} of {total} endpoint(s) have an enabled WAF policy."
                    : $"{covered} of {total} domain(s) (endpoints + custom domains) are covered by an enabled WAF policy.",
                NoSurfaceCapReason = "No enabled WAF policy is protecting this Front Door.",
                NoSurfaceDetail = (enabled, linked) => enabled.Count > 0
                    ? $"{enabled.Count} enabled WAF polic{(enabled.Count == 1 ? "y is" : "ies are")} associated: {string.Join(", ", enabled.Select(p => p.Name))}."
                    : linked.Count > 0
                        ? "A WAF policy is associated but it is disabled."
                        : "No WAF policy is associated with this Front Door.",
                AssociateAction = $"Associate an enabled WAF policy with '{fd.Name}' via a security policy.",
                EnableDrsAction = $"Enable the Microsoft Default Rule Set on the WAF policy{premiumNote}.",
                WafLogsEnabled = fd.WafLogsEnabled,
                LogDestinations = fd.LogDestinations,
            };
        }

        public static RatingSubject For(AppGatewayInfo gw) => new()
        {
            Kind = WafFlowKind.ApplicationGateway,
            Id = gw.Id,
            Name = gw.Name,
            SubscriptionId = gw.SubscriptionId,
            TypeLabel = "Application Gateway",
            Unit = "listener",
            Surfaces = gw.Listeners,
            IsLinked = p =>
                p.AssociationIds.Any(id => MatchesResource(id, gw.Id)) ||
                p.Id.Equals(gw.FirewallPolicyId, StringComparison.OrdinalIgnoreCase) ||
                (p.IsLegacyInline && p.Id.Equals(gw.LegacyPolicyId, StringComparison.OrdinalIgnoreCase)) ||
                gw.Listeners.Any(l => p.Id.Equals(l.WafPolicyId, StringComparison.OrdinalIgnoreCase)),
            CoverageDetail = (covered, total) => $"{covered} of {total} listener(s) are protected by an enabled WAF policy.",
            NoSurfaceCapReason = "No enabled WAF policy is protecting this Application Gateway.",
            NoSurfaceDetail = (enabled, linked) => enabled.Count > 0
                ? $"{enabled.Count} enabled WAF polic{(enabled.Count == 1 ? "y is" : "ies are")} attached: {string.Join(", ", enabled.Select(p => p.Name))}."
                : linked.Count > 0
                    ? "A WAF policy is attached but it is disabled."
                    : "No WAF policy or inline WAF configuration is attached to this Application Gateway.",
            AssociateAction = $"Attach an enabled WAF policy to '{gw.Name}' (at gateway level, or to every listener).",
            EnableDrsAction = "Enable a managed rule set (Microsoft Default Rule Set 2.1 or OWASP CRS 3.2) on the WAF policy.",
            WafLogsEnabled = gw.WafLogsEnabled,
            LogDestinations = gw.LogDestinations,
            WafUnsupportedReason = gw.IsWafTier ? null
                : $"'{gw.Name}' uses the {(string.IsNullOrEmpty(gw.Tier) ? "Standard" : gw.Tier)} tier, which does not support the Web Application Firewall.",
            WafUnsupportedAction = gw.IsWafTier ? null
                : $"Upgrade '{gw.Name}' to the WAF_v2 tier and attach an enabled WAF policy.",
        };
    }

    // ── The engine ───────────────────────────────────────────────────────────

    internal static WafRating Rate(RatingSubject s, IReadOnlyList<WafPolicyInfo> allPolicies)
    {
        var linked = s.WafUnsupportedReason is null
            ? allPolicies.Where(s.IsLinked).ToList()
            : new List<WafPolicyInfo>();
        var enabled = linked.Where(p => p.IsEnabled).ToList();
        var ruleSets = enabled.SelectMany(p => p.ManagedRuleSets).ToList();

        var rating = new WafRating
        {
            TargetKind = s.Kind,
            TargetId = s.Id,
            TargetName = s.Name,
            SubscriptionId = s.SubscriptionId
        };

        // Caps collected as (key, max grade, reason); improvements may lift one by key.
        var caps = new List<(string Key, string MaxGrade, string Reason)>();
        var improvements = new List<(WafImprovement Item, string? LiftsCapKey)>();

        void Improve(string action, int points, string? liftsCapKey = null)
        {
            if (points > 0)
                improvements.Add((new WafImprovement { Action = action, PointsGained = points }, liftsCapKey));
        }

        // ── 1. WAF coverage & state (30) ─────────────────────────────────────
        // Coverage is per surface: a WAF is only linked to the endpoints/domains/listeners it is
        // associated with, so any surface without one is completely unprotected, which is worse
        // than a detection-only WAF that at least sees the traffic. Hence the D cap below.
        var coverage = new WafRatingCategory { Name = CoverageCategory, Possible = CoveragePts };
        if (s.WafUnsupportedReason is not null)
        {
            coverage.Earned = 0;
            coverage.Details.Add(s.WafUnsupportedReason);
            caps.Add(("nowaf", "F", s.WafUnsupportedReason));
            Improve(s.WafUnsupportedAction!, CoveragePts, "nowaf");
        }
        else if (s.Surfaces.Count > 0)
        {
            var total = s.Surfaces.Count;
            var covered = s.Surfaces.Count(ep => SurfaceCovered(ep, allPolicies));
            coverage.Earned = (int)Math.Round(CoveragePts * (double)covered / total);
            if (covered > 0 && covered < total)
                coverage.Earned = Math.Clamp(coverage.Earned, 1, CoveragePts - 1);
            coverage.Details.Add(s.CoverageDetail(covered, total));

            if (covered == 0)
                caps.Add(("nowaf", "F", $"No {s.Unit} of this {s.TypeLabel} is protected by an enabled WAF policy."));
            else if (covered < total)
                caps.Add(("nowaf", "D",
                    $"{total - covered} {s.Unit}(s) have no WAF at all — an unprotected {s.Unit} is worse than a detection-only WAF."));

            if (covered < total)
                Improve($"Link an enabled WAF policy to every {s.Unit} of '{s.Name}' " +
                        $"({total - covered} {s.Unit}(s) unprotected).",
                        CoveragePts - coverage.Earned, "nowaf");
        }
        else
        {
            coverage.Earned = enabled.Count > 0 ? CoveragePts : 0;
            coverage.Details.Add(s.NoSurfaceDetail(enabled, linked));
            if (enabled.Count == 0)
            {
                caps.Add(("nowaf", "F", s.NoSurfaceCapReason));
                Improve(s.AssociateAction, CoveragePts, "nowaf");
            }
        }
        rating.Categories.Add(coverage);

        // ── 2. Prevention mode (20) ──────────────────────────────────────────
        var prevention = new WafRatingCategory { Name = PreventionCategory, Possible = PreventionPts };
        if (enabled.Count > 0)
        {
            var preventing = enabled.Where(p => p.IsPrevention).ToList();
            prevention.Earned = (int)Math.Round(PreventionPts * (double)preventing.Count / enabled.Count);
            prevention.Details.Add($"{preventing.Count} of {enabled.Count} linked polic{(enabled.Count == 1 ? "y" : "ies")} in Prevention mode.");

            var detecting = enabled.Except(preventing).Select(p => p.Name).ToList();
            if (detecting.Count > 0)
            {
                var liftsCap = preventing.Count == 0;
                if (liftsCap)
                    caps.Add(("detection", "C", "All linked policies run in Detection mode — attacks are logged but never blocked."));
                Improve($"Switch polic{(detecting.Count == 1 ? "y" : "ies")} {string.Join(", ", detecting.Select(n => $"'{n}'"))} " +
                        "to Prevention mode so threats are blocked, not just logged.",
                        PreventionPts - prevention.Earned, liftsCap ? "detection" : null);
            }
        }
        else
        {
            prevention.Details.Add("No enabled policy to assess.");
        }
        rating.Categories.Add(prevention);

        // ── 3. Managed rule protection (20) ──────────────────────────────────
        var managed = new WafRatingCategory { Name = ManagedCategory, Possible = ManagedPts };
        var drs = ruleSets.Where(IsDefaultRuleSet).ToList();
        if (drs.Count > 0)
        {
            managed.Earned += 10;
            managed.Details.Add($"Default rule set configured: {string.Join(", ", drs.Select(r => $"{r.RuleSetType} {r.RuleSetVersion}"))}.");

            var known = drs.Where(r => r.IsLatest is not null).ToList();
            if (known.Count == 0)
            {
                managed.Earned += 5;
                managed.Details.Add("Latest rule set version could not be determined — no points deducted.");
            }
            else
            {
                var latestPts = (int)Math.Round(5.0 * known.Count(r => r.IsLatest == true) / known.Count);
                managed.Earned += latestPts;
                var outdated = known.Where(r => r.IsLatest == false).ToList();
                if (outdated.Count > 0)
                {
                    managed.Details.Add($"Outdated: {string.Join(", ", outdated.Select(r => $"{r.RuleSetType} {r.RuleSetVersion} → {r.LatestVersion}"))}.");
                    Improve($"Upgrade {string.Join(", ", outdated.Select(r => $"{r.RuleSetType} to {r.LatestVersion}"))} " +
                            "(test in Detection mode first if the policy has exclusions).",
                            5 - latestPts);
                }
                else
                {
                    managed.Details.Add("All default rule sets are on the latest version.");
                }
            }
        }
        else if (enabled.Count > 0)
        {
            managed.Details.Add($"No managed default rule set (DRS) is configured — only custom rules protect this {s.TypeLabel}.");
            caps.Add(("nodrs", "C", "No managed rule set is configured — custom rules alone do not give OWASP coverage."));
            Improve(s.EnableDrsAction, 15, "nodrs");
        }
        else
        {
            managed.Details.Add("No enabled policy to assess.");
        }

        if (ruleSets.Any(r => r.RuleSetType.Contains("BotManager", StringComparison.OrdinalIgnoreCase)))
        {
            managed.Earned += 5;
            managed.Details.Add("Bot Manager rule set enabled.");
        }
        else if (enabled.Count > 0)
        {
            Improve("Enable the Microsoft Bot Manager rule set to block known malicious bots.", 5);
        }
        rating.Categories.Add(managed);

        // ── 4. Logging & monitoring (15) ─────────────────────────────────────
        var logging = new WafRatingCategory { Name = LoggingCategory, Possible = LoggingPts };
        switch (s.WafLogsEnabled)
        {
            case true:
                logging.Earned += 10;
                logging.Details.Add("WAF diagnostic logging is enabled.");
                break;
            case null:
                logging.Earned += 5;
                logging.Details.Add("Logging state could not be determined — half points awarded.");
                break;
            case false:
                logging.Details.Add("WAF diagnostic logging is disabled.");
                caps.Add(("nologs", "B", "WAF logging is disabled — no visibility of attacks or false positives."));
                Improve($"Enable WAF diagnostic logging on '{s.Name}'.", 10, "nologs");
                break;
        }
        if (s.LogDestinations.Any(d => d.StartsWith("Log Analytics", StringComparison.OrdinalIgnoreCase)))
        {
            logging.Earned += 5;
            logging.Details.Add("Logs flow to a Log Analytics workspace.");
        }
        else
        {
            logging.Details.Add("Logs do not reach a Log Analytics workspace, so they cannot be analysed.");
            Improve("Send the WAF logs to a Log Analytics workspace so they can be queried and tuned.", 5);
        }
        rating.Categories.Add(logging);

        // ── 5. Tuning hygiene (10) ───────────────────────────────────────────
        var hygiene = new WafRatingCategory { Name = HygieneCategory, Possible = HygienePts };
        var disabledRules = ruleSets.Sum(r => r.DisabledRuleCount);
        var overrides     = ruleSets.Sum(r => r.ActionOverrideCount);
        var exclusions    = ruleSets.Sum(r => r.ExclusionCount) + enabled.Sum(p => p.ExclusionCount);

        var deduction = Math.Min(6, (disabledRules + 1) / 2)
                      + Math.Min(2, (overrides + 2) / 3)
                      + Math.Min(2, (exclusions + 2) / 3);
        hygiene.Earned = Math.Max(0, HygienePts - deduction);
        hygiene.Details.Add(disabledRules + overrides + exclusions == 0
            ? "No disabled rules, action overrides or exclusions — clean tuning."
            : $"{disabledRules} disabled rule(s), {overrides} action override(s), {exclusions} exclusion(s).");
        if (deduction > 0)
            Improve("Review the tuning: re-enable disabled managed rules and replace broad exclusions with narrowly scoped ones.",
                    HygienePts - hygiene.Earned);
        rating.Categories.Add(hygiene);

        // ── 6. Hardening extras (5) ──────────────────────────────────────────
        var extras = new WafRatingCategory { Name = ExtrasCategory, Possible = ExtrasPts };
        var customRules = enabled
            .SelectMany(p => p.CustomRules)
            .Where(r => !r.EnabledState.Equals("Disabled", StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (customRules.Any(r => r.RuleType.Equals("RateLimitRule", StringComparison.OrdinalIgnoreCase)))
        {
            extras.Earned += 2;
            extras.Details.Add("Rate-limiting custom rule in place.");
        }
        else if (enabled.Count > 0)
        {
            Improve("Add a rate-limiting custom rule to blunt volumetric and brute-force attacks.", 2);
        }

        if (customRules.Any(r => r.Conditions.Any(c =>
                c.Contains("Geo", StringComparison.OrdinalIgnoreCase) ||
                c.Contains("RemoteAddr", StringComparison.OrdinalIgnoreCase) ||
                c.Contains("SocketAddr", StringComparison.OrdinalIgnoreCase) ||
                c.Contains("IPMatch", StringComparison.OrdinalIgnoreCase))))
        {
            extras.Earned += 1;
            extras.Details.Add("Geo/IP-based custom rule in place.");
        }
        else if (enabled.Count > 0)
        {
            Improve("Add geo-filtering or IP allow/deny custom rules for traffic you never expect.", 1);
        }

        if (enabled.Count > 0 &&
            !enabled.Any(p => p.RequestBodyCheck.Equals("Disabled", StringComparison.OrdinalIgnoreCase)))
        {
            extras.Earned += 2;
            extras.Details.Add("Request body inspection is on.");
        }
        else if (enabled.Count > 0)
        {
            Improve("Enable request body inspection so payloads (not just headers/URLs) are checked.", 2);
        }
        if (enabled.Count == 0) extras.Details.Add("No enabled policy to assess.");
        rating.Categories.Add(extras);

        // ── Score, caps and grade ────────────────────────────────────────────
        rating.Score = rating.Categories.Sum(c => c.Earned);

        var scoreGrade = GradeForScore(rating.Score);
        var finalGrade = caps.Aggregate(scoreGrade, (g, cap) => WorstGrade(g, cap.MaxGrade));

        rating.Grade = finalGrade;
        rating.GradeLabel = LabelForGrade(finalGrade);
        rating.CapReason = finalGrade != scoreGrade
            ? caps.Where(c => c.MaxGrade == finalGrade).Select(c => c.Reason).FirstOrDefault()
            : null;

        // ── Resulting grade per improvement (score + points, minus any lifted cap) ──
        foreach (var (item, liftsCapKey) in improvements)
        {
            var newScore = Math.Min(100, rating.Score + item.PointsGained);
            var remainingCaps = caps.Where(c => c.Key != liftsCapKey);
            item.ResultingGrade = remainingCaps.Aggregate(GradeForScore(newScore), (g, cap) => WorstGrade(g, cap.MaxGrade));
        }
        rating.Improvements = improvements
            .Select(i => i.Item)
            .OrderByDescending(i => i.PointsGained)
            .ToList();

        return rating;
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static bool SurfaceCovered(WafSurfaceInfo surface, IReadOnlyList<WafPolicyInfo> allPolicies)
    {
        if (string.IsNullOrEmpty(surface.WafPolicyId)) return false;
        var policy = allPolicies.FirstOrDefault(p => p.Id.Equals(surface.WafPolicyId, StringComparison.OrdinalIgnoreCase));
        // A policy outside the scanned scope counts as covered — we can't see its state.
        return policy is null || policy.IsEnabled;
    }

    private static bool IsDefaultRuleSet(ManagedRuleSetInfo rs) =>
        rs.RuleSetType.Contains("DefaultRuleSet", StringComparison.OrdinalIgnoreCase) ||
        rs.RuleSetType.Contains("OWASP", StringComparison.OrdinalIgnoreCase);

    public static bool MatchesResource(string associationId, string resourceId) =>
        associationId.Equals(resourceId, StringComparison.OrdinalIgnoreCase) ||
        associationId.StartsWith(resourceId + "/", StringComparison.OrdinalIgnoreCase);
}
