namespace RateMyWaf.Models;

/// <summary>A-F security rating for one Front Door's or Application Gateway's WAF setup.</summary>
public sealed class WafRating
{
    public WafFlowKind TargetKind { get; set; }
    public string TargetId { get; set; } = string.Empty;
    public string TargetName { get; set; } = string.Empty;
    public string SubscriptionId { get; set; } = string.Empty;

    /// <summary>Total score out of 100 across all categories.</summary>
    public int Score { get; set; }

    /// <summary>"A" (best) to "F" (worst), after caps.</summary>
    public string Grade { get; set; } = "F";
    public string GradeLabel { get; set; } = string.Empty;

    /// <summary>Why the grade was capped below what the raw score would give; null when uncapped.</summary>
    public string? CapReason { get; set; }

    public List<WafRatingCategory> Categories { get; set; } = new();

    /// <summary>Actions that raise the score, largest gain first.</summary>
    public List<WafImprovement> Improvements { get; set; } = new();
}

public sealed class WafRatingCategory
{
    public string Name { get; set; } = string.Empty;
    public int Earned { get; set; }
    public int Possible { get; set; }
    public List<string> Details { get; set; } = new();
}

public sealed class WafImprovement
{
    public string Action { get; set; } = string.Empty;
    public int PointsGained { get; set; }

    /// <summary>Grade after applying just this improvement (including any cap it lifts).</summary>
    public string ResultingGrade { get; set; } = string.Empty;
}
