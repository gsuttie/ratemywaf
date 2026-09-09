namespace RateMyWaf.Models;

public sealed class SubscriptionInfo
{
    public string SubscriptionId { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string State { get; set; } = string.Empty;
    public string TenantId { get; set; } = string.Empty;
}

public sealed class TenantInfo
{
    public string TenantId { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string DefaultDomain { get; set; } = string.Empty;

    public string BestName => string.IsNullOrWhiteSpace(DisplayName) ? TenantId : DisplayName;
}

/// <summary>Which of the two product flows the user is in.</summary>
public enum WafFlowKind { FrontDoor, ApplicationGateway }

public static class WafFlowKindExtensions
{
    public static string Label(this WafFlowKind kind) => kind == WafFlowKind.FrontDoor ? "Front Door" : "Application Gateway";
    public static string PluralLabel(this WafFlowKind kind) => kind == WafFlowKind.FrontDoor ? "Front Doors" : "Application Gateways";
    public static string Route(this WafFlowKind kind) => kind == WafFlowKind.FrontDoor ? "front-door" : "app-gateway";
}

/// <summary>Counts of flow-relevant resources in one subscription (from Azure Resource Graph).</summary>
public sealed class WafSubscriptionSummary
{
    public string SubscriptionId { get; set; } = string.Empty;
    public int AppGatewayCount { get; set; }
    public int FrontDoorCount { get; set; }
    public int AppGatewayPolicyCount { get; set; }
    public int FrontDoorPolicyCount { get; set; }

    public int EdgeCount(WafFlowKind kind) => kind == WafFlowKind.FrontDoor ? FrontDoorCount : AppGatewayCount;
    public int PolicyCount(WafFlowKind kind) => kind == WafFlowKind.FrontDoor ? FrontDoorPolicyCount : AppGatewayPolicyCount;
    public bool IsRelevant(WafFlowKind kind) => EdgeCount(kind) + PolicyCount(kind) > 0;
}
