using Azure.Core;
using Azure.ResourceManager;
using RateMyWaf.Models;

namespace RateMyWaf.Services;

/// <summary>Enumerates the subscriptions and tenants visible to the current credential (az login).</summary>
public sealed class AzureSubscriptionService
{
    private readonly TokenCredential _credential;
    private readonly ILogger<AzureSubscriptionService> _logger;
    private ArmClient _armClient;

    public AzureSubscriptionService(TokenCredential credential, ILogger<AzureSubscriptionService> logger)
    {
        _credential = credential;
        _logger = logger;
        _armClient = new ArmClient(credential);
    }

    /// <summary>Drops the cached ARM client so a fresh az login is picked up.</summary>
    public void Reset() => _armClient = new ArmClient(_credential);

    public async Task<List<SubscriptionInfo>> GetSubscriptionsAsync(CancellationToken ct = default)
    {
        var subscriptions = new List<SubscriptionInfo>();
        await foreach (var subscription in _armClient.GetSubscriptions().GetAllAsync(ct))
        {
            subscriptions.Add(new SubscriptionInfo
            {
                SubscriptionId = subscription.Data.SubscriptionId,
                DisplayName = subscription.Data.DisplayName ?? subscription.Data.SubscriptionId,
                State = subscription.Data.State?.ToString() ?? string.Empty,
                TenantId = subscription.Data.TenantId?.ToString() ?? string.Empty
            });
        }
        return subscriptions.OrderBy(s => s.DisplayName, StringComparer.OrdinalIgnoreCase).ToList();
    }

    /// <summary>Best-effort tenant names; tenants outside the credential's reach fall back to their ID.</summary>
    public async Task<Dictionary<string, TenantInfo>> GetTenantsAsync(CancellationToken ct = default)
    {
        var result = new Dictionary<string, TenantInfo>(StringComparer.OrdinalIgnoreCase);
        try
        {
            await foreach (var tenant in _armClient.GetTenants().GetAllAsync(ct))
            {
                var id = tenant.Data.TenantId?.ToString();
                if (string.IsNullOrEmpty(id)) continue;
                result[id] = new TenantInfo
                {
                    TenantId = id,
                    DisplayName = tenant.Data.DisplayName ?? string.Empty,
                    DefaultDomain = tenant.Data.DefaultDomain ?? string.Empty
                };
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex, "Could not enumerate tenants — tenant IDs will be shown without names.");
        }
        return result;
    }
}
